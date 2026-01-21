use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::time::Duration;

use pnet::packet::ethernet::{EtherType, EthernetPacket};
use pnet_datalink::{
    self, Channel, Config, DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface,
};
use thiserror::Error;

use crate::auth::EAPError;
use crate::eap::{Code, EAPoL, SendEAPoL, Type, EAPOL_PKT_LEN};
use crate::util::{AUTH_8021X_LOGOFF_DELAY, MULTICAST_ADDR};

pub const EAPOL: EtherType = EtherType(0x888E);

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),
    #[error("Failed to create channel: {0}")]
    ChannelCreationFailed(String),
    #[error("No MAC address on interface")]
    NoMacAddress,
    #[error("No IPv4 address on interface")]
    NoIpv4Address,
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),
    #[error("Timeout")]
    Timeout,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Dot1xChannel {
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
    interface: NetworkInterface,
    timeout: Duration,
}

impl Dot1xChannel {
    pub fn new(interface_name: &str, timeout_ms: u64) -> Result<Self, NetworkError> {
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| NetworkError::InterfaceNotFound(interface_name.to_string()))?;

        let config = pnet_datalink::Config {
            read_timeout: Some(Duration::from_millis(timeout_ms)),
            ..Default::default()
        };

        let (tx, rx) = match pnet_datalink::channel(&interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(NetworkError::ChannelCreationFailed(
                    "Unknown channel type".to_string(),
                ))
            }
            Err(e) => return Err(NetworkError::ChannelCreationFailed(e.to_string())),
        };

        let ret = Self {
            tx,
            rx,
            interface,
            timeout: Duration::from_millis(timeout_ms),
        };

        ret.ipv4_address()?;
        ret.mac_address()?;

        Ok(ret)
    }

    pub fn mac_address(&self) -> Result<MacAddr, NetworkError> {
        self.interface.mac.ok_or(NetworkError::NoMacAddress)
    }

    pub fn ipv4_address(&self) -> Result<Ipv4Addr, NetworkError> {
        self.interface
            .ips
            .iter()
            .find_map(|ip| match ip.ip() {
                std::net::IpAddr::V4(ipv4) => Some(ipv4),
                _ => None,
            })
            .ok_or(NetworkError::NoIpv4Address)
    }

    pub fn send_start_eapol(&mut self, dest: MacAddr) -> Result<(), EAPError> {
        // let mut sendbuf = Vec::with_capacity(EAPOL_PKT_LEN);
        self.tx
            .build_and_send(1, EAPOL_PKT_LEN, &mut |tx_pkt| {
                let mut send_pkt = SendEAPoL::new(tx_pkt);
                send_pkt.data.set_destination(dest);
                send_pkt.start();
            })
            .expect("Wrong EAPoL Packet Size")
            .map_err(|e| match e.kind() {
                ErrorKind::InvalidData => {
                    log::error!("Send start eapol fail due to IO Error: {e}");
                    EAPError::Network
                }
                e => {
                    log::error!("Send start eapol fail due to IO Error: {e}");
                    EAPError::Network
                }
            })
    }

    pub fn send_logoff_eapol(&mut self) {
        log::info!("Client: Send Logoff.");

        self.set_timeout(AUTH_8021X_LOGOFF_DELAY).unwrap();

        for _ in 0..2 {
            let _ = self
                .tx
                .build_and_send(1, EAPOL_PKT_LEN, &mut |buf| {
                    let mut send_pkt = SendEAPoL::new(buf);
                    send_pkt.data.set_destination(MacAddr::from(MULTICAST_ADDR));
                    send_pkt.logoff();
                })
                .expect("Invalid EAPoL Packet Size");
            if let Ok(rx_pkt) = self.rx.next() {
                let rx_pkt = EthernetPacket::new(rx_pkt).expect("packet length too short");
                if let Some(rx_eapol) = EAPoL::new(rx_pkt) {
                    if rx_eapol.eap_code() == Code::FAILURE {
                        log::info!("Logged off successfully.")
                    }
                }
            }
            // still send logoff
        }
    }

    pub fn try_recv_and_handle_eapol(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<(), EAPError> {
        let ipv4 = self.ipv4_address()?;
        let rx_pkt = match self.rx.next() {
            Ok(packet) => {
                assert!(
                    packet.len() >= 24,
                    "unexpected packet length too short, length: {}",
                    packet.len()
                );
                Ok(EthernetPacket::new(packet).expect("packet length too short"))
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    Err(NetworkError::Timeout)
                } else {
                    Err(NetworkError::ReceiveFailed(e.to_string()))
                }
            }
        }?;
        let rx_eapol = EAPoL::new(rx_pkt).ok_or(EAPError::InvalidPacket)?;
        use Code::*;
        use Type::*;
        let mut sendbuf = Vec::with_capacity(EAPOL_PKT_LEN);

        let mut send_pkt = SendEAPoL::new(sendbuf.as_mut_slice());
        send_pkt.data.set_destination(rx_eapol.src_addr());
        match rx_eapol.eap_code() {
            FAILURE => return Err(EAPError::Failure),
            SUCCESS => {
                return Ok(());
            }
            REQUEST => match rx_eapol.eap_type() {
                NOTIFICATION => {
                    log::warn!("DOT1X: NOTIFICATION: {}", rx_eapol.parse_error());
                    return Err(EAPError::Notification);
                }
                IDENTITY => send_pkt.identity(rx_eapol.eap_id(), ipv4, username),
                MD5 => send_pkt.md5_response(
                    rx_eapol.eap_id(),
                    ipv4,
                    rx_eapol.md5_challenge(),
                    username,
                    password,
                ),
                _ => {
                    log::error!("Unknown EAPOL type: {:?}", rx_eapol.eap_type());
                    return Err(EAPError::InvalidPacket);
                }
            },
            _ => return Err(EAPError::InvalidPacket),
        }
        self.tx.send_to(&sendbuf, None);
        Ok(())
    }

    pub fn interface(&self) -> &NetworkInterface {
        &self.interface
    }

    /// Update the read timeout for the channel.
    /// Used to set a shorter timeout for polling mode.
    pub fn set_timeout(&mut self, timeout_ms: u64) -> Result<(), NetworkError> {
        let config = Config {
            read_timeout: Some(Duration::from_millis(timeout_ms)),
            ..Default::default()
        };

        let (tx, rx) = match pnet_datalink::channel(&self.interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(NetworkError::ChannelCreationFailed(
                    "Unknown channel type".to_string(),
                ))
            }
            Err(e) => return Err(NetworkError::ChannelCreationFailed(e.to_string())),
        };

        self.tx = tx;
        self.rx = rx;
        self.timeout = Duration::from_millis(timeout_ms);
        Ok(())
    }
}
