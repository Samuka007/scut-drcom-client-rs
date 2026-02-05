use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::time::Duration;

use pnet::packet::ethernet::EthernetPacket;
use pnet_datalink::{Channel, Config, DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface};
use smoltcp::wire::EthernetAddress;

use crate::config::{AUTH_8021X_LOGOFF_DELAY, EAPOL_PKT_LEN, MULTICAST_ADDR};
use crate::credentials::Credentials;
use crate::error::AuthError;
use crate::protocol::eap::{Code, EAPoL, SendEAPoL, Type};

pub struct Dot1xTransport {
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
    interface: NetworkInterface,
    timeout: Duration,
}

impl Dot1xTransport {
    pub fn new(interface_name: &str, timeout_ms: u64) -> Result<Self, AuthError> {
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| AuthError::InterfaceNotFound(interface_name.to_string()))?;

        let config = Config {
            read_timeout: Some(Duration::from_millis(timeout_ms)),
            ..Default::default()
        };

        let (tx, rx) = match pnet_datalink::channel(&interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(AuthError::ChannelCreationFailed(
                    "Unknown channel type".to_string(),
                ))
            }
            Err(e) => return Err(AuthError::ChannelCreationFailed(e.to_string())),
        };

        let ret = Self {
            tx,
            rx,
            interface,
            timeout: Duration::from_millis(timeout_ms),
        };

        // Validate interface has required addresses
        ret.ipv4_address()?;
        ret.mac_address()?;

        Ok(ret)
    }

    pub fn mac_address(&self) -> Result<MacAddr, AuthError> {
        self.interface.mac.ok_or(AuthError::NoMacAddress)
    }

    pub fn ethernet_address(&self) -> Result<EthernetAddress, AuthError> {
        let mac = self.mac_address()?;
        Ok(EthernetAddress::from_bytes(&mac.octets()))
    }

    pub fn ipv4_address(&self) -> Result<Ipv4Addr, AuthError> {
        self.interface
            .ips
            .iter()
            .find_map(|ip| match ip.ip() {
                std::net::IpAddr::V4(ipv4) => Some(ipv4),
                _ => None,
            })
            .ok_or(AuthError::NoIpv4Address)
    }

    pub fn interface(&self) -> &NetworkInterface {
        &self.interface
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn set_timeout(&mut self, timeout_ms: u64) -> Result<(), AuthError> {
        let config = Config {
            read_timeout: Some(Duration::from_millis(timeout_ms)),
            ..Default::default()
        };

        let (tx, rx) = match pnet_datalink::channel(&self.interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(AuthError::ChannelCreationFailed(
                    "Unknown channel type".to_string(),
                ))
            }
            Err(e) => return Err(AuthError::ChannelCreationFailed(e.to_string())),
        };

        self.tx = tx;
        self.rx = rx;
        self.timeout = Duration::from_millis(timeout_ms);
        Ok(())
    }

    pub fn send_start_eapol(&mut self, dest: MacAddr) -> Result<(), AuthError> {
        let src = self.mac_address()?;
        self.tx
            .build_and_send(1, EAPOL_PKT_LEN, &mut |tx_pkt| {
                let mut send_pkt = SendEAPoL::new(tx_pkt);
                send_pkt.data.set_source(src);
                send_pkt.data.set_destination(dest);
                send_pkt.start();
            })
            .expect("Wrong EAPoL Packet Size")
            .map_err(|e| match e.kind() {
                ErrorKind::InvalidData => {
                    log::error!("Send start eapol fail due to IO Error: {e}");
                    AuthError::Network(e.to_string())
                }
                _ => {
                    log::error!("Send start eapol fail due to IO Error: {e}");
                    AuthError::Network(e.to_string())
                }
            })
    }

    pub fn send_logoff_eapol(&mut self) {
        log::info!("Client: Send Logoff.");

        let _ = self.set_timeout(AUTH_8021X_LOGOFF_DELAY);

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
        }
    }

    pub fn try_recv_and_handle_eapol(&mut self, credentials: &Credentials) -> Result<(), AuthError> {
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
                    Err(AuthError::Timeout)
                } else {
                    Err(AuthError::ReceiveFailed(e.to_string()))
                }
            }
        }?;
        let rx_eapol = EAPoL::new(rx_pkt).ok_or(AuthError::InvalidPacket)?;
        let mut sendbuf = vec![0u8; EAPOL_PKT_LEN];

        let mut send_pkt = SendEAPoL::new(sendbuf.as_mut_slice());
        send_pkt.data.set_destination(rx_eapol.src_addr());
        match rx_eapol.eap_code() {
            Code::FAILURE => return Err(AuthError::EapFailure),
            Code::SUCCESS => {
                return Ok(());
            }
            Code::REQUEST => match rx_eapol.eap_type() {
                Type::NOTIFICATION => {
                    let err_msg = rx_eapol.parse_error().to_string();
                    log::warn!("DOT1X: NOTIFICATION: {}", err_msg);
                    return Err(AuthError::Notification(err_msg));
                }
                Type::IDENTITY => send_pkt.identity(rx_eapol.eap_id(), ipv4, &credentials.username),
                Type::MD5 => send_pkt.md5_response(
                    rx_eapol.eap_id(),
                    ipv4,
                    rx_eapol.md5_challenge(),
                    &credentials.username,
                    &credentials.password,
                ),
                _ => {
                    log::error!("Unknown EAPOL type: {:?}", rx_eapol.eap_type());
                    return Err(AuthError::InvalidPacket);
                }
            },
            _ => return Err(AuthError::InvalidPacket),
        }
        self.tx.send_to(&sendbuf, None);
        Ok(())
    }
}
