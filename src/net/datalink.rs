use std::net::Ipv4Addr;
use std::time::Duration;

use pnet_datalink::{self, Channel, Config, DataLinkReceiver, DataLinkSender, NetworkInterface};
use thiserror::Error;

pub const EAPOL_ETHERTYPE: u16 = 0x888E;

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

        Ok(Self {
            tx,
            rx,
            interface,
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    pub fn mac_address(&self) -> Result<[u8; 6], NetworkError> {
        self.interface
            .mac
            .map(|mac| mac.octets())
            .ok_or(NetworkError::NoMacAddress)
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

    pub fn send(&mut self, packet: &[u8]) -> Result<(), NetworkError> {
        self.tx
            .send_to(packet, None)
            .ok_or_else(|| NetworkError::SendFailed("Send returned None".to_string()))?
            .map_err(|e| NetworkError::SendFailed(e.to_string()))
    }

    pub fn recv_eapol(&mut self) -> Result<Vec<u8>, NetworkError> {
        loop {
            match self.rx.next() {
                Ok(packet) => {
                    if packet.len() >= 14 {
                        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
                        if ethertype == EAPOL_ETHERTYPE {
                            return Ok(packet.to_vec());
                        }
                    }
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock
                    {
                        return Err(NetworkError::Timeout);
                    }
                    return Err(NetworkError::ReceiveFailed(e.to_string()));
                }
            }
        }
    }

    pub fn interface(&self) -> &NetworkInterface {
        &self.interface
    }

    /// Non-blocking receive for EAPOL packets.
    /// Returns Ok(Some(packet)) if an EAPOL packet is received,
    /// Ok(None) if no packet is ready (timeout/would-block),
    /// Err for actual errors.
    pub fn try_recv_eapol(&mut self) -> Result<Option<Vec<u8>>, NetworkError> {
        match self.rx.next() {
            Ok(packet) => {
                if packet.len() >= 14 {
                    let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
                    if ethertype == EAPOL_ETHERTYPE {
                        return Ok(Some(packet.to_vec()));
                    }
                }
                // Not an EAPOL packet, return None to continue polling
                Ok(None)
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    Ok(None)
                } else {
                    Err(NetworkError::ReceiveFailed(e.to_string()))
                }
            }
        }
    }

    /// Update the read timeout for the channel.
    /// Used to set a shorter timeout for polling mode.
    pub fn set_timeout(&mut self, interface_name: &str, timeout_ms: u64) -> Result<(), NetworkError> {
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| NetworkError::InterfaceNotFound(interface_name.to_string()))?;

        let config = Config {
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

        self.tx = tx;
        self.rx = rx;
        self.timeout = Duration::from_millis(timeout_ms);
        Ok(())
    }
}
