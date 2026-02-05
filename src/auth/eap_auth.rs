use std::net::Ipv4Addr;
use std::rc::Rc;

use pnet_datalink::MacAddr;
use smoltcp::wire::EthernetAddress;

use crate::config::{BROADCAST_ADDR, MULTICAST_ADDR, UNICAST_ADDR};
use crate::credentials::Credentials;
use crate::error::AuthError;
use crate::transport::Dot1xTransport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapState {
    Init,
    WaitingResponse,
    Authenticated,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestMac {
    Multicast,
    Broadcast,
    Unicast,
}

impl DestMac {
    pub fn to_addr(&self) -> EthernetAddress {
        match self {
            DestMac::Multicast => EthernetAddress::from_bytes(&MULTICAST_ADDR),
            DestMac::Broadcast => EthernetAddress::from_bytes(&BROADCAST_ADDR),
            DestMac::Unicast => EthernetAddress::from_bytes(&UNICAST_ADDR),
        }
    }

    pub fn to_mac_addr(&self) -> MacAddr {
        match self {
            DestMac::Multicast => MacAddr::from(MULTICAST_ADDR),
            DestMac::Broadcast => MacAddr::from(BROADCAST_ADDR),
            DestMac::Unicast => MacAddr::from(UNICAST_ADDR),
        }
    }

    /// Cycle to next destination MAC for retry logic
    pub fn next(&self) -> Option<DestMac> {
        match self {
            DestMac::Multicast => Some(DestMac::Broadcast),
            DestMac::Broadcast => Some(DestMac::Unicast),
            DestMac::Unicast => None, // No more options
        }
    }
}

impl From<DestMac> for EthernetAddress {
    fn from(mac: DestMac) -> Self {
        mac.to_addr()
    }
}

impl From<EthernetAddress> for DestMac {
    fn from(addr: EthernetAddress) -> Self {
        if addr == EthernetAddress::from_bytes(&MULTICAST_ADDR) {
            DestMac::Multicast
        } else if addr == EthernetAddress::from_bytes(&BROADCAST_ADDR) {
            DestMac::Broadcast
        } else {
            DestMac::Unicast
        }
    }
}

impl std::fmt::Display for DestMac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DestMac::Multicast => write!(f, "Multicast"),
            DestMac::Broadcast => write!(f, "Broadcast"),
            DestMac::Unicast => write!(f, "Unicast"),
        }
    }
}

pub struct EapAuth {
    transport: Dot1xTransport,
    credentials: Rc<Credentials>,
    state: EapState,
    dest_mac: DestMac,
}

impl EapAuth {
    pub fn new(interface: &str, credentials: Rc<Credentials>) -> Result<Self, AuthError> {
        let transport = Dot1xTransport::new(interface, 1000)?;

        Ok(Self {
            transport,
            credentials,
            state: EapState::Init,
            dest_mac: DestMac::Multicast,
        })
    }

    pub fn state(&self) -> EapState {
        self.state
    }

    pub fn is_authenticated(&self) -> bool {
        self.state == EapState::Authenticated
    }

    pub fn local_ip(&self) -> Ipv4Addr {
        self.transport.ipv4_address().unwrap()
    }

    pub fn local_mac(&self) -> EthernetAddress {
        self.transport.ethernet_address().unwrap()
    }

    pub fn interface_name(&self) -> &str {
        &self.transport.interface().name
    }

    pub fn set_timeout(&mut self, timeout_ms: u64) -> Result<(), AuthError> {
        self.transport.set_timeout(timeout_ms)
    }

    pub fn logoff(&mut self) {
        self.transport.send_logoff_eapol();
    }

    /// Process one tick: handle packets, manage retry on timeout
    /// Returns the current state after processing
    pub fn tick(&mut self) -> Result<EapState, AuthError> {
        // Kick off the session by sending EAPOL-Start.
        if self.state == EapState::Init {
            let dest = self.dest_mac.to_mac_addr();
            self.transport.send_start_eapol(dest)?;
            self.state = EapState::WaitingResponse;
        }

        match self.transport.try_recv_and_handle_eapol(&self.credentials) {
            Ok(()) => {
                if self.state != EapState::Authenticated {
                    log::info!("DOT1X: Authentication successful.");
                }
                self.state = EapState::Authenticated;
                Ok(self.state)
            }
            Err(AuthError::Notification(msg)) => {
                log::warn!("EAPOL notification received: {}, continuing...", msg);
                Ok(self.state)
            }
            Err(AuthError::Timeout) => {
                log::debug!("EAP timeout...");
                if self.state != EapState::Authenticated {
                    // Try next destination MAC (and send a new EAPOL-Start on that destination).
                    if let Some(next_mac) = self.dest_mac.next() {
                        log::info!("Trying {} destination...", next_mac);
                        self.dest_mac = next_mac;
                        self.transport
                            .send_start_eapol(self.dest_mac.to_mac_addr())?;
                        self.state = EapState::WaitingResponse;
                        Ok(self.state)
                    } else {
                        self.state = EapState::Failed;
                        Err(AuthError::Network(
                            "All destination MACs exhausted".to_string(),
                        ))
                    }
                } else {
                    Ok(self.state)
                }
            }
            Err(e) => {
                log::error!("EAPOL error: {:?}", e);
                self.state = EapState::Failed;
                Err(e)
            }
        }
    }
}
