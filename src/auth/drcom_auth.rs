use std::net::Ipv4Addr;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use smoltcp::wire::EthernetAddress;

use crate::config::{DNS_ADDR, DRCOM_UDP_HEARTBEAT_DELAY, DRCOM_UDP_HEARTBEAT_TIMEOUT, VERSION};
use crate::credentials::Credentials;
use crate::error::AuthError;
use crate::config::ETH_FRAME_LEN;
use crate::protocol::drcom::{
    alive_heart_beat_type_setter, encrypt_info, misc_heart_beat_01_type_immediate,
    misc_heart_beat_03_type_immediate, misc_info_setter, misc_start_alive_setter_immediate,
    AuthType, MiscType,
};
use crate::transport::UdpTransport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrcomState {
    Idle,
    Alive,
    Heartbeat,
}

pub struct DrcomAuth {
    transport: UdpTransport,
    credentials: Rc<Credentials>,
    mac: EthernetAddress,
    addr: Ipv4Addr,

    // Protocol state
    pkt_id: u8,
    crc_md5_info: [u8; 16],
    tail_info: [u8; 16],
    misc1_flux: u32,

    // Heartbeat timing
    state: DrcomState,
    base_hb_time: SystemTime,
    last_hb_done: bool,
    need_hb: bool,
}

impl DrcomAuth {
    pub fn new(
        addr: Ipv4Addr,
        mac: EthernetAddress,
        credentials: Rc<Credentials>,
    ) -> Result<Self, AuthError> {
        let transport = UdpTransport::new(addr)?;

        Ok(Self {
            transport,
            credentials,
            mac,
            addr,
            pkt_id: 0,
            crc_md5_info: [0; 16],
            tail_info: [0; 16],
            misc1_flux: 0,
            state: DrcomState::Idle,
            base_hb_time: SystemTime::now(),
            last_hb_done: false,
            need_hb: true,
        })
    }

    pub fn state(&self) -> DrcomState {
        self.state
    }

    pub fn set_timeout(&mut self, timeout: Duration) -> Result<(), AuthError> {
        self.transport.set_timeout(timeout)
    }

    /// Start DRCOM alive sequence
    pub fn start(&mut self) -> Result<(), AuthError> {
        self.transport.send(&misc_start_alive_setter_immediate())?;
        self.reset_heartbeat_time();
        self.state = DrcomState::Alive;
        Ok(())
    }

    fn reset_heartbeat_time(&mut self) {
        self.base_hb_time = SystemTime::now();
    }

    fn misc_info(&mut self, recv_data: &[u8]) -> Result<(), AuthError> {
        let mut send_buf = [0u8; ETH_FRAME_LEN];
        let len = misc_info_setter(
            &mut send_buf,
            recv_data,
            &mut self.crc_md5_info,
            &self.credentials.username,
            &self.credentials.hostname,
            self.mac.as_bytes(),
            self.addr,
            DNS_ADDR,
            &VERSION,
            self.credentials.hash.as_bytes(),
        );
        self.transport.send(&send_buf[..len])?;
        Ok(())
    }

    fn misc_heartbeat1(&mut self) -> Result<usize, AuthError> {
        self.transport.send(&misc_heart_beat_01_type_immediate(
            &mut self.pkt_id,
            &self.misc1_flux.to_be_bytes(),
        ))
    }

    fn misc_heartbeat3(&mut self, recv_data: &[u8]) -> Result<usize, AuthError> {
        self.transport.send(&misc_heart_beat_03_type_immediate(
            recv_data,
            &mut self.pkt_id,
            self.addr,
        ))
    }

    fn alive_heartbeat(&mut self) -> Result<usize, AuthError> {
        let len = alive_heart_beat_type_setter(
            self.transport.send_buf_mut(),
            &self.crc_md5_info,
            &self.tail_info,
        );
        self.transport.send_from_buf(len)
    }

    /// Handle received packet
    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), AuthError> {
        if packet[0] == 0x07 {
            match AuthType::from(packet[4]) {
                AuthType::ResponseForAlive => {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    self.misc_info(packet)?;
                    self.reset_heartbeat_time();
                    self.last_hb_done = true;
                    self.need_hb = false;
                    log::info!("Server: MISC_RESPONSE_FOR_ALIVE. Send MISC_INFO.");
                }
                AuthType::ResponseInfo => {
                    self.tail_info.copy_from_slice(&packet[16..32]);
                    encrypt_info(&mut self.tail_info);
                    self.misc_heartbeat1()?;
                    self.need_hb = true;
                    self.state = DrcomState::Heartbeat;
                    log::info!("Server: MISC_RESPONSE_INFO. Send MISC_HEART_BEAT_01.");
                }
                AuthType::HeartBeat => match MiscType::from(packet[5]) {
                    MiscType::FileType => {
                        self.misc_heartbeat1()?;
                        log::info!("Server: MISC_FILE_TYPE. Send MISC_HEART_BEAT_01.");
                    }
                    MiscType::HeartBeat02Type => {
                        self.misc_heartbeat3(packet)?;
                        log::info!("Server: MISC_HEART_BEAT_02. Send MISC_HEART_BEAT_03.");
                    }
                    MiscType::HeartBeat04Type => {
                        self.reset_heartbeat_time();
                        self.last_hb_done = true;
                        self.alive_heartbeat()?;
                        log::info!("Server: MISC_HEART_BEAT_04. Wait for next heartbeat cycle.");
                    }
                    _ => {
                        log::error!("Server: Unknown MISC type: {:02x}", packet[5]);
                    }
                },
                AuthType::ResponseHeartBeat => {
                    self.misc_heartbeat1()?;
                    log::info!("Server: MISC_RESPONSE_HEART_BEAT. Send MISC_HEART_BEAT_01.");
                }
                _ => {
                    log::error!("Server: Unknown AUTH type: {:02x}", packet[4]);
                }
            }
        }

        if packet[0] == 0x4d && packet[1] == 0x38 {
            log::info!("Server info: {}", String::from_utf8_lossy(&packet[4..]));
        }

        Ok(())
    }

    /// Process one tick: handle packets + heartbeat timing
    pub fn tick(&mut self) -> Result<(), AuthError> {
        // Check for UDP packets
        match self.transport.try_recv() {
            Ok(Some(len)) => {
                let buf = self.transport.recv_buf()[..len].to_vec();
                self.handle_packet(&buf)?;
            }
            Ok(None) => {
                // No UDP packet ready (timeout), continue
            }
            Err(e) => {
                log::error!("UDP recv error: {}", e);
                return Err(e);
            }
        }

        // Heartbeat timing logic
        if self.need_hb {
            let elapsed = self
                .base_hb_time
                .elapsed()
                .unwrap_or(Duration::from_secs(0));

            if !self.last_hb_done && elapsed > Duration::from_secs(DRCOM_UDP_HEARTBEAT_TIMEOUT) {
                log::error!("Heartbeat timeout");
                return Err(AuthError::HeartbeatTimeout);
            }

            if elapsed > Duration::from_secs(DRCOM_UDP_HEARTBEAT_DELAY) {
                self.alive_heartbeat()?;
                self.reset_heartbeat_time();
                self.last_hb_done = false;
                log::debug!("Alive heartbeat sent");
            }
        }

        Ok(())
    }
}
