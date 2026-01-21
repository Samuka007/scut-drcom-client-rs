use std::{
    io::ErrorKind,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};

use derive_builder::Builder;
use smoltcp::wire::EthernetAddress;

use crate::{
    drcom,
    net::{Dot1xChannel, NetworkError},
    util::*,
};

const ETH_FRAME_LEN: usize = 1514;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestMac {
    Multicast,
    Broadcast,
    RuijieSwitch,
}

impl DestMac {
    fn to_addr(&self) -> EthernetAddress {
        match self {
            DestMac::Multicast => EthernetAddress::from_bytes(&MULTICAST_ADDR),
            DestMac::Broadcast => EthernetAddress::from_bytes(&BROADCAST_ADDR),
            DestMac::RuijieSwitch => EthernetAddress::from_bytes(&UNICAST_ADDR),
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
            DestMac::RuijieSwitch
        }
    }
}

impl std::fmt::Display for DestMac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DestMac::Multicast => write!(f, "Multicast"),
            DestMac::Broadcast => write!(f, "Broadcast"),
            DestMac::RuijieSwitch => write!(f, "RuijieSwitch"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EAPError {
    Timeout,
    InvalidPacket,
    Notification,
    Failure,
    Network,
    Unknown,
}

impl From<NetworkError> for EAPError {
    fn from(e: NetworkError) -> Self {
        log::debug!("Network Error: {:?}", e);
        match e {
            NetworkError::Timeout => EAPError::Timeout,
            _ => EAPError::Network,
        }
    }
}

impl From<std::io::Error> for EAPError {
    fn from(e: std::io::Error) -> Self {
        log::debug!("IO Error: {:?}", e);
        match e.kind() {
            std::io::ErrorKind::TimedOut => EAPError::Timeout,
            _ => EAPError::Unknown,
        }
    }
}

pub struct Dot1xAuth {
    // success_8021x: bool,
    channel: Dot1xChannel,
    // local_mac: EthernetAddress,
    // local_ip: Ipv4Addr,
    username: String,
    password: String,
}

impl Dot1xAuth {
    pub fn new(
        interface_name: &str,
        username: String,
        password: String,
    ) -> Result<Self, NetworkError> {
        let channel = Dot1xChannel::new(interface_name, 1000)?;

        // let local_mac = EthernetAddress::from_bytes(&channel.mac_address()?);
        // let local_ip = channel.ipv4_address()?;

        // let mut send_pkt = eap::SendEAPoL::new();
        // send_pkt.set_src_addr(local_mac);
        // send_pkt.set_dst_addr(DestMac::Multicast.to_addr());

        Ok(Self {
            // success_8021x: false,
            channel,
            // local_mac,
            // local_ip,
            username,
            password,
            // send_pkt,
        })
    }

    pub fn local_ip(&self) -> Ipv4Addr {
        self.channel.ipv4_address().unwrap()
    }

    pub fn local_mac(&self) -> EthernetAddress {
        EthernetAddress::from_bytes(&self.channel.mac_address().unwrap().octets())
    }

    /// Get the interface name for the channel.
    pub fn interface_name(&self) -> &str {
        &self.channel.interface().name
    }

    pub fn logoff(&mut self) {
        self.channel.send_logoff_eapol();
    }

    /// Set the timeout for EAPOL channel polling.
    pub fn set_timeout(&mut self, timeout_ms: u64) -> Result<(), EAPError> {
        Ok(self.channel.set_timeout(timeout_ms)?)
    }

    pub fn try_recv_and_handle_eapol(&mut self) -> Result<(), EAPError> {
        self.channel
            .try_recv_and_handle_eapol(&self.username, &self.password)
    }
}

#[derive(Debug, Builder)]
#[builder(pattern = "owned")]
#[builder(build_fn(skip))]
pub struct UdpAuth {
    addr: Ipv4Addr,

    username: String,
    // password: String,
    hostname: String,
    mac: EthernetAddress,
    hash: String,

    crc_md5_info: [u8; 16],
    tail_info: [u8; 16],

    recv_buf: [u8; ETH_FRAME_LEN],
    send_buf: [u8; ETH_FRAME_LEN],

    socket: std::net::UdpSocket,
    #[builder(default = 0)]
    pkt_id: u8,

    misc1_flux: u32,
    // misc3_flux: u32,
    need_hb: bool,
    base_hb_time: SystemTime,
    last_hb_done: bool,
}

impl UdpAuthBuilder {
    pub fn build(self) -> Result<UdpAuth, std::io::Error> {
        let socket =
            std::net::UdpSocket::bind((self.addr.unwrap(), DRCOM_SERVER_PORT)).map_err(|e| {
                log::error!("Failed to bind UDP socket: {}", e);
                e
            })?;
        socket.set_broadcast(true)?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(DRCOM_UDP_RECV_DELAY)))?;
        socket.connect((SERVER_ADDR, DRCOM_SERVER_PORT))?;

        Ok(UdpAuth {
            addr: self.addr.unwrap(),
            socket,
            pkt_id: 0,
            username: self.username.unwrap(),
            // password: self.password.unwrap(),
            hostname: self.hostname.unwrap(),
            mac: self.mac.unwrap(),
            hash: self.hash.unwrap(),
            crc_md5_info: [0; 16],
            tail_info: [0; 16],
            recv_buf: [0; ETH_FRAME_LEN],
            send_buf: [0; ETH_FRAME_LEN],
            misc1_flux: 0,
            // misc3_flux: 0,
            base_hb_time: SystemTime::now(),
            last_hb_done: false,
            need_hb: true,
        })
    }
}

impl UdpAuth {
    /// Get a mutable reference to the underlying UDP socket.
    pub fn socket_mut(&mut self) -> &mut std::net::UdpSocket {
        &mut self.socket
    }

    /// Non-blocking receive for UDP packets.
    /// Returns Ok(Some(len)) if a packet is received,
    /// Ok(None) if no packet is ready (would-block),
    /// Err for actual errors.
    pub fn try_recv(&mut self) -> Result<Option<usize>, std::io::Error> {
        match self.socket.recv(&mut self.recv_buf) {
            Ok(len) => Ok(Some(len)),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    pub fn misc_start_alive(&mut self) -> Result<usize, std::io::Error> {
        self.socket
            .send(&drcom::misc_start_alive_setter_immediate())
    }

    pub fn misc_info(&mut self) -> Result<(), std::io::Error> {
        let len = drcom::misc_info_setter(
            &mut self.send_buf,
            &self.recv_buf,
            &mut self.crc_md5_info,
            &self.username,
            &self.hostname,
            self.mac.as_bytes(),
            self.addr,
            DNS_ADDR,
            &VERSION,
            self.hash.as_bytes(),
        );
        self.socket.send(&self.send_buf[..len])?;
        Ok(())
    }

    pub fn misc_heartbeat1(&mut self) -> Result<usize, std::io::Error> {
        self.socket.send(&drcom::misc_heart_beat_01_type_immediate(
            &mut self.pkt_id,
            &self.misc1_flux.to_be_bytes(),
        ))
    }

    pub fn misc_heartbeat3(&mut self) -> Result<usize, std::io::Error> {
        self.socket.send(&drcom::misc_heart_beat_03_type_immediate(
            &self.recv_buf,
            &mut self.pkt_id,
            self.addr,
        ))
    }

    pub fn alive_heartbeat(&mut self) -> Result<usize, std::io::Error> {
        let len = drcom::alive_heart_beat_type_setter(
            &mut self.send_buf,
            &self.crc_md5_info,
            &self.tail_info,
        );
        self.socket.send(&self.send_buf[..len])
    }

    pub fn handle(&mut self, packet: &[u8]) -> Result<(), std::io::Error> {
        if packet[0] == 0x07 {
            match drcom::AuthType::from(packet[4]) {
                drcom::AuthType::ResponseForAlive => {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    self.misc_info()?;
                    self.reset_heartbeat_time();
                    self.last_hb_done = true;
                    self.need_hb = false;
                    log::info!("Server: MISC_RESPONSE_FOR_ALIVE. Send MISC_INFO.");
                }
                drcom::AuthType::ResponseInfo => {
                    self.tail_info.copy_from_slice(&packet[16..32]);
                    drcom::encrypt_info(&mut self.tail_info);
                    self.misc_heartbeat1()?;
                    self.need_hb = true;
                    log::info!("Server: MISC_RESPONSE_INFO. Send MISC_HEART_BEAT_01.");
                }
                drcom::AuthType::HeartBeat => match drcom::MiscType::from(packet[5]) {
                    drcom::MiscType::FileType => {
                        self.misc_heartbeat1()?;
                        log::info!("Server: MISC_FILE_TYPE. Send MISC_HEART_BEAT_01.");
                    }
                    drcom::MiscType::HeartBeat02Type => {
                        self.misc_heartbeat3()?;
                        log::info!("Server: MISC_HEART_BEAT_02. Send MISC_HEART_BEAT_03.");
                    }
                    drcom::MiscType::HeartBeat04Type => {
                        self.reset_heartbeat_time();
                        self.last_hb_done = true;
                        self.alive_heartbeat()?;
                        log::info!("Server: MISC_HEART_BEAT_04. Wait for next heartbeat cycle.");
                    }
                    _ => {
                        log::error!("Server: Unknown MISC type: {:02x}", packet[5]);
                    }
                },
                drcom::AuthType::ResponseHeartBeat => {
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

    // pub fn get_heartbeat_time(&self) -> SystemTime {
    //     self.base_hb_time
    // }

    pub fn reset_heartbeat_time(&mut self) {
        self.base_hb_time = SystemTime::now();
    }
}

pub struct Auth {
    eap_success: bool,
    start_loop: DestMac,
    dot1x: Dot1xAuth,
    udp: UdpAuth,
}

impl Auth {
    pub fn new(dot1x: Dot1xAuth, udp: UdpAuth) -> Self {
        Self {
            eap_success: false,
            start_loop: DestMac::Multicast,
            dot1x,
            udp,
        }
    }

    /// Single-threaded authentication event loop using timeout-based polling.
    /// This is cross-platform (works on Windows, Linux, macOS) and replaces
    /// the previous two-thread architecture that had synchronization issues.
    ///
    /// The approach is similar to the C scutclient's select() loop, but uses
    /// short timeouts on both sockets to achieve non-blocking behavior.
    pub fn authentication(&mut self) -> Result<(), EAPError> {
        // Phase 2: Start UDP keepalive
        self.udp.misc_start_alive()?;
        self.udp.reset_heartbeat_time();

        // Phase 3: Set up shutdown flag for signal handling
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        ctrlc::set_handler(move || {
            log::info!("Received shutdown signal...");
            shutdown_clone.store(true, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");

        // Phase 4: Configure short timeouts for polling mode
        // This enables cross-platform non-blocking behavior without platform-specific APIs
        const POLL_TIMEOUT_MS: u64 = 100;

        self.dot1x.set_timeout(POLL_TIMEOUT_MS)?;
        self.udp
            .socket_mut()
            .set_read_timeout(Some(Duration::from_millis(POLL_TIMEOUT_MS)))
            .map_err(|e| {
                log::error!("Failed to set UDP socket timeout: {}", e);
                EAPError::Network
            })?;

        log::info!("Entering main event loop...");

        // Phase 5: Unified polling loop
        // Both sockets have short timeouts, so we poll them sequentially
        loop {
            // Check for shutdown signal at start of each iteration
            if shutdown.load(Ordering::SeqCst) {
                log::info!("Shutting down...");
                self.dot1x.logoff();
                return Ok(());
            }

            // Check for EAPOL packets (handles re-authentication requests)
            use EAPError::*;
            match self.dot1x.try_recv_and_handle_eapol() {
                Ok(()) => {
                    if !self.eap_success {
                        log::info!("DOT1X: Authentication successful.");
                    }
                    self.eap_success = true;
                }
                Err(Notification) => {
                    // Notification received, log but continue
                    log::warn!("EAPOL notification received, continuing...");
                }
                Err(Timeout) => {
                    log::debug!("Timeout...");
                    if !self.eap_success {
                        match self.start_loop {
                            DestMac::Multicast => self.start_loop = DestMac::Broadcast,
                            DestMac::Broadcast => self.start_loop = DestMac::RuijieSwitch, // just alias of "if still timeout, just fail"
                            DestMac::RuijieSwitch => return Err(EAPError::Network), // Init failed, error type need refactor
                        }
                        continue; // skip udp heart beat
                    }
                }
                Err(e) => {
                    log::error!("EAPOL error: {:?}", e);
                    return Err(e);
                }
            }

            // Check for UDP packets
            match self.udp.try_recv() {
                Ok(Some(len)) => {
                    let buf = self.udp.recv_buf[..len].to_vec();
                    if let Err(e) = self.udp.handle(&buf) {
                        log::error!("UDP handle error: {}", e);
                        return Err(EAPError::Network);
                    }
                }
                Ok(None) => {
                    // No UDP packet ready (timeout), continue
                }
                Err(e) => {
                    log::error!("UDP recv error: {}", e);
                    return Err(EAPError::Network);
                }
            }

            // Heartbeat logic - runs every loop iteration
            if self.udp.need_hb {
                let elapsed = self
                    .udp
                    .base_hb_time
                    .elapsed()
                    .unwrap_or(Duration::from_secs(0));

                if !self.udp.last_hb_done
                    && elapsed > Duration::from_secs(DRCOM_UDP_HEARTBEAT_TIMEOUT)
                {
                    log::error!("Heartbeat timeout");
                    return Err(EAPError::Timeout);
                }

                if elapsed > Duration::from_secs(DRCOM_UDP_HEARTBEAT_DELAY) {
                    if let Err(e) = self.udp.alive_heartbeat() {
                        log::error!("Failed to send heartbeat: {}", e);
                        return Err(EAPError::Network);
                    }
                    self.udp.reset_heartbeat_time();
                    self.udp.last_hb_done = false;
                    log::debug!("Alive heartbeat sent");
                }
            }
        }
    }
}
