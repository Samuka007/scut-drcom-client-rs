use std::{net::{IpAddr, Ipv4Addr, SocketAddrV4}, time::SystemTime};

use derive_builder::Builder;
use smoltcp::wire::{EthernetAddress, EthernetFrame};

use crate::{drcom, eap::{self, EAPoL}, util::*};

const ETH_FRAME_LEN: usize = 1514;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestMac {
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
    Unknown,
}

impl From<pcap::Error> for EAPError {
    fn from(e: pcap::Error) -> Self {
        use pcap::Error::*;
        log::debug!("PCAP Error: {:?}", e);
        match e {
            TimeoutExpired => EAPError::Timeout,
            _ => EAPError::Unknown,
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
    success_8021x: bool,
    // base_hb_time: libc::time_t,
    last_hb_done: bool,
    dev_dotx: pcap::Capture<pcap::Active>,
    // dev_udp: pcap::Capture<pcap::Active>,
    // dst_mac: DestMac,
    local_ip: Ipv4Addr,
    send_pkt: eap::SendEAPoL,

    username: String,
    password: String,
}

impl Dot1xAuth {
    fn new(
        dev: &pcap::Device,
        username: String,
        password: String,
    ) -> Result<Self, pcap::Error> {
        let mut cap_dotx = pcap::Capture::from_device(dev.clone())?
            .promisc(false)
            .snaplen(1514)
            .timeout(1000)
            .open()?;
        // capture 802.1x packets
        cap_dotx.set_datalink(pcap::Linktype::ETHERNET)?;
        cap_dotx.filter("ether proto 0x888E", true)?;


        let local_ip = dev.addresses.iter()
            .find_map(|addr| {
                if let IpAddr::V4(ipv4) = addr.addr {
                    Some(ipv4)
                } else {
                    None
                }
            }).expect("No IPv4 address found");
        
        let mut send_pkt = eap::SendEAPoL::new();
        send_pkt.set_src_addr(EthernetAddress::from_bytes(&[0x01; 6]));
        send_pkt.set_dst_addr(DestMac::Multicast.to_addr());

        Ok(Self {
            success_8021x: false,
            last_hb_done: false,
            dev_dotx: cap_dotx,
            local_ip,
            username,
            password,
            send_pkt,
        })
    }

    /*
    * 发送 EAPOL Start 以获取服务器MAC地址及执行后续认证流程
    * Dr.com客户端发送EAP包目标MAC有3个：
    * 组播地址 (01:80:c2:00:00:03)
    * 广播地址 (ff:ff:ff:ff:ff:ff)
    * 锐捷交换机 (01:d0:f8:00:00:03) PS:我校应该没有这货
    * 
    * 因为实际上是在 Broadcast 和 Multicast 之间切换，直接重试1次
    */
    fn login_get_server_mac(&mut self) -> Result<(), EAPError> {
        self.send_pkt.set_dst_addr(DestMac::Multicast.to_addr());
        self.dev_dotx.sendpacket(self.send_pkt.start())?;
        log::info!("DOT1X: Multicast start.");

        match self.wait_eapol() {
            Err(EAPError::Timeout) => {},
            other => return other,
        }

        self.send_pkt.set_dst_addr(DestMac::Broadcast.to_addr());
        self.dev_dotx.sendpacket(self.send_pkt.start())?;
        log::info!("DOT1X: Broadcast start.");

        return self.wait_eapol();
    }

    fn wait_eapol(&mut self) -> Result<(), EAPError> {
        let result = self.dev_dotx.next_packet().map(|packet| EAPoL::from_packet(packet))?;
        self.send_pkt.set_dst_addr(result.src_addr());

        use eap::Type::*;
        use eap::Code::*;
        let pkt_ref = match result.eap_code {
            REQUEST => {
                match result.eap_type {
                    IDENTITY => {
                        self.send_pkt.identity(result.eap_id(), self.local_ip, &self.username)
                    }
                    MD5 => {
                        self.send_pkt.md5_response(result.eap_id(), self.local_ip, &result.md5_challenge(), &self.username, &self.password)
                    }
                    NOTIFICATION => {
                        log::warn!("DOT1X: NOTIFICATION: {}", result.parse_error());
                        return Err(EAPError::Notification);
                    }
                    _ => {
                        log::error!("Unknown EAPOL type: {:?}", result.eap_type());
                        return Err(EAPError::InvalidPacket);
                    }
                }
            },
            FAILURE => return Err(EAPError::Failure), // TODO change udp state
            SUCCESS => {
                self.success_8021x = true;
                return Ok(())
            },
            _ => return Err(EAPError::InvalidPacket),
        };

        self.dev_dotx.sendpacket(pkt_ref)?;
        Ok(())
    }

    pub fn is_success(&self) -> bool {
        self.success_8021x
    }
}

#[derive(Debug, Builder)]
#[builder(pattern = "owned")]
#[builder(build_fn(skip))]
pub struct UdpAuth {
    addr: Ipv4Addr,
    
    username: String,
    password: String,
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
    misc3_flux: u32,

    need_hb: bool,
    base_hb_time: SystemTime,
    last_hb_done: bool,
}


impl UdpAuthBuilder {
    pub fn build(self) -> Result<UdpAuth, std::io::Error> {
        let socket = std::net::UdpSocket::bind((self.addr.clone().unwrap(), DRCOM_SERVER_PORT))
            .map_err(|e| {
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
            password: self.password.unwrap(),
            hostname: self.hostname.unwrap(),
            mac: self.mac.unwrap(),
            hash: self.hash.unwrap(),
            crc_md5_info: [0; 16],
            tail_info: [0; 16],
            recv_buf: [0; ETH_FRAME_LEN],
            send_buf: [0; ETH_FRAME_LEN],
            misc1_flux: 0,
            misc3_flux: 0,
            base_hb_time: SystemTime::now(),
            last_hb_done: false,
            need_hb: true,
        })
    }
}

impl UdpAuth {

    pub fn misc_start_alive(&mut self) -> Result<usize, std::io::Error> {
        self.socket.send(&drcom::misc_start_alive_setter_immediate())
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
                    //ALIVE已经回复，关闭心跳计时
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
                drcom::AuthType::HeartBeat => {
                    match drcom::MiscType::from(packet[5]) {
                        drcom::MiscType::FileType => {
                            self.misc_heartbeat1()?;
                            log::info!("Server: MISC_FILE_TYPE. Send MISC_HEART_BEAT_01.");
                        },
                        drcom::MiscType::HeartBeat02Type => {
                            self.misc_heartbeat3()?;
                            log::info!("Server: MISC_HEART_BEAT_02. Send MISC_HEART_BEAT_03.");
                        },
                        drcom::MiscType::HeartBeat04Type => {
                            self.reset_heartbeat_time();
                            self.last_hb_done = true;
                            self.alive_heartbeat()?;
                            log::info!("Server: MISC_HEART_BEAT_04. Wait for next heartbeat cycle.");
                        },
                        _ => {
                            log::error!("Server: Unknown MISC type: {:02x}", packet[5]);
                        }
                    }
                }
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
            log::info!("Server info: {}", unsafe { std::str::from_utf8_unchecked(&packet[4..]) });
        }

        Ok(())
    }

    pub fn get_heartbeat_time(&self) -> SystemTime {
        self.base_hb_time
    }

    pub fn reset_heartbeat_time(&mut self) {
        self.base_hb_time = SystemTime::now();
    }
}

pub fn authentication(mut auth: Dot1xAuth, mut udp: UdpAuth) -> Result<(), EAPError> {
    auth.login_get_server_mac()?;
    udp.misc_start_alive()?;
    udp.reset_heartbeat_time();
    let eapol_thread = std::thread::spawn(move || {
        loop {
            match auth.wait_eapol() {
                Ok(_) | Err(EAPError::Timeout)=> continue,
                other => return other,
            }
        }
    });

    loop {
        
        todo!("UDP Loop");
    }

    eapol_thread.join().unwrap()?;
    Ok(())
}

