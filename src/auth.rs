use std::net::{IpAddr, Ipv4Addr};

use pcap::{Packet, PacketCodec};
use smoltcp::wire::{EthernetAddress, EthernetFrame};

use crate::{drcom, eap::{self, EAPoL}, util};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestMac {
    Multicast,
    Broadcast,
    RuijieSwitch,
}

impl DestMac {
    fn to_addr(&self) -> EthernetAddress {
        match self {
            DestMac::Multicast => EthernetAddress::from_bytes(&util::MULTICAST_ADDR),
            DestMac::Broadcast => EthernetAddress::from_bytes(&util::BROADCAST_ADDR),
            DestMac::RuijieSwitch => EthernetAddress::from_bytes(&util::UNICAST_ADDR),
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
        if addr == EthernetAddress::from_bytes(&util::MULTICAST_ADDR) {
            DestMac::Multicast
        } else if addr == EthernetAddress::from_bytes(&util::BROADCAST_ADDR) {
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
        match e {
            TimeoutExpired => EAPError::Timeout,
            _ => EAPError::Unknown,
        }
    }
}

pub struct Auth {
    times: u32,
    success_8021x: bool,
    is_need_heartbeat: bool,
    // base_hb_time: libc::time_t,
    last_hb_done: bool,
    dev_dotx: pcap::Capture<pcap::Active>,
    dev_udp: pcap::Capture<pcap::Active>,
    // dst_mac: DestMac,
    local_ip: Ipv4Addr,
    send_pkt: eap::SendEAPoL,

    username: String,
    password: String,
}

impl Auth {
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

        let mut cap_udp = pcap::Capture::from_device(dev.clone())?
            .promisc(false)
            .snaplen(1514)
            .open()?;
        cap_udp.filter("udp", true)?;

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
            times: 0,
            success_8021x: false,
            is_need_heartbeat: false,
            last_hb_done: false,
            dev_dotx: cap_dotx,
            dev_udp: cap_udp,
            // dst_mac: DestMac::Multicast,
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
            FAILURE => return Err(EAPError::Failure),
            SUCCESS => todo!("UDP"),
            _ => return Err(EAPError::InvalidPacket),
        };

        self.dev_dotx.sendpacket(pkt_ref)?;
        Ok(())
    }
}

pub fn authentication(mut auth: Auth) -> Result<(), EAPError> {
    auth.login_get_server_mac()?;
    let handle = std::thread::spawn(move || {
        loop {
            match auth.wait_eapol() {
                Ok(_) => {
                    continue;
                },
                Err(EAPError::Timeout) => {
                    continue;
                },
                other => return other,
            }
        }
    });

    handle.join().unwrap()?;
    Ok(())
}

