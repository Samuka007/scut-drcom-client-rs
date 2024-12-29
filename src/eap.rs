use std::net::Ipv4Addr;

use pcap::Packet;
use smoltcp::wire::{EthernetAddress, EthernetFrame};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Code {
    REQUEST = 1,
    RESPONSE = 2,
    SUCCESS = 3,
    FAILURE = 4,
    H3CDATA = 10,
    Unknown,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Type {
    IDENTITY = 1,
    NOTIFICATION = 2,
    MD5 = 4,
    AVAILABLE = 20,
    ALLOCATED_0x07 = 7,
    ALLOCATED_0x08 = 8,
    Unknown,
}

pub const EAPOL_PKT_LEN: usize = 96;

pub struct EAPoL <'a> {
    pub eap_code: Code,
    pub eap_type: Type,
    pub data: EthernetFrame<&'a [u8]>,
}

impl<'a> EAPoL <'a> {
    // pub fn from_payload(payload: &'a [u8]) -> Self {
    //     Self {
    //         eap_code: match payload[18] {
    //             1 => Code::REQUEST,
    //             2 => Code::RESPONSE,
    //             3 => Code::SUCCESS,
    //             4 => Code::FAILURE,
    //             10 => Code::H3CDATA,
    //             _ => Code::Unknown,
    //         },
    //         eap_type: match payload[22] {
    //             1 => Type::IDENTITY,
    //             2 => Type::NOTIFICATION,
    //             4 => Type::MD5,
    //             20 => Type::AVAILABLE,
    //             7 => Type::ALLOCATED_0x07,
    //             8 => Type::ALLOCATED_0x08,
    //             _ => Type::Unknown,
    //         },
    //         data: EthernetFrame::new_unchecked(payload),
    //     }
    // }

    pub fn from_packet(packet: Packet<'a>) -> Self {
        let pkt_len = packet.header.len;
        let pkt_len2 = u16::from_be_bytes([packet.data[20], packet.data[21]]);
        log::debug!("EAPol Length: {}, {}", pkt_len, pkt_len2);
        Self {
            eap_code: match packet.data[18] {
                1 => Code::REQUEST,
                2 => Code::RESPONSE,
                3 => Code::SUCCESS,
                4 => Code::FAILURE,
                10 => Code::H3CDATA,
                _ => Code::Unknown,
            },
            eap_type: match packet.data[22] {
                1 => Type::IDENTITY,
                2 => Type::NOTIFICATION,
                4 => Type::MD5,
                20 => Type::AVAILABLE,
                7 => Type::ALLOCATED_0x07,
                8 => Type::ALLOCATED_0x08,
                _ => Type::Unknown,
            },
            data: EthernetFrame::new_unchecked(packet.data),
        }
    }

    pub fn eap_code(&self) -> u8 {
        self.data.as_ref()[18]
    }

    pub fn eap_id(&self) -> u8 {
        self.data.as_ref()[19]
    }

    pub fn eap_type(&self) -> u8 {
        self.data.as_ref()[22]
    }

    pub fn packet_len(&self) -> u16 {
        u16::from_be_bytes([self.data.as_ref()[20], self.data.as_ref()[21]])
    }

    pub fn md5_challenge(&self) -> &[u8] {
        &self.data.as_ref()[24..40]
    }

    pub fn src_addr(&self) -> EthernetAddress {
        self.data.src_addr()
    }

    pub fn dst_addr(&self) -> EthernetAddress {
        self.data.dst_addr()
    }
    
    pub fn parse_error(&self) -> &str {
        let error = std::str::from_utf8(&self.data.as_ref()[23..]).unwrap();
        eap_err_parse(error)
    }
}

pub struct SendEAPoL {
    pub data: EthernetFrame<[u8; EAPOL_PKT_LEN]>,
}

impl SendEAPoL {
    pub fn eap_code(&self) -> u8 {
        self.data.as_ref()[18]
    }

    pub fn eap_id(&self) -> u8 {
        self.data.as_ref()[19]
    }

    pub fn eap_type(&self) -> u8 {
        self.data.as_ref()[22]
    }

    pub fn packet_len(&self) -> u16 {
        u16::from_be_bytes([self.data.as_ref()[20], self.data.as_ref()[21]])
    }

    pub fn md5_challenge(&self) -> &[u8] {
        &self.data.as_ref()[24..40]
    }

    pub fn src_addr(&self) -> EthernetAddress {
        self.data.src_addr()
    }

    pub fn dst_addr(&self) -> EthernetAddress {
        self.data.dst_addr()
    }

    pub fn new() -> Self {
        let mut data = EthernetFrame::new_unchecked([0u8; EAPOL_PKT_LEN]);
        data.set_ethertype(smoltcp::wire::EthernetProtocol::Unknown(0x888E));
        Self {
            data,
        }
    }

    pub fn set_src_addr(&mut self, addr: EthernetAddress) {
        self.data.set_src_addr(addr);
    }

    pub fn set_dst_addr(&mut self, addr: EthernetAddress) {
        self.data.set_dst_addr(addr);
    }

    /// Set the EAP code. (At offset 18)
    pub fn set_eap_code(&mut self, code: Code) {
        self.data.payload_mut()[18 - 14] = code as u8;
    }

    /// Set the EAP ID. (At offset 19)
    pub fn set_eap_id(&mut self, id: u8) {
        self.data.payload_mut()[19 - 14] = id;
    }

    /// Set the EAP type. (At offset 22)
    pub fn set_eap_type(&mut self, eap_type: Type) {
        self.data.payload_mut()[22 - 14] = eap_type as u8;
    }

    pub fn set_md5_challenge(&mut self, password: &str, challenge: &[u8]) {
        let mut md5 = md5::Context::new();
        md5.consume(&[self.eap_id()]);
        md5.consume(password.as_bytes());
        md5.consume(&challenge[..16]);
        let digest = md5.compute();
        self.data.payload_mut()[24 - 14..40 - 14].copy_from_slice(digest.as_ref());
    }

    pub fn start(&mut self) -> &[u8] {
        self.data.payload_mut().fill(0);
        self.data.payload_mut()[0] = 0x01;  // Version 1
        self.data.payload_mut()[1] = 0x01;  // Type Start
        self.data.payload_mut()[2] = 0x00;  // Length 0x0000
        self.data.payload_mut()[3] = 0x00;
        self.data.as_ref()
    }

    pub fn identity(&mut self, id: u8, ipaddr: Ipv4Addr, username: &str) -> &[u8] {
        self.data.payload_mut().fill(0);
        self.data.payload_mut()[0] = 0x01;  // Version 1
        self.data.payload_mut()[1] = 0x00;  // Type EAP Packet

        // Extensible Authentication Protocol
        self.set_eap_code(Code::RESPONSE);  // Code
        self.set_eap_id(id);  // ID
        self.set_eap_type(Type::IDENTITY);  // Type

        // Username
        let mut pos = 23 - 14;
        self.data.payload_mut()[pos ..pos + username.len()].copy_from_slice(username.as_bytes());
        pos += username.len();

        let fill = [0x0, 0x44, 0x61, 0x0, 0x0];
        self.data.payload_mut()[pos..pos + 5].copy_from_slice(&fill);
        pos += fill.len();

        // IP Address
        self.data.payload_mut()[pos..pos + ipaddr.octets().len()].copy_from_slice(&ipaddr.octets());

        // Length
        let eap_len: u16 = username.len() as u16 + 14;
        self.data.payload_mut()[16 - 14..].copy_from_slice(&eap_len.to_be_bytes());
        self.data.payload_mut()[20 - 14..].copy_from_slice(&eap_len.to_be_bytes());

        self.data.as_ref()
    }

    pub fn md5_response(
        &mut self,
        id: u8,
        ipaddr: Ipv4Addr,
        challenge: &[u8],
        username: &str,
        password: &str,
    ) -> &[u8] {
        self.data.payload_mut().fill(0);
        self.data.payload_mut()[0] = 0x01;  // Version 1
        self.data.payload_mut()[1] = 0x00;  // Type EAP Packet

        // Extensible Authentication Protocol
        self.set_eap_code(Code::RESPONSE);  // Code
        self.set_eap_id(id);  // ID
        self.set_eap_type(Type::MD5);  // Type
        self.data.payload_mut()[23 - 14] = 0x10;  // Value-Size: 16 Bytes

        // MD5 Challenge
        self.set_md5_challenge(password, challenge);

        // Username
        let mut pos = 40 - 14;
        self.data.payload_mut()[pos ..pos + username.len()].copy_from_slice(username.as_bytes());
        pos += username.len();

        let fill = [0x0, 0x44, 0x61, 0x2a, 0x0];
        self.data.payload_mut()[pos..pos + 5].copy_from_slice(&fill);
        pos += fill.len();

        // IP Address
        self.data.payload_mut()[pos..pos + ipaddr.octets().len()].copy_from_slice(&ipaddr.octets());
        // pos += ipaddr.octets().len();

        // Length
        let eap_len: u16 = username.len() as u16 + 31;
        self.data.payload_mut()[16 - 14..].copy_from_slice(&eap_len.to_be_bytes());
        self.data.payload_mut()[20 - 14..].copy_from_slice(&eap_len.to_be_bytes());

        self.data.as_ref()
    }

    pub fn logoff(&mut self) -> &[u8] {
        self.data.payload_mut().fill(0xa5);
        self.data.payload_mut()[0] = 0x01;  // Version 1
        self.data.payload_mut()[1] = 0x02;  // Type Logoff
        self.data.payload_mut()[2] = 0x00;  // Length 0x0000
        self.data.payload_mut()[3] = 0x00;
        
        self.data.as_ref()
    }
}

pub fn eap_err_parse<'a>(str: &'a str) -> &'a str {
    if str.starts_with("userid error") {
        let errcode: i32 = str[12..].trim().parse().unwrap_or(-1);
        return match errcode {
            1 => "Account does not exist.",
            2 | 3 => "Username or password invalid.",
            4 => "This account might be expended.",
            _ => str,
        };
    } else if str.starts_with("Authentication Fail") {
        let errcode: i32 = str[19..].trim().parse().unwrap_or(-1);
        return match errcode {
            0 => "Username or password invalid.",
            5 => "This account is suspended.",
            9 => "This account might be expended.",
            11 => "You are not allowed to perform a radius authentication.",
            16 => "You are not allowed to access the internet now.",
            30 | 63 => "No more time available for this account.",
            _ => str,
        };
    } else if str.starts_with("AdminReset") {
        return str;
    } else if str.contains("Mac, IP, NASip, PORT") {
        return "You are not allowed to login using current IP/MAC address.";
    } else if str.contains("flowover") {
        return "Data usage has reached the limit.";
    } else if str.contains("In use") {
        return "This account is in use.";
    }
    str
}