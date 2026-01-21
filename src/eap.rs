use std::net::Ipv4Addr;

// use smoltcp::wire::{EthernetAddress, EthernetFrame};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet_datalink::MacAddr;

use crate::net::datalink::EAPOL;

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
    Allocated0x07 = 7,
    Allocated0x08 = 8,
    Unknown,
}

pub const EAPOL_PKT_LEN: usize = 96;

pub struct EAPoL<'a> {
    pub data: EthernetPacket<'a>,
}

impl<'a> EAPoL<'a> {
    pub fn new(data: EthernetPacket<'a>) -> Option<Self> {
        let pkt = data.packet();
        let pkt_check_len = u16::from_be_bytes([pkt[20], pkt[21]]);
        log::debug!("EAPol Length: {}, {}", pkt.len(), pkt_check_len);
        if data.get_ethertype() != EAPOL {
            return None;
        }
        Some(Self { data })
    }

    pub fn eap_code(&self) -> Code {
        match self.data.packet()[18] {
            1 => Code::REQUEST,
            2 => Code::RESPONSE,
            3 => Code::SUCCESS,
            4 => Code::FAILURE,
            10 => Code::H3CDATA,
            _ => Code::Unknown,
        }
    }

    pub fn eap_type(&self) -> Type {
        match self.data.packet()[22] {
            1 => Type::IDENTITY,
            2 => Type::NOTIFICATION,
            4 => Type::MD5,
            20 => Type::AVAILABLE,
            7 => Type::Allocated0x07,
            8 => Type::Allocated0x08,
            _ => Type::Unknown,
        }
    }

    pub fn eap_id(&self) -> u8 {
        self.data.packet()[19]
    }

    pub fn md5_challenge(&self) -> &[u8] {
        &self.data.packet()[24..40]
    }

    pub fn src_addr(&self) -> MacAddr {
        self.data.get_source()
    }

    pub fn parse_error(&self) -> &str {
        let error = std::str::from_utf8(&self.data.packet()[23..]).unwrap();
        eap_err_parse(error)
    }
}

pub struct SendEAPoL<'a> {
    // pub data: EthernetFrame<[u8; EAPOL_PKT_LEN]>,
    pub data: MutableEthernetPacket<'a>,
}

impl<'a> SendEAPoL<'a> {
    fn eap_id(&self) -> u8 {
        self.data.packet()[19]
    }

    pub fn new(data: &'a mut [u8]) -> Self {
        assert!(data.len() >= EAPOL_PKT_LEN);
        let mut data = MutableEthernetPacket::new(data).expect("Fail to construct send packet");
        data.set_ethertype(EAPOL);
        let mut it = Self { data };
        it.set_version();
        it
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

    pub fn set_version(&mut self) {
        self.data.payload_mut()[0] = 0x01; // Version 1
    }

    pub fn set_length(&mut self, len: u16) {
        // TODO: big small endian
        self.data.payload_mut()[16 - 14..].copy_from_slice(&len.to_be_bytes());
        self.data.payload_mut()[20 - 14..].copy_from_slice(&len.to_be_bytes());
    }

    pub fn set_zerolength(&mut self) {
        self.data.payload_mut()[2] = 0;
        self.data.payload_mut()[3] = 0;
    }

    pub fn set_md5_challenge(&mut self, password: &str, challenge: &[u8]) {
        let mut md5 = md5::Context::new();
        md5.consume([self.eap_id()]);
        md5.consume(password.as_bytes());
        md5.consume(&challenge[..16]);
        let digest = md5.compute();
        self.data.payload_mut()[24 - 14..40 - 14].copy_from_slice(digest.as_ref());
    }

    pub fn set_response_type(&mut self, response_type: u8) {
        self.data.payload_mut()[1] = response_type; // Type Start
    }

    pub fn start(&mut self) {
        self.set_response_type(0x01);
        self.set_zerolength();
    }

    pub fn identity(&mut self, id: u8, ipaddr: Ipv4Addr, username: &str) {
        self.set_response_type(0x00);

        // Extensible Authentication Protocol
        self.set_eap_code(Code::RESPONSE); // Code
        self.set_eap_id(id); // ID
        self.set_eap_type(Type::IDENTITY); // Type

        // Username
        let mut pos = 23 - 14;
        self.data.payload_mut()[pos..pos + username.len()].copy_from_slice(username.as_bytes());
        pos += username.len();

        let fill = [0x0, 0x44, 0x61, 0x0, 0x0];
        self.data.payload_mut()[pos..pos + 5].copy_from_slice(&fill);
        pos += fill.len();

        // IP Address
        self.data.payload_mut()[pos..pos + ipaddr.octets().len()].copy_from_slice(&ipaddr.octets());

        // Length
        let eap_len: u16 = username.len() as u16 + 14;
        self.set_length(eap_len);
    }

    pub fn md5_response(
        &mut self,
        id: u8,
        ipaddr: Ipv4Addr,
        challenge: &[u8],
        username: &str,
        password: &str,
    ) {
        self.set_response_type(0x00); // Type EAP Packet

        // Extensible Authentication Protocol
        self.set_eap_code(Code::RESPONSE); // Code
        self.set_eap_id(id); // ID
        self.set_eap_type(Type::MD5); // Type
        self.data.payload_mut()[23 - 14] = 0x10; // Value-Size: 16 Bytes

        // MD5 Challenge
        self.set_md5_challenge(password, challenge);

        // Username
        let mut pos = 40 - 14;
        self.data.payload_mut()[pos..pos + username.len()].copy_from_slice(username.as_bytes());
        pos += username.len();

        let fill = [0x0, 0x44, 0x61, 0x2a, 0x0];
        self.data.payload_mut()[pos..pos + 5].copy_from_slice(&fill);
        pos += fill.len();

        // IP Address
        self.data.payload_mut()[pos..pos + ipaddr.octets().len()].copy_from_slice(&ipaddr.octets());
        // pos += ipaddr.octets().len();

        // Length
        let eap_len: u16 = username.len() as u16 + 31;
        self.set_length(eap_len);
    }

    pub fn logoff(&mut self) {
        self.data.payload_mut().fill(0xa5);
        self.set_version();
        self.set_response_type(0x02);
        self.set_zerolength();
    }
}

pub fn eap_err_parse(str: &str) -> &str {
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
