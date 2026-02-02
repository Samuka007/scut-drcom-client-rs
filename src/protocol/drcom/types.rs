#[derive(Debug, Clone, Copy)]
pub enum AuthType {
    StartAlive = 0x01,
    ResponseForAlive = 0x02,
    Info = 0x03,
    ResponseInfo = 0x04,
    HeartBeat = 0x0b,
    ResponseHeartBeat = 0x06,
    Unknown,
}

impl From<u8> for AuthType {
    fn from(val: u8) -> Self {
        match val {
            0x01 => AuthType::StartAlive,
            0x02 => AuthType::ResponseForAlive,
            0x03 => AuthType::Info,
            0x04 => AuthType::ResponseInfo,
            0x0b => AuthType::HeartBeat,
            0x06 => AuthType::ResponseHeartBeat,
            _ => AuthType::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum MiscType {
    HeartBeat01Type = 0x01,
    HeartBeat02Type = 0x02,
    HeartBeat03Type = 0x03,
    HeartBeat04Type = 0x04,
    FileType = 0x06,
    Unknown,
}

impl From<u8> for MiscType {
    fn from(val: u8) -> Self {
        match val {
            0x01 => MiscType::HeartBeat01Type,
            0x02 => MiscType::HeartBeat02Type,
            0x03 => MiscType::HeartBeat03Type,
            0x04 => MiscType::HeartBeat04Type,
            0x06 => MiscType::FileType,
            _ => MiscType::Unknown,
        }
    }
}
