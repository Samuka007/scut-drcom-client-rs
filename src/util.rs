// pub constants
pub const DRCOM_UDP_HEARTBEAT_DELAY: u64 = 12; // Drcom client heartbeat delay in seconds, default 12 seconds
pub const DRCOM_UDP_HEARTBEAT_TIMEOUT: u64 = 2; // Drcom client heartbeat timeout in seconds
pub const DRCOM_UDP_RECV_DELAY: u64 = 2; // Drcom client receive UDP packet delay in seconds, default 2 seconds
pub const AUTH_8021X_LOGOFF_DELAY: u64 = 500_000; // Client logout receive packet wait time 0.5 seconds (500,000 microseconds)
pub const AUTH_8021X_RECV_DELAY: u64 = 1; // Client receive 8021x packet delay in seconds, default 1 second
pub const AUTH_8021X_RECV_TIMES: u32 = 3; // Client receive 8021x packet retry times

// Static pub constants
pub const BROADCAST_ADDR: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]; // Broadcast MAC address
pub const MULTICAST_ADDR: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]; // Multicast MAC address
pub const UNICAST_ADDR: [u8; 6] = [0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03]; // Unicast MAC address

