use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    // Network errors
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),
    #[error("Failed to create channel: {0}")]
    ChannelCreationFailed(String),
    #[error("No MAC address on interface")]
    NoMacAddress,
    #[error("No IPv4 address on interface")]
    NoIpv4Address,
    #[error("Network error: {0}")]
    Network(String),
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),

    // Protocol errors
    #[error("Timeout")]
    Timeout,
    #[error("Invalid packet")]
    InvalidPacket,
    #[error("EAP failure")]
    EapFailure,
    #[error("EAP notification: {0}")]
    Notification(String),
    #[error("Heartbeat timeout")]
    HeartbeatTimeout,

    // IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
