use std::io::ErrorKind;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use crate::config::{DRCOM_SERVER_PORT, DRCOM_UDP_RECV_DELAY, ETH_FRAME_LEN, SERVER_ADDR};
use crate::error::AuthError;

pub struct UdpTransport {
    socket: UdpSocket,
    recv_buf: [u8; ETH_FRAME_LEN],
    send_buf: [u8; ETH_FRAME_LEN],
}

impl UdpTransport {
    pub fn new(local_ip: Ipv4Addr) -> Result<Self, AuthError> {
        let socket = UdpSocket::bind((local_ip, DRCOM_SERVER_PORT)).map_err(|e| {
            log::error!("Failed to bind UDP socket: {}", e);
            AuthError::Io(e)
        })?;
        socket.set_broadcast(true)?;
        socket.set_read_timeout(Some(Duration::from_secs(DRCOM_UDP_RECV_DELAY)))?;
        socket.connect((SERVER_ADDR, DRCOM_SERVER_PORT))?;

        Ok(Self {
            socket,
            recv_buf: [0; ETH_FRAME_LEN],
            send_buf: [0; ETH_FRAME_LEN],
        })
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn socket_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }

    pub fn recv_buf(&self) -> &[u8] {
        &self.recv_buf
    }

    pub fn send_buf_mut(&mut self) -> &mut [u8] {
        &mut self.send_buf
    }

    pub fn set_timeout(&mut self, timeout: Duration) -> Result<(), AuthError> {
        self.socket.set_read_timeout(Some(timeout))?;
        Ok(())
    }

    /// Non-blocking receive for UDP packets.
    /// Returns Ok(Some(len)) if a packet is received,
    /// Ok(None) if no packet is ready (would-block),
    /// Err for actual errors.
    pub fn try_recv(&mut self) -> Result<Option<usize>, AuthError> {
        match self.socket.recv(&mut self.recv_buf) {
            Ok(len) => Ok(Some(len)),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                Ok(None)
            }
            Err(e) => Err(AuthError::Io(e)),
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Result<usize, AuthError> {
        self.socket.send(data).map_err(AuthError::Io)
    }

    pub fn send_from_buf(&mut self, len: usize) -> Result<usize, AuthError> {
        self.socket.send(&self.send_buf[..len]).map_err(AuthError::Io)
    }
}
