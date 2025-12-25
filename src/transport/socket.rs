//! Async UDP socket wrapper for NOMAD transport.
//!
//! Provides a high-level interface for sending and receiving NOMAD frames
//! over UDP.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use super::frame::sizes;

/// Default receive buffer size.
pub const DEFAULT_RECV_BUFFER_SIZE: usize = 65535;

/// Async UDP socket wrapper for NOMAD.
///
/// Provides convenient methods for sending/receiving frames with
/// proper buffer management.
#[derive(Debug)]
pub struct NomadSocket {
    /// The underlying UDP socket.
    socket: Arc<UdpSocket>,
    /// Receive buffer.
    recv_buffer: Vec<u8>,
    /// Maximum payload size (for MTU considerations).
    max_payload_size: usize,
}

impl NomadSocket {
    /// Create a new NOMAD socket bound to the given address.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self::from_socket(socket))
    }

    /// Create a NOMAD socket from an existing UDP socket.
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            recv_buffer: vec![0u8; DEFAULT_RECV_BUFFER_SIZE],
            max_payload_size: sizes::DEFAULT_MAX_PAYLOAD,
        }
    }

    /// Set the maximum payload size (for MTU considerations).
    pub fn set_max_payload_size(&mut self, size: usize) {
        self.max_payload_size = size;
    }

    /// Get the maximum payload size.
    pub fn max_payload_size(&self) -> usize {
        self.max_payload_size
    }

    /// Get the local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Connect to a remote address (for client sockets).
    ///
    /// After connecting, `send` and `recv` can be used instead of
    /// `send_to` and `recv_from`.
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.socket.connect(addr).await
    }

    /// Send data to a specific address.
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(data, addr).await
    }

    /// Send data to the connected address.
    pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
        self.socket.send(data).await
    }

    /// Receive data and return the sender's address.
    pub async fn recv_from(&mut self) -> io::Result<(&[u8], SocketAddr)> {
        let (len, addr) = self.socket.recv_from(&mut self.recv_buffer).await?;
        Ok((&self.recv_buffer[..len], addr))
    }

    /// Receive data from the connected address.
    pub async fn recv(&mut self) -> io::Result<&[u8]> {
        let len = self.socket.recv(&mut self.recv_buffer).await?;
        Ok(&self.recv_buffer[..len])
    }

    /// Try to receive data without blocking.
    ///
    /// Returns `Ok(None)` if no data is available.
    pub fn try_recv_from(&mut self) -> io::Result<Option<(usize, SocketAddr)>> {
        match self.socket.try_recv_from(&mut self.recv_buffer) {
            Ok((len, addr)) => Ok(Some((len, addr))),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get the received data after a successful `try_recv_from`.
    pub fn recv_data(&self, len: usize) -> &[u8] {
        &self.recv_buffer[..len]
    }

    /// Get a reference to the underlying socket.
    pub fn inner(&self) -> &UdpSocket {
        &self.socket
    }

    /// Get a clone of the Arc-wrapped socket.
    pub fn socket_arc(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Calculate maximum frame size considering headers.
    pub fn max_frame_size(&self) -> usize {
        self.max_payload_size + sizes::DATA_FRAME_HEADER_SIZE + sizes::AEAD_TAG_SIZE
    }
}

/// Builder for creating NOMAD sockets with custom options.
#[derive(Debug, Clone)]
pub struct NomadSocketBuilder {
    recv_buffer_size: usize,
    max_payload_size: usize,
}

impl Default for NomadSocketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NomadSocketBuilder {
    /// Create a new socket builder with default options.
    pub fn new() -> Self {
        Self {
            recv_buffer_size: DEFAULT_RECV_BUFFER_SIZE,
            max_payload_size: sizes::DEFAULT_MAX_PAYLOAD,
        }
    }

    /// Set the receive buffer size.
    pub fn recv_buffer_size(mut self, size: usize) -> Self {
        self.recv_buffer_size = size;
        self
    }

    /// Set the maximum payload size.
    pub fn max_payload_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
        self
    }

    /// Bind to the given address and create a socket.
    pub async fn bind(self, addr: SocketAddr) -> io::Result<NomadSocket> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(self.from_socket(socket))
    }

    /// Create a socket from an existing UDP socket.
    pub fn from_socket(self, socket: UdpSocket) -> NomadSocket {
        NomadSocket {
            socket: Arc::new(socket),
            recv_buffer: vec![0u8; self.recv_buffer_size],
            max_payload_size: self.max_payload_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_socket_bind() {
        let socket = NomadSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = socket.local_addr().unwrap();
        assert!(addr.port() != 0);
    }

    #[tokio::test]
    async fn test_socket_send_recv() {
        let mut server = NomadSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = NomadSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        // Send from client
        let data = b"hello NOMAD";
        client.send_to(data, server_addr).await.unwrap();

        // Receive on server
        let (received, from) = server.recv_from().await.unwrap();
        assert_eq!(received, data);
        assert_eq!(from, client.local_addr().unwrap());
    }

    #[tokio::test]
    async fn test_socket_connected() {
        let mut server = NomadSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = NomadSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        client.connect(server_addr).await.unwrap();

        // Send using connected interface
        let data = b"connected send";
        client.send(data).await.unwrap();

        // Receive on server
        let (received, _) = server.recv_from().await.unwrap();
        assert_eq!(received, data);
    }

    #[test]
    fn test_socket_builder() {
        let builder = NomadSocketBuilder::new()
            .recv_buffer_size(4096)
            .max_payload_size(1400);

        assert_eq!(builder.recv_buffer_size, 4096);
        assert_eq!(builder.max_payload_size, 1400);
    }

    #[tokio::test]
    async fn test_max_frame_size() {
        let socket = NomadSocketBuilder::new()
            .max_payload_size(1200)
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        // max_frame_size = payload + header + tag
        let expected = 1200 + sizes::DATA_FRAME_HEADER_SIZE + sizes::AEAD_TAG_SIZE;
        assert_eq!(socket.max_frame_size(), expected);
    }
}
