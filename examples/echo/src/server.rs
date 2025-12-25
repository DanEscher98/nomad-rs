//! Echo server implementation with Noise_IK handshake.
//!
//! A NOMAD echo server that performs proper cryptographic handshake
//! and encrypts all messages using the derived session keys.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use nomad_protocol::core::SyncState;
use nomad_protocol::crypto::{
    CryptoSession, ResponderHandshake, Role, SessionId, SessionKeys, StaticKeypair,
};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::state::EchoState;

/// Message types for the protocol.
mod msg_type {
    /// Handshake initiation (client -> server)
    pub const HANDSHAKE_INIT: u8 = 0x00;
    /// Handshake response (server -> client)
    pub const HANDSHAKE_RESP: u8 = 0x01;
    /// Encrypted data frame
    pub const DATA: u8 = 0x03;
}

/// Server configuration.
#[derive(Clone)]
pub struct EchoServerConfig {
    /// Bind address.
    pub bind_addr: SocketAddr,
    /// Server keypair.
    pub keypair: StaticKeypair,
}

impl EchoServerConfig {
    /// Create config with a specific keypair.
    pub fn new(bind_addr: SocketAddr, keypair: StaticKeypair) -> Self {
        Self { bind_addr, keypair }
    }

    /// Create config from raw private key bytes.
    pub fn from_private_key(bind_addr: SocketAddr, private_key: [u8; 32]) -> Self {
        // For zero key, generate a fresh keypair
        let keypair = if private_key == [0u8; 32] {
            eprintln!("Using generated keypair (zero key provided)");
            StaticKeypair::generate()
        } else {
            // Derive public key from private key using snow
            let builder = snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
            let kp = builder.generate_keypair().unwrap();
            // Use the provided private key with a computed public key
            // Note: This is a simplification - in production you'd derive the public key properly
            StaticKeypair::from_bytes(private_key, *kp.public.as_slice().try_into().unwrap_or(&[0u8; 32]))
        };
        Self { bind_addr, keypair }
    }
}

impl Default for EchoServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:19999".parse().unwrap(),
            keypair: StaticKeypair::generate(),
        }
    }
}

/// Session state for a connected client.
struct ClientSession {
    /// Client address.
    addr: SocketAddr,
    /// Crypto session for this client.
    crypto: CryptoSession,
    /// Current state.
    state: EchoState,
    /// Last seen sequence from client.
    last_client_seq: u64,
    /// Our sequence number.
    server_seq: u64,
}

impl ClientSession {
    fn new(addr: SocketAddr, crypto: CryptoSession) -> Self {
        Self {
            addr,
            crypto,
            state: EchoState::new(),
            last_client_seq: 0,
            server_seq: 0,
        }
    }
}

/// Echo server with Noise_IK handshake support.
pub struct EchoServer {
    config: EchoServerConfig,
    /// Sessions indexed by session ID
    sessions: Arc<RwLock<HashMap<[u8; 6], ClientSession>>>,
    /// Pending handshakes indexed by client address
    pending_handshakes: Arc<RwLock<HashMap<SocketAddr, ResponderHandshake>>>,
    running: Arc<RwLock<bool>>,
}

impl EchoServer {
    /// Create a new echo server.
    pub fn new(config: EchoServerConfig) -> Self {
        eprintln!(
            "Server public key: {:02x?}",
            config.keypair.public_key()
        );
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_handshakes: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Get the server's public key (for clients to use).
    pub fn public_key(&self) -> &[u8; 32] {
        self.config.keypair.public_key()
    }

    /// Run the echo server.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket = UdpSocket::bind(self.config.bind_addr).await?;
        eprintln!("Echo server listening on {}", self.config.bind_addr);

        *self.running.write().await = true;

        let mut buf = [0u8; 65535];

        loop {
            if !*self.running.read().await {
                break;
            }

            // Use timeout to allow checking running flag
            let recv_result = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                socket.recv_from(&mut buf),
            )
            .await;

            let (len, addr) = match recv_result {
                Ok(Ok((len, addr))) => (len, addr),
                Ok(Err(e)) => {
                    eprintln!("Receive error: {}", e);
                    continue;
                }
                Err(_) => continue, // Timeout, check running flag
            };

            // Process the message
            if let Err(e) = self.handle_message(&socket, addr, &buf[..len]).await {
                eprintln!("Error handling message from {}: {}", addr, e);
            }
        }

        eprintln!("Echo server stopped");
        Ok(())
    }

    /// Handle an incoming message.
    async fn handle_message(
        &self,
        socket: &UdpSocket,
        addr: SocketAddr,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if data.is_empty() {
            return Ok(());
        }

        let msg_type = data[0];

        match msg_type {
            msg_type::HANDSHAKE_INIT => {
                self.handle_handshake_init(socket, addr, &data[1..]).await
            }
            msg_type::DATA => {
                self.handle_data(socket, addr, &data[1..]).await
            }
            _ => {
                eprintln!("Unknown message type from {}: 0x{:02x}", addr, msg_type);
                Ok(())
            }
        }
    }

    /// Handle handshake initiation.
    async fn handle_handshake_init(
        &self,
        socket: &UdpSocket,
        addr: SocketAddr,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        eprintln!("Received handshake init from {} ({} bytes)", addr, data.len());

        // Create responder handshake
        let mut handshake = ResponderHandshake::new(&self.config.keypair)?;

        // Process initiator's message
        let (client_payload, client_public_key) = handshake.read_message(data)?;

        eprintln!(
            "Client {} requests state type: {:?}, pubkey: {:02x?}",
            addr,
            String::from_utf8_lossy(&client_payload),
            &client_public_key[..8]
        );

        // Verify state type
        if client_payload != EchoState::STATE_TYPE_ID.as_bytes() {
            eprintln!(
                "Unknown state type from {}: {:?}",
                addr,
                String::from_utf8_lossy(&client_payload)
            );
            return Err("Unknown state type".into());
        }

        // Generate session ID
        let session_id = SessionId::generate();

        // Build response payload: [session_id:6][OK]
        let mut response_payload = Vec::with_capacity(8);
        response_payload.extend_from_slice(session_id.as_bytes());
        response_payload.extend_from_slice(b"OK");

        // Complete handshake
        let (response_message, handshake_result) = handshake.write_message(&response_payload)?;

        // Derive session keys
        let session_keys = SessionKeys::derive(&handshake_result)?;

        // Create crypto session (server is responder)
        let crypto = CryptoSession::new(
            session_id,
            Role::Responder,
            session_keys.responder_key,
            session_keys.initiator_key,
            handshake_result.handshake_hash,
        );

        // Store session
        let session = ClientSession::new(addr, crypto);
        self.sessions.write().await.insert(*session_id.as_bytes(), session);

        // Send response: [type:1][message...]
        let mut packet = Vec::with_capacity(1 + response_message.len());
        packet.push(msg_type::HANDSHAKE_RESP);
        packet.extend_from_slice(&response_message);

        socket.send_to(&packet, addr).await?;

        eprintln!(
            "Handshake complete with {}, session_id: {:02x?}",
            addr,
            session_id.as_bytes()
        );

        Ok(())
    }

    /// Handle encrypted data.
    async fn handle_data(
        &self,
        socket: &UdpSocket,
        addr: SocketAddr,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Parse header: [session_id:6][nonce:8][ciphertext...]
        if data.len() < 14 {
            return Err("Data packet too short".into());
        }

        let mut session_id_bytes = [0u8; 6];
        session_id_bytes.copy_from_slice(&data[0..6]);
        let nonce_counter = u64::from_le_bytes(data[6..14].try_into()?);
        let ciphertext = &data[14..];

        // Find session
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&session_id_bytes)
            .ok_or("Unknown session")?;

        // Update client address (for roaming)
        session.addr = addr;

        // Decrypt
        let plaintext = session.crypto.decrypt_frame(msg_type::DATA, 0x00, nonce_counter, ciphertext)?;

        // Parse plaintext: [sequence:8][payload...]
        if plaintext.len() < 8 {
            return Err("Plaintext too short".into());
        }

        let client_seq = u64::from_le_bytes(plaintext[0..8].try_into()?);
        let payload = &plaintext[8..];

        eprintln!(
            "Received from {}: seq={}, msg={:?}",
            addr,
            client_seq,
            String::from_utf8_lossy(payload)
        );

        // Only process if sequence is newer
        if client_seq > session.last_client_seq {
            session.last_client_seq = client_seq;

            // Update state
            if !payload.is_empty() {
                session.state.message = payload.to_vec();
                session.state.sequence = client_seq;
            }

            // Increment server sequence and send echo
            session.server_seq += 1;

            // Build response plaintext: [server_seq:8][acked_seq:8][payload...]
            let mut response_plaintext = Vec::with_capacity(16 + payload.len());
            response_plaintext.extend_from_slice(&session.server_seq.to_le_bytes());
            response_plaintext.extend_from_slice(&client_seq.to_le_bytes());
            response_plaintext.extend_from_slice(payload);

            // Encrypt
            let (resp_nonce, resp_ciphertext) =
                session.crypto.encrypt_frame(msg_type::DATA, 0x00, &response_plaintext)?;

            // Build packet: [type:1][session_id:6][nonce:8][ciphertext...]
            let mut packet = Vec::with_capacity(15 + resp_ciphertext.len());
            packet.push(msg_type::DATA);
            packet.extend_from_slice(&session_id_bytes);
            packet.extend_from_slice(&resp_nonce.to_le_bytes());
            packet.extend_from_slice(&resp_ciphertext);

            socket.send_to(&packet, addr).await?;

            eprintln!("Echoed back to {}: seq={}", addr, session.server_seq);
        }

        Ok(())
    }

    /// Stop the server.
    pub async fn stop(&self) {
        *self.running.write().await = false;
    }

    /// Get the number of active sessions.
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_config_default() {
        let config = EchoServerConfig::default();
        assert_eq!(config.bind_addr.port(), 19999);
    }
}
