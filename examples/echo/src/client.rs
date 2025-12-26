//! Echo client implementation with Noise_IK handshake.
//!
//! A NOMAD echo client that performs proper cryptographic handshake
//! and encrypts all messages using the derived session keys.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nomad_protocol::core::SyncState;
use nomad_protocol::crypto::{
    CryptoSession, InitiatorHandshake, Role, SessionId, SessionKeys, StaticKeypair,
};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::state::EchoState;

/// Message types for the protocol (per specs/1-SECURITY.md).
mod msg_type {
    /// Handshake initiation (client -> server) - Type 0x01
    pub const HANDSHAKE_INIT: u8 = 0x01;
    /// Handshake response (server -> client) - Type 0x02
    pub const HANDSHAKE_RESP: u8 = 0x02;
    /// Encrypted data frame - Type 0x03
    pub const DATA: u8 = 0x03;
}

/// Client configuration.
#[derive(Clone)]
pub struct EchoClientConfig {
    /// Server address.
    pub server_addr: SocketAddr,
    /// Server public key (32 bytes).
    pub server_public_key: [u8; 32],
    /// Local bind address (0 = auto).
    pub bind_addr: SocketAddr,
    /// Client keypair (generated if not provided).
    pub client_keypair: Option<StaticKeypair>,
    /// Enable persistent mode (stay connected after test).
    pub persistent: bool,
}

impl std::fmt::Debug for EchoClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EchoClientConfig")
            .field("server_addr", &self.server_addr)
            .field("server_public_key", &"[redacted]")
            .field("bind_addr", &self.bind_addr)
            .field("client_keypair", &self.client_keypair.as_ref().map(|_| "[keypair]"))
            .field("persistent", &self.persistent)
            .finish()
    }
}

impl Default for EchoClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:19999".parse().unwrap(),
            server_public_key: [0u8; 32],
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            client_keypair: None,
            persistent: false,
        }
    }
}

/// Connected echo client with established crypto session.
pub struct EchoClient {
    config: EchoClientConfig,
    socket: Option<UdpSocket>,
    crypto: Option<CryptoSession>,
    state: Arc<RwLock<EchoState>>,
    sequence: Arc<RwLock<u64>>,
    last_server_seq: Arc<RwLock<u64>>,
    client_keypair: StaticKeypair,
}

impl EchoClient {
    /// Create a new echo client.
    pub fn new(config: EchoClientConfig) -> Self {
        let client_keypair = config
            .client_keypair
            .clone()
            .unwrap_or_else(StaticKeypair::generate);

        Self {
            config,
            socket: None,
            crypto: None,
            state: Arc::new(RwLock::new(EchoState::new())),
            sequence: Arc::new(RwLock::new(0)),
            last_server_seq: Arc::new(RwLock::new(0)),
            client_keypair,
        }
    }

    /// Connect to the server and perform Noise_IK handshake.
    pub async fn connect(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket = UdpSocket::bind(self.config.bind_addr).await?;
        socket.connect(self.config.server_addr).await?;
        eprintln!(
            "Connected to server {} from {}",
            self.config.server_addr,
            socket.local_addr()?
        );

        // Perform Noise_IK handshake
        let session_id = self.perform_handshake(&socket).await?;
        eprintln!("Handshake complete, session_id: {:02x?}", session_id.as_bytes());

        self.socket = Some(socket);
        Ok(())
    }

    /// Perform the Noise_IK handshake.
    ///
    /// Wire format per specs/1-SECURITY.md:
    /// - HandshakeInit: [Type:1][Reserved:1][Version:2][Noise message...]
    /// - HandshakeResp: [Type:1][Reserved:1][SessionID:6][Noise message...]
    async fn perform_handshake(
        &mut self,
        socket: &UdpSocket,
    ) -> Result<SessionId, Box<dyn std::error::Error + Send + Sync>> {
        // Create initiator handshake state
        let mut handshake =
            InitiatorHandshake::new(&self.client_keypair, &self.config.server_public_key)?;

        // Build handshake initiation with state type ID as payload
        let payload = EchoState::STATE_TYPE_ID.as_bytes();
        let noise_message = handshake.write_message(payload)?;

        // Build packet per spec: [Type:1][Reserved:1][Version:2][Noise message...]
        let mut packet = Vec::with_capacity(4 + noise_message.len());
        packet.push(msg_type::HANDSHAKE_INIT);  // Type 0x01
        packet.push(0x00);                       // Reserved
        packet.extend_from_slice(&0x0001u16.to_le_bytes());  // Protocol version 1.0
        packet.extend_from_slice(&noise_message);
        socket.send(&packet).await?;

        eprintln!("Sent handshake init ({} bytes)", packet.len());

        // Wait for handshake response
        let mut buf = [0u8; 65535];
        let recv_result = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf)).await;

        let len = match recv_result {
            Ok(Ok(len)) => len,
            Ok(Err(e)) => return Err(format!("Receive error: {}", e).into()),
            Err(_) => return Err("Handshake timeout".into()),
        };

        let data = &buf[..len];

        // Parse response header: [Type:1][Reserved:1][SessionID:6][Noise response...]
        if data.len() < 8 {
            return Err("HandshakeResp too short".into());
        }
        if data[0] != msg_type::HANDSHAKE_RESP {
            return Err(format!("Unexpected response type: {:02x}", data[0]).into());
        }
        let _reserved = data[1];

        // Extract session ID from header (in the clear)
        let mut session_id_bytes = [0u8; 6];
        session_id_bytes.copy_from_slice(&data[2..8]);
        let session_id = SessionId::from_bytes(session_id_bytes);

        // Process Noise response (starts at byte 8)
        let noise_response = &data[8..];
        let (server_payload, handshake_result) = handshake.read_message(noise_response)?;

        eprintln!(
            "Received handshake response, session_id: {:02x?}, server payload: {:?}",
            session_id.as_bytes(),
            String::from_utf8_lossy(&server_payload)
        );

        // Compute static DH secret for PCS (Post-Compromise Security)
        let static_dh_secret = self.client_keypair.compute_static_dh(&self.config.server_public_key);

        // Derive session keys (includes rekey_auth_key for PCS)
        let session_keys = SessionKeys::derive(&handshake_result, &static_dh_secret)?;

        // Create crypto session
        let crypto = CryptoSession::new(
            session_id,
            Role::Initiator,
            session_keys.initiator_key,
            session_keys.responder_key,
            handshake_result.handshake_hash,
            session_keys.rekey_auth_key,
        );

        self.crypto = Some(crypto);
        Ok(session_id)
    }

    /// Send an encrypted message to the server.
    pub async fn send_message(
        &mut self,
        message: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket = self.socket.as_ref().ok_or("Not connected")?;
        let crypto = self.crypto.as_mut().ok_or("No crypto session")?;

        // Increment sequence
        let seq = {
            let mut seq = self.sequence.write().await;
            *seq += 1;
            *seq
        };

        // Update local state
        {
            let mut state = self.state.write().await;
            state.message = message.to_vec();
            state.sequence = seq;
        }

        // Build plaintext: [sequence:8][payload...]
        let mut plaintext = Vec::with_capacity(8 + message.len());
        plaintext.extend_from_slice(&seq.to_le_bytes());
        plaintext.extend_from_slice(message);

        // Encrypt the frame
        let (nonce_counter, ciphertext) = crypto.encrypt_frame(msg_type::DATA, 0x00, &plaintext)?;

        // Build packet: [type:1][session_id:6][nonce:8][ciphertext...]
        let session_id = crypto.session_id();
        let mut packet = Vec::with_capacity(15 + ciphertext.len());
        packet.push(msg_type::DATA);
        packet.extend_from_slice(session_id.as_bytes());
        packet.extend_from_slice(&nonce_counter.to_le_bytes());
        packet.extend_from_slice(&ciphertext);

        socket.send(&packet).await?;
        eprintln!(
            "Sent encrypted message: seq={}, nonce={}, msg={:?}",
            seq,
            nonce_counter,
            String::from_utf8_lossy(message)
        );

        Ok(())
    }

    /// Receive an encrypted response from the server.
    pub async fn recv_response(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<EchoState>, Box<dyn std::error::Error + Send + Sync>> {
        let socket = self.socket.as_ref().ok_or("Not connected")?;
        let crypto = self.crypto.as_mut().ok_or("No crypto session")?;

        let mut buf = [0u8; 65535];

        let result = tokio::time::timeout(timeout, socket.recv(&mut buf)).await;

        match result {
            Ok(Ok(len)) => {
                let data = &buf[..len];

                // Minimum: type(1) + session_id(6) + nonce(8) + tag(16)
                if data.len() < 31 {
                    eprintln!("Response too short: {} bytes", len);
                    return Ok(None);
                }

                let msg_type = data[0];
                if msg_type != msg_type::DATA {
                    eprintln!("Unexpected message type: {:02x}", msg_type);
                    return Ok(None);
                }

                // Parse header
                let _session_id = &data[1..7];
                let nonce_counter = u64::from_le_bytes(data[7..15].try_into()?);
                let ciphertext = &data[15..];

                // Decrypt
                let plaintext = crypto.decrypt_frame(msg_type::DATA, 0x00, nonce_counter, ciphertext)?;

                // Parse plaintext: [server_seq:8][acked_seq:8][payload...]
                if plaintext.len() < 16 {
                    eprintln!("Plaintext too short: {} bytes", plaintext.len());
                    return Ok(None);
                }

                let server_seq = u64::from_le_bytes(plaintext[0..8].try_into()?);
                let acked_seq = u64::from_le_bytes(plaintext[8..16].try_into()?);
                let payload = &plaintext[16..];

                eprintln!(
                    "Received encrypted response: server_seq={}, acked={}, msg={:?}",
                    server_seq,
                    acked_seq,
                    String::from_utf8_lossy(payload)
                );

                // Update last server sequence
                {
                    let mut last = self.last_server_seq.write().await;
                    if server_seq > *last {
                        *last = server_seq;
                    }
                }

                Ok(Some(EchoState {
                    message: payload.to_vec(),
                    sequence: server_seq,
                }))
            }
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Ok(None), // Timeout
        }
    }

    /// Send a message and wait for echo response.
    pub async fn echo(
        &mut self,
        message: &[u8],
    ) -> Result<EchoState, Box<dyn std::error::Error + Send + Sync>> {
        self.send_message(message).await?;

        // Wait for response with retries
        for attempt in 0..3 {
            if let Some(response) = self.recv_response(Duration::from_millis(500)).await? {
                return Ok(response);
            }
            eprintln!("No response, retrying... (attempt {})", attempt + 1);
            self.send_message(message).await?;
        }

        Err("No response from server after 3 attempts".into())
    }

    /// Run in persistent mode - stay connected and echo stdin.
    pub async fn run_persistent(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::io::{AsyncBufReadExt, BufReader};

        eprintln!("Persistent mode: Enter messages to echo (Ctrl+C to exit)");

        let stdin = tokio::io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();

        loop {
            match lines.next_line().await {
                Ok(Some(text)) => {
                    if text.is_empty() {
                        continue;
                    }
                    match self.echo(text.as_bytes()).await {
                        Ok(response) => {
                            let echoed = String::from_utf8_lossy(&response.message);
                            if response.message == text.as_bytes() {
                                eprintln!("✓ Echo matched: {:?}", echoed);
                            } else {
                                eprintln!("✗ Echo mismatch: expected {:?}, got {:?}", text, echoed);
                            }
                        }
                        Err(e) => {
                            eprintln!("✗ Echo failed: {}", e);
                        }
                    }
                }
                Ok(None) => {
                    eprintln!("EOF received, exiting");
                    break;
                }
                Err(e) => {
                    eprintln!("Read error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Get current local state.
    pub async fn state(&self) -> EchoState {
        self.state.read().await.clone()
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.socket.is_some() && self.crypto.is_some()
    }

    /// Disconnect from server.
    pub fn disconnect(&mut self) {
        self.socket = None;
        self.crypto = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_config_default() {
        let config = EchoClientConfig::default();
        assert_eq!(config.server_addr.port(), 19999);
        assert!(!config.persistent);
    }
}
