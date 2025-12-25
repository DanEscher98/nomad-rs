//! High-level NOMAD client API.
//!
//! Provides `NomadClient<S>` for connecting to a NOMAD server and synchronizing
//! state of type `S: SyncState`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::sync::{mpsc, oneshot, RwLock};

use crate::core::SyncState;

/// Errors that can occur in the NOMAD client.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Failed to connect to server.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Handshake failed.
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// Session terminated.
    #[error("session terminated: {0}")]
    SessionTerminated(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// State synchronization error.
    #[error("sync error: {0}")]
    SyncError(String),

    /// Client is disconnected.
    #[error("client disconnected")]
    Disconnected,

    /// Operation timed out.
    #[error("operation timed out")]
    Timeout,
}

/// Client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Server address to connect to.
    pub server_addr: SocketAddr,

    /// Server's static public key (32 bytes).
    pub server_public_key: [u8; 32],

    /// Client's static private key (optional, generated if not provided).
    pub client_private_key: Option<[u8; 32]>,

    /// Connection timeout.
    pub connect_timeout: Duration,

    /// Enable compression extension.
    pub enable_compression: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:19999".parse().unwrap(),
            server_public_key: [0u8; 32],
            client_private_key: None,
            connect_timeout: Duration::from_secs(10),
            enable_compression: true,
        }
    }
}

/// Builder for creating a `NomadClient`.
#[derive(Debug)]
pub struct NomadClientBuilder {
    config: ClientConfig,
}

impl NomadClientBuilder {
    /// Create a new client builder.
    pub fn new() -> Self {
        Self {
            config: ClientConfig::default(),
        }
    }

    /// Set the server address.
    pub fn server_addr(mut self, addr: SocketAddr) -> Self {
        self.config.server_addr = addr;
        self
    }

    /// Set the server's public key.
    pub fn server_public_key(mut self, key: [u8; 32]) -> Self {
        self.config.server_public_key = key;
        self
    }

    /// Set the client's private key.
    pub fn client_private_key(mut self, key: [u8; 32]) -> Self {
        self.config.client_private_key = Some(key);
        self
    }

    /// Set the connection timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Enable or disable compression.
    pub fn compression(mut self, enabled: bool) -> Self {
        self.config.enable_compression = enabled;
        self
    }

    /// Build the client configuration.
    pub fn build(self) -> ClientConfig {
        self.config
    }
}

impl Default for NomadClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal client state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Not connected.
    Disconnected,
    /// Handshake in progress.
    Connecting,
    /// Connected and syncing.
    Connected,
    /// Connection closed gracefully.
    Closed,
}

/// Handle for sending state updates to the server.
pub struct StateSender<S: SyncState> {
    tx: mpsc::Sender<S>,
}

impl<S: SyncState> StateSender<S> {
    /// Send a state update to the server.
    ///
    /// This is non-blocking; the update will be queued and sent
    /// according to the pacing algorithm.
    pub async fn send(&self, state: S) -> Result<(), ClientError> {
        self.tx
            .send(state)
            .await
            .map_err(|_| ClientError::Disconnected)
    }
}

impl<S: SyncState> Clone for StateSender<S> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

/// Handle for receiving state updates from the server.
pub struct StateReceiver<S: SyncState> {
    rx: mpsc::Receiver<S>,
}

impl<S: SyncState> StateReceiver<S> {
    /// Receive the next state update from the server.
    ///
    /// Returns `None` if the connection is closed.
    pub async fn recv(&mut self) -> Option<S> {
        self.rx.recv().await
    }
}

/// A NOMAD protocol client.
///
/// Generic over state type `S` which must implement `SyncState`.
///
/// # Example
///
/// ```ignore
/// use nomad_protocol::client::{NomadClient, NomadClientBuilder};
///
/// let config = NomadClientBuilder::new()
///     .server_addr("127.0.0.1:19999".parse()?)
///     .server_public_key(server_pubkey)
///     .build();
///
/// let (client, state_rx) = NomadClient::<MyState>::connect(config, initial_state).await?;
///
/// // Send state updates
/// client.update_state(new_state).await?;
///
/// // Receive server state updates
/// while let Some(server_state) = state_rx.recv().await {
///     // Handle server state
/// }
/// ```
pub struct NomadClient<S: SyncState> {
    /// Current client state.
    state: Arc<RwLock<ClientState>>,

    /// Current local state.
    local_state: Arc<RwLock<S>>,

    /// Channel for sending state updates.
    state_tx: mpsc::Sender<S>,

    /// Shutdown signal.
    shutdown_tx: Option<oneshot::Sender<()>>,

    /// Client configuration.
    config: ClientConfig,
}

impl<S: SyncState> NomadClient<S> {
    /// Connect to a NOMAD server.
    ///
    /// Returns the client handle and a receiver for server state updates.
    pub async fn connect(
        config: ClientConfig,
        initial_state: S,
    ) -> Result<(Self, StateReceiver<S>), ClientError> {
        // Create channels for state communication
        let (state_tx, _state_rx) = mpsc::channel::<S>(32);
        let (server_state_tx, server_state_rx) = mpsc::channel::<S>(32);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();

        let client_state = Arc::new(RwLock::new(ClientState::Connecting));
        let local_state = Arc::new(RwLock::new(initial_state));

        // TODO: Spawn connection task that:
        // 1. Creates UDP socket
        // 2. Performs Noise_IK handshake (via crypto module)
        // 3. Starts sync engine (via sync module)
        // 4. Handles incoming/outgoing frames (via transport module)

        // For now, we set state to Connected (will be replaced with actual handshake)
        {
            let mut state = client_state.write().await;
            *state = ClientState::Connected;
        }

        // Spawn the background I/O task
        let _io_state = client_state.clone();
        let _io_local = local_state.clone();
        let _io_config = config.clone();
        let _io_server_tx = server_state_tx;

        tokio::spawn(async move {
            // TODO: Implement the actual I/O loop
            // This will be implemented when lower layers are ready

            // For now, this is a placeholder that keeps the client "alive"
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        let client = Self {
            state: client_state,
            local_state,
            state_tx,
            shutdown_tx: Some(shutdown_tx),
            config,
        };

        let receiver = StateReceiver { rx: server_state_rx };

        Ok((client, receiver))
    }

    /// Get the current client state.
    pub async fn client_state(&self) -> ClientState {
        *self.state.read().await
    }

    /// Get a copy of the current local state.
    pub async fn local_state(&self) -> S {
        self.local_state.read().await.clone()
    }

    /// Update the local state.
    ///
    /// This queues the state for synchronization with the server.
    pub async fn update_state(&self, new_state: S) -> Result<(), ClientError> {
        // Update local state
        {
            let mut state = self.local_state.write().await;
            *state = new_state.clone();
        }

        // Queue for sending
        self.state_tx
            .send(new_state)
            .await
            .map_err(|_| ClientError::Disconnected)
    }

    /// Get a sender handle for state updates.
    ///
    /// This can be cloned and used from multiple tasks.
    pub fn state_sender(&self) -> StateSender<S> {
        StateSender {
            tx: self.state_tx.clone(),
        }
    }

    /// Check if the client is connected.
    pub async fn is_connected(&self) -> bool {
        matches!(*self.state.read().await, ClientState::Connected)
    }

    /// Gracefully disconnect from the server.
    pub async fn disconnect(mut self) -> Result<(), ClientError> {
        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Update state
        {
            let mut state = self.state.write().await;
            *state = ClientState::Closed;
        }

        Ok(())
    }

    /// Get the server address.
    pub fn server_addr(&self) -> SocketAddr {
        self.config.server_addr
    }
}

impl<S: SyncState> Drop for NomadClient<S> {
    fn drop(&mut self) {
        // Send shutdown signal if not already sent
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    // TODO: Add tests once we have a concrete SyncState implementation
}
