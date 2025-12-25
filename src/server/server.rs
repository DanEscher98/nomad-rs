//! High-level NOMAD server API.
//!
//! Provides `NomadServer<S>` for accepting client connections and synchronizing
//! state of type `S: SyncState`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, RwLock};

use super::session::{ServerSession, ServerSessionId};
use crate::core::SyncState;

/// Errors that can occur in the NOMAD server.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Failed to bind to address.
    #[error("bind failed: {0}")]
    BindFailed(String),

    /// Session error.
    #[error("session error: {0}")]
    SessionError(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Server is shut down.
    #[error("server shut down")]
    Shutdown,

    /// Invalid handshake.
    #[error("invalid handshake: {0}")]
    InvalidHandshake(String),
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address to bind to.
    pub bind_addr: SocketAddr,

    /// Server's static private key (32 bytes).
    pub private_key: [u8; 32],

    /// Maximum number of concurrent sessions.
    pub max_sessions: usize,

    /// Session timeout for cleanup.
    pub session_timeout: Duration,

    /// Enable compression extension.
    pub enable_compression: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:19999"
                .parse()
                .expect("default bind address is valid"),
            private_key: [0u8; 32],
            max_sessions: 1000,
            session_timeout: Duration::from_secs(300),
            enable_compression: true,
        }
    }
}

/// Builder for creating a `NomadServer`.
#[derive(Debug)]
pub struct NomadServerBuilder {
    config: ServerConfig,
}

impl NomadServerBuilder {
    /// Create a new server builder.
    pub fn new() -> Self {
        Self {
            config: ServerConfig::default(),
        }
    }

    /// Set the bind address.
    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.config.bind_addr = addr;
        self
    }

    /// Set the server's private key.
    pub fn private_key(mut self, key: [u8; 32]) -> Self {
        self.config.private_key = key;
        self
    }

    /// Set the maximum number of concurrent sessions.
    pub fn max_sessions(mut self, max: usize) -> Self {
        self.config.max_sessions = max;
        self
    }

    /// Set the session timeout.
    pub fn session_timeout(mut self, timeout: Duration) -> Self {
        self.config.session_timeout = timeout;
        self
    }

    /// Enable or disable compression.
    pub fn compression(mut self, enabled: bool) -> Self {
        self.config.enable_compression = enabled;
        self
    }

    /// Build the server configuration.
    pub fn build(self) -> ServerConfig {
        self.config
    }
}

impl Default for NomadServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Event from the server.
#[derive(Debug)]
pub enum ServerEvent<S: SyncState> {
    /// A new client has connected.
    ClientConnected {
        /// Session ID.
        session_id: ServerSessionId,
        /// Client's public key.
        client_public_key: [u8; 32],
    },

    /// Client state has been updated.
    StateUpdated {
        /// Session ID.
        session_id: ServerSessionId,
        /// The new state from the client.
        state: S,
    },

    /// A client has disconnected.
    ClientDisconnected {
        /// Session ID.
        session_id: ServerSessionId,
    },
}

/// Handle for sending state updates to a specific client.
pub struct SessionSender<S: SyncState> {
    session_id: ServerSessionId,
    tx: mpsc::Sender<(ServerSessionId, S)>,
}

impl<S: SyncState> SessionSender<S> {
    /// Send a state update to this session's client.
    pub async fn send(&self, state: S) -> Result<(), ServerError> {
        self.tx
            .send((self.session_id, state))
            .await
            .map_err(|_| ServerError::Shutdown)
    }

    /// Get the session ID.
    pub fn session_id(&self) -> ServerSessionId {
        self.session_id
    }
}

impl<S: SyncState> Clone for SessionSender<S> {
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id,
            tx: self.tx.clone(),
        }
    }
}

/// A NOMAD protocol server.
///
/// Generic over state type `S` which must implement `SyncState`.
///
/// # Example
///
/// ```ignore
/// use nomad_protocol::server::{NomadServer, NomadServerBuilder};
///
/// let config = NomadServerBuilder::new()
///     .bind_addr("0.0.0.0:19999".parse()?)
///     .private_key(server_privkey)
///     .build();
///
/// let (server, mut events) = NomadServer::<MyState>::bind(config, initial_state_factory).await?;
///
/// // Handle events
/// while let Some(event) = events.recv().await {
///     match event {
///         ServerEvent::ClientConnected { session_id, .. } => {
///             println!("Client connected: {:?}", session_id);
///         }
///         ServerEvent::StateUpdated { session_id, state } => {
///             // Process client state, send response
///             server.send_to(session_id, response_state).await?;
///         }
///         ServerEvent::ClientDisconnected { session_id } => {
///             println!("Client disconnected: {:?}", session_id);
///         }
///     }
/// }
/// ```
pub struct NomadServer<S: SyncState> {
    /// Server configuration.
    config: ServerConfig,

    /// Active sessions.
    sessions: Arc<RwLock<HashMap<ServerSessionId, ServerSession<S>>>>,

    /// Channel for sending state to clients.
    state_tx: mpsc::Sender<(ServerSessionId, S)>,

    /// Shutdown signal.
    shutdown_tx: Option<oneshot::Sender<()>>,

    /// The UDP socket (for reference).
    local_addr: SocketAddr,
}

impl<S: SyncState> NomadServer<S> {
    /// Bind to an address and start the server.
    ///
    /// The `state_factory` is called for each new session to create the initial state.
    pub async fn bind<F>(
        config: ServerConfig,
        _state_factory: F,
    ) -> Result<(Self, mpsc::Receiver<ServerEvent<S>>), ServerError>
    where
        F: Fn() -> S + Send + Sync + 'static,
    {
        // Bind UDP socket
        let socket = UdpSocket::bind(config.bind_addr)
            .await
            .map_err(|e| ServerError::BindFailed(e.to_string()))?;

        let local_addr = socket.local_addr()?;

        // Create channels
        let (state_tx, _state_rx) = mpsc::channel::<(ServerSessionId, S)>(256);
        let (event_tx, event_rx) = mpsc::channel::<ServerEvent<S>>(256);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();

        let sessions: Arc<RwLock<HashMap<ServerSessionId, ServerSession<S>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Spawn the main server loop
        let _sessions_clone = sessions.clone();
        let _config_clone = config.clone();
        let _event_tx = event_tx;

        tokio::spawn(async move {
            // TODO: Implement the actual server loop
            // This will be implemented when lower layers are ready

            // For now, this is a placeholder that keeps the server "alive"
            let mut buf = [0u8; 65535];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((_len, _addr)) => {
                        // TODO: Parse frame, handle handshake or data
                        // For now, we just ignore incoming packets
                    }
                    Err(_e) => {
                        // TODO: Handle error
                        break;
                    }
                }
            }
        });

        let server = Self {
            config,
            sessions,
            state_tx,
            shutdown_tx: Some(shutdown_tx),
            local_addr,
        };

        Ok((server, event_rx))
    }

    /// Get the local address the server is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the number of active sessions.
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Send state to a specific session.
    pub async fn send_to(&self, session_id: ServerSessionId, state: S) -> Result<(), ServerError> {
        self.state_tx
            .send((session_id, state))
            .await
            .map_err(|_| ServerError::Shutdown)
    }

    /// Broadcast state to all sessions.
    pub async fn broadcast(&self, state: S) -> Result<(), ServerError> {
        let sessions = self.sessions.read().await;
        for session_id in sessions.keys() {
            self.state_tx
                .send((*session_id, state.clone()))
                .await
                .map_err(|_| ServerError::Shutdown)?;
        }
        Ok(())
    }

    /// Get a sender handle for a specific session.
    pub fn session_sender(&self, session_id: ServerSessionId) -> SessionSender<S> {
        SessionSender {
            session_id,
            tx: self.state_tx.clone(),
        }
    }

    /// Disconnect a specific session.
    pub async fn disconnect(&self, session_id: ServerSessionId) -> Result<(), ServerError> {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(&session_id).is_some() {
            // TODO: Send close frame
            Ok(())
        } else {
            Err(ServerError::SessionError(format!(
                "session not found: {:?}",
                session_id
            )))
        }
    }

    /// Gracefully shut down the server.
    pub async fn shutdown(mut self) -> Result<(), ServerError> {
        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // TODO: Send close frames to all sessions

        // Clear sessions
        self.sessions.write().await.clear();

        Ok(())
    }

    /// Get the server configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }
}

impl<S: SyncState> Drop for NomadServer<S> {
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
