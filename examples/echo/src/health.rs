//! Health check endpoint.
//!
//! Provides an HTTP health check endpoint on port 8080
//! as required by CONFORMANCE.md.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use tokio::sync::RwLock;

/// Health status.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthStatus {
    /// Whether the service is healthy.
    pub healthy: bool,
    /// Service mode (server or client).
    pub mode: String,
    /// Number of active sessions (server only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessions: Option<usize>,
    /// Whether connected to server (client only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
}

/// Shared state for health endpoint.
#[derive(Clone)]
pub struct HealthState {
    inner: Arc<RwLock<HealthStateInner>>,
}

struct HealthStateInner {
    healthy: bool,
    mode: String,
    sessions: Option<usize>,
    connected: Option<bool>,
}

impl HealthState {
    /// Create new health state for server mode.
    pub fn server() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HealthStateInner {
                healthy: true,
                mode: "server".to_string(),
                sessions: Some(0),
                connected: None,
            })),
        }
    }

    /// Create new health state for client mode.
    pub fn client() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HealthStateInner {
                healthy: true,
                mode: "client".to_string(),
                sessions: None,
                connected: Some(false),
            })),
        }
    }

    /// Update session count (server mode).
    pub async fn set_sessions(&self, count: usize) {
        let mut inner = self.inner.write().await;
        inner.sessions = Some(count);
    }

    /// Update connected status (client mode).
    pub async fn set_connected(&self, connected: bool) {
        let mut inner = self.inner.write().await;
        inner.connected = Some(connected);
    }

    /// Set healthy status.
    pub async fn set_healthy(&self, healthy: bool) {
        let mut inner = self.inner.write().await;
        inner.healthy = healthy;
    }

    /// Get current status.
    pub async fn status(&self) -> HealthStatus {
        let inner = self.inner.read().await;
        HealthStatus {
            healthy: inner.healthy,
            mode: inner.mode.clone(),
            sessions: inner.sessions,
            connected: inner.connected,
        }
    }
}

/// Health check handler.
async fn health_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let status = state.status().await;
    let code = if status.healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(status))
}

/// Readiness handler (same as health for now).
async fn ready_handler(State(state): State<HealthState>) -> impl IntoResponse {
    health_handler(State(state)).await
}

/// Liveness handler (always returns OK if server is running).
async fn live_handler() -> impl IntoResponse {
    StatusCode::OK
}

/// Start the health check server.
pub async fn start_health_server(
    bind_addr: SocketAddr,
    state: HealthState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/live", get(live_handler))
        .with_state(state);

    eprintln!("Health server listening on http://{}", bind_addr);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_state_server() {
        let state = HealthState::server();
        let status = state.status().await;
        assert!(status.healthy);
        assert_eq!(status.mode, "server");
        assert_eq!(status.sessions, Some(0));
    }

    #[tokio::test]
    async fn test_health_state_client() {
        let state = HealthState::client();
        let status = state.status().await;
        assert!(status.healthy);
        assert_eq!(status.mode, "client");
        assert_eq!(status.connected, Some(false));
    }

    #[tokio::test]
    async fn test_update_sessions() {
        let state = HealthState::server();
        state.set_sessions(5).await;
        let status = state.status().await;
        assert_eq!(status.sessions, Some(5));
    }
}
