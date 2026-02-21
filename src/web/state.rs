// FRD: specs/frds/FRD-P006.md
// FRD: specs/frds/FRD-P009.md
// FRD: specs/frds/FRD-P009B.md

//! Shared application state for web API handlers.

use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::distribution::{ConfigTokenStore, ServerContext};
use crate::registry::ClientRegistry;
use crate::web::handlers::ServerConfigResponse;

/// Shared state accessible to all web API handlers.
///
/// All fields are cheaply cloneable (`Arc`-wrapped) so axum can clone
/// this into each handler invocation.
#[derive(Clone)]
pub struct AppState {
    /// Client registry (shared with VPN server).
    pub registry: Arc<Mutex<ClientRegistry>>,
    /// Number of currently connected VPN clients (shared with VPN server).
    pub active_connections: Arc<AtomicU32>,
    /// Timestamp when the server process started (for uptime).
    pub start_time: std::time::Instant,
    /// HMAC key for JWT signing (HS256, 32 random bytes).
    pub jwt_secret: Arc<[u8]>,
    /// Session timeout in seconds (from config, default 3600).
    pub session_timeout: u64,
    /// Argon2id PHC hash string of admin password.
    pub admin_password_hash: Arc<str>,
    /// Coordinated shutdown token.
    pub cancel: CancellationToken,
    /// Server context for client config generation (P-009).
    pub server_context: Arc<ServerContext>,
    /// Token store for time-limited config download URLs (P-009).
    pub config_tokens: Arc<ConfigTokenStore>,
    /// Non-sensitive server configuration for read-only display (P-009B).
    pub server_config: Arc<ServerConfigResponse>,
}
