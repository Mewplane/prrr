// FRD: specs/frds/FRD-P006.md
// FRD: specs/frds/FRD-P009.md
// FRD: specs/frds/FRD-P009B.md
// FRD: specs/frds/FRD-20260223-harp-tunnel-orchestration.md
// FRD: specs/frds/FRD-20260223-transport-visibility-ui.md
// FRD: specs/frds/FRD-20260224-cdn-header-parsing.md

//! Shared application state for web API handlers.

use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::distribution::{ConfigTokenStore, ServerContext};
use crate::registry::ClientRegistry;
use crate::web::handlers::{ServerConfigResponse, TransportInfoResponse};
use crate::web::harp::{HarpSessionStore, HarpTunnelSpawner};

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
    /// Resolved transport configurations for API exposure.
    pub resolved_transports: Arc<Vec<TransportInfoResponse>>,
    /// HARP session store for active VPN tunnel sessions.
    pub harp_sessions: Arc<HarpSessionStore>,
    /// Server Noise X25519 private key bytes (for HARP handshake).
    pub server_noise_private_key: Arc<[u8]>,
    /// Server Noise X25519 public key (for HARP handshake).
    pub server_noise_public_key: [u8; 32],
    /// Server ML-KEM-768 decapsulation key bytes (for HARP handshake).
    pub server_kem_dk_bytes: Arc<[u8]>,
    /// Tunnel spawner for creating per-client VPN pipelines on HARP sessions.
    ///
    /// `None` when the web admin runs without VPN server (e.g., standalone mode).
    pub tunnel_spawner: Option<Arc<dyn HarpTunnelSpawner>>,
    /// Whether the cover landing page is served at `/` (default: `true`).
    pub cover_page_enabled: bool,
    /// Whether to trust proxy headers for real client IP extraction (default: `false`).
    /// Enable when behind a trusted CDN (e.g., Cloudflare).
    pub trust_proxy_headers: bool,
    /// Whether the server supports HTTP/2 streaming binding (default: `true`).
    pub h2_streaming_enabled: bool,
}
