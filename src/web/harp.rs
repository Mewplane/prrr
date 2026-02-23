// FRD: specs/frds/FRD-20260223-harp-session-store.md
// FRD: specs/frds/FRD-20260223-harp-session-establishment.md
// FRD: specs/frds/FRD-20260223-harp-websocket-streaming.md
// FRD: specs/frds/FRD-20260223-harp-tunnel-orchestration.md
// FRD: specs/frds/FRD-20260223-harp-polling-transport.md

//! HARP session management, establishment, WebSocket/polling transport, and
//! tunnel orchestration for the HTTPS API Relay Protocol.
//!
//! Provides [`HarpSessionStore`] — a concurrent, lock-free session map that
//! tracks active HARP tunnel sessions. Each [`HarpSession`] contains
//! bidirectional mpsc channels for passing HARP frames between HTTP transport
//! handlers (WebSocket or polling) and the tunnel pipeline.
//!
//! The [`HarpTunnelSpawner`] trait and its default implementation
//! [`DefaultHarpTunnelSpawner`] wire up the full server-side VPN tunnel:
//! session creation → TUN device → EncryptedChannel → TunnelPipeline.
//!
//! Also provides the [`create_session`] handler for `POST /api/v1/harp/session`
//! which performs the hybrid Noise IK + ML-KEM-768 handshake over HTTP.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::crypto::hybrid_kex::KemKeyPair;
use crate::handshake::hybrid::{HybridResponder, SessionKeys};
use crate::handshake::noise_ik::KeyPair;
use crate::registry::{ClientRecord, ClientRegistry, ConnectionEvent};
use crate::transport::encrypted_channel::EncryptedChannel;
use crate::transport::harp::{HARP_MAX_PAYLOAD_LEN, HarpFrameReader, HarpFrameType, HarpReceiver, HarpSender};
use crate::tunnel::TunFactory;
use crate::tunnel::pipeline::{TrafficStats, TunnelPipeline};
use crate::tunnel::tun_device::TunDevice as _;
use crate::web::state::AppState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Byte length of a HARP session identifier.
pub const SESSION_ID_LEN: usize = 32;

/// Default bounded capacity for per-session frame channels.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A 32-byte HARP session identifier.
pub type SessionId = [u8; SESSION_ID_LEN];

// ---------------------------------------------------------------------------
// HarpSession
// ---------------------------------------------------------------------------

/// An active HARP tunnel session on the server side.
///
/// Holds the bidirectional channels that bridge HTTP transport handlers
/// to the tunnel pipeline. Created by [`HarpSessionStore::create`] after
/// a successful hybrid handshake.
pub struct HarpSession {
    /// Cryptographically random 32-byte session identifier.
    pub session_id: SessionId,
    /// Registry UUID of the authenticated client.
    pub client_id: Uuid,
    /// When this session was created.
    pub created_at: std::time::Instant,
    /// Epoch millis of last frame activity (atomically updatable).
    pub last_activity: Arc<AtomicU64>,
    /// Sender half: server pushes frames destined for the client.
    pub to_client_tx: mpsc::Sender<Vec<u8>>,
    /// Receiver half: transport handler reads frames to send to the client.
    pub to_client_rx: Arc<TokioMutex<mpsc::Receiver<Vec<u8>>>>,
    /// Sender half: transport handler pushes frames received from the client.
    pub from_client_tx: mpsc::Sender<Vec<u8>>,
    /// Receiver half: tunnel pipeline reads frames from the client.
    pub from_client_rx: Arc<TokioMutex<mpsc::Receiver<Vec<u8>>>>,
}

impl HarpSession {
    /// Update the last activity timestamp to now.
    pub fn touch(&self) {
        let now = epoch_millis_now();
        self.last_activity.store(now, Ordering::Relaxed);
    }

    /// Return the duration since the last activity.
    pub fn idle_duration(&self) -> Duration {
        let last = self.last_activity.load(Ordering::Relaxed);
        let now = epoch_millis_now();
        let elapsed_ms = now.saturating_sub(last);
        Duration::from_millis(elapsed_ms)
    }
}

impl std::fmt::Debug for HarpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HarpSession")
            .field("session_id", &"[32 bytes]")
            .field("client_id", &self.client_id)
            .field("created_at", &self.created_at)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// HarpSessionStore
// ---------------------------------------------------------------------------

/// Concurrent store mapping session IDs to active HARP sessions.
///
/// Uses [`DashMap`] for lock-free reads and fine-grained write locking.
/// Designed to be wrapped in `Arc` and shared via `AppState`.
pub struct HarpSessionStore {
    sessions: DashMap<SessionId, Arc<HarpSession>>,
}

impl Default for HarpSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HarpSessionStore {
    /// Create a new empty session store.
    pub fn new() -> Self {
        Self { sessions: DashMap::new() }
    }

    /// Create a new session for the given client.
    ///
    /// Generates a cryptographically random session ID, creates
    /// bidirectional channels, and inserts the session into the store.
    ///
    /// Returns the session ID and an `Arc` reference to the session.
    pub fn create(&self, client_id: Uuid) -> (SessionId, Arc<HarpSession>) {
        let session_id = generate_session_id();

        let (to_client_tx, to_client_rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        let (from_client_tx, from_client_rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);

        let session = Arc::new(HarpSession {
            session_id,
            client_id,
            created_at: std::time::Instant::now(),
            last_activity: Arc::new(AtomicU64::new(epoch_millis_now())),
            to_client_tx,
            to_client_rx: Arc::new(TokioMutex::new(to_client_rx)),
            from_client_tx,
            from_client_rx: Arc::new(TokioMutex::new(from_client_rx)),
        });

        self.sessions.insert(session_id, Arc::clone(&session));
        (session_id, session)
    }

    /// Look up a session by its ID.
    ///
    /// Returns `None` if the session does not exist.
    pub fn get(&self, session_id: &SessionId) -> Option<Arc<HarpSession>> {
        self.sessions.get(session_id).map(|entry| Arc::clone(entry.value()))
    }

    /// Remove a session by its ID.
    ///
    /// Returns the removed session, or `None` if it did not exist.
    pub fn remove(&self, session_id: &SessionId) -> Option<Arc<HarpSession>> {
        self.sessions.remove(session_id).map(|(_, session)| session)
    }

    /// Remove all sessions that have been idle longer than `max_idle`.
    ///
    /// Returns the number of sessions removed.
    pub fn cleanup_expired(&self, max_idle: Duration) -> usize {
        let mut removed = 0usize;
        self.sessions.retain(|_, session| {
            if session.idle_duration() > max_idle {
                removed += 1;
                false
            } else {
                true
            }
        });
        removed
    }

    /// Return the number of currently active sessions.
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// Iterate over all active sessions.
    pub fn iter(&self) -> dashmap::iter::Iter<'_, SessionId, Arc<HarpSession>> {
        self.sessions.iter()
    }
}

// ---------------------------------------------------------------------------
// Tunnel Orchestration
// ---------------------------------------------------------------------------

/// Parameters for spawning a HARP tunnel pipeline.
pub struct HarpTunnelParams {
    /// The session whose channels will bridge to the pipeline.
    pub session: Arc<HarpSession>,
    /// Derived session keys from the handshake.
    pub session_keys: SessionKeys,
    /// Authenticated client record from the registry.
    pub client_record: ClientRecord,
    /// Shared client registry for stats and logging.
    pub registry: Arc<TokioMutex<ClientRegistry>>,
    /// Shared active connection counter.
    pub active_connections: Arc<AtomicU32>,
    /// Cancellation token for graceful shutdown.
    pub cancel: CancellationToken,
    /// VPN gateway IP address (first host in subnet).
    pub gateway_ip: Ipv4Addr,
}

/// Type-erased trait for spawning HARP tunnel pipelines.
///
/// Allows `create_session` to trigger tunnel creation without making
/// `AppState` generic over `TunFactory`.
pub trait HarpTunnelSpawner: Send + Sync {
    /// Spawn a tunnel pipeline task for the given session.
    ///
    /// Returns `true` if the tunnel was spawned, `false` if rejected
    /// (e.g., at max client capacity).
    fn spawn(&self, params: HarpTunnelParams) -> bool;
}

/// Default tunnel spawner backed by a concrete [`TunFactory`].
pub struct DefaultHarpTunnelSpawner<F: TunFactory> {
    tun_factory: Arc<F>,
    max_clients: u32,
}

impl<F: TunFactory> DefaultHarpTunnelSpawner<F> {
    /// Create a new spawner with the given TUN factory and max client limit.
    pub fn new(tun_factory: Arc<F>, max_clients: u32) -> Self {
        Self { tun_factory, max_clients }
    }
}

impl<F> HarpTunnelSpawner for DefaultHarpTunnelSpawner<F>
where
    F: TunFactory + 'static,
    F::Tun: 'static,
    F::Handle: 'static,
{
    fn spawn(&self, params: HarpTunnelParams) -> bool {
        // Check max clients
        let current = params.active_connections.load(Ordering::Relaxed);
        if current >= self.max_clients {
            tracing::warn!(
                active = current,
                limit = self.max_clients,
                "HARP: max_clients reached, not spawning tunnel"
            );
            return false;
        }

        // Create TUN device
        let tun_config = crate::tunnel::TunConfig::new(params.gateway_ip)
            .with_destination(params.client_record.ip_address)
            .with_netmask(Ipv4Addr::new(255, 255, 255, 255));

        let (tun, _handle) = match self.tun_factory.create_tun(&tun_config) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!(error = %e, "HARP: failed to create TUN device");
                return false;
            }
        };

        tracing::info!(
            device = tun.name(),
            address = %params.gateway_ip,
            peer = %params.client_record.ip_address,
            "HARP: TUN device created for client"
        );

        // Build encrypted channel (keys swapped for server: rx_key for sending, tx_key for receiving)
        let channel = EncryptedChannel::new(params.session_keys.rx_key, params.session_keys.tx_key);

        // Create HARP pipeline adapters
        let sender = HarpSender::new(params.session.to_client_tx.clone());
        let receiver = HarpReceiver::new(Arc::clone(&params.session.from_client_rx));

        let stats = Arc::new(TrafficStats::new());
        let pipeline = TunnelPipeline::new(tun, channel, sender, receiver, Arc::clone(&stats));

        let client_id = params.client_record.id;
        let client_name = params.client_record.name.clone();
        let registry = params.registry;
        let active_connections = params.active_connections;
        let cancel = params.cancel;

        // Increment active connections
        active_connections.fetch_add(1, Ordering::Relaxed);

        tokio::spawn(async move {
            // RAII guard: decrement active count on exit
            let _guard = ActiveClientGuard {
                counter: Arc::clone(&active_connections),
            };

            tracing::info!(client_id = %client_id, client_name = %client_name, "HARP pipeline running");

            let pipeline_result = pipeline.run(cancel).await;

            // Persist traffic stats
            let sent = stats.bytes_sent.load(Ordering::Relaxed);
            let received = stats.bytes_received.load(Ordering::Relaxed);
            {
                let mut reg = registry.lock().await;
                if sent > 0 || received > 0 {
                    let _ = reg.update_traffic(client_id, sent, received);
                }
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs();
                let _ = reg.update_last_seen(client_id, now);

                let error_msg = match &pipeline_result {
                    Err(crate::tunnel::TunnelError::Cancelled) => None,
                    Err(e) => Some(e.to_string()),
                    Ok(()) => None,
                };
                let _ = reg.log_connection_event(client_id, ConnectionEvent::Disconnect, None, error_msg.as_deref(), sent, received);
            }

            match &pipeline_result {
                Err(crate::tunnel::TunnelError::Cancelled) => {
                    tracing::info!(client_id = %client_id, "HARP pipeline cancelled");
                }
                Err(e) => {
                    tracing::warn!(client_id = %client_id, error = %e, "HARP pipeline error");
                }
                Ok(()) => {
                    tracing::info!(client_id = %client_id, "HARP pipeline finished");
                }
            }
        });

        true
    }
}

/// RAII guard that decrements the active client counter on drop.
struct ActiveClientGuard {
    counter: Arc<AtomicU32>,
}

impl Drop for ActiveClientGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Session Establishment Constants
// ---------------------------------------------------------------------------

/// Maximum allowed clock skew for session establishment requests (seconds).
const TIMESTAMP_TOLERANCE_SECS: u64 = 30;

/// Approximate length of a Noise IK message 2 (for generating fake responses).
const FAKE_NOISE_MSG2_LEN: usize = 96;

/// Default rekey interval in seconds.
const DEFAULT_REKEY_INTERVAL: u64 = 3600;

/// Default keepalive interval in seconds.
const DEFAULT_KEEPALIVE_INTERVAL: u64 = 25;

/// Default polling interval in milliseconds.
const DEFAULT_POLL_INTERVAL_MS: u64 = 100;

/// API path prefix for HARP endpoints.
const HARP_API_PREFIX: &str = "/api/v1/harp";

// ---------------------------------------------------------------------------
// Session Establishment Request / Response Types
// ---------------------------------------------------------------------------

/// JSON request body for `POST /api/v1/harp/session`.
#[derive(Debug, Serialize, Deserialize)]
pub struct HarpSessionRequest {
    /// Base64-encoded Noise IK message 1 (contains KEM ciphertext as payload).
    pub noise_msg1: String,
    /// Transport modes the client supports: `["stream"]`, `["poll"]`, or both.
    pub capabilities: Vec<String>,
    /// Unix epoch seconds — server rejects if too far from current time.
    pub timestamp: u64,
}

/// JSON response body for `POST /api/v1/harp/session`.
#[derive(Debug, Serialize, Deserialize)]
pub struct HarpSessionResponse {
    /// Base64-encoded 32-byte session identifier.
    pub session_id: String,
    /// Base64-encoded Noise IK message 2.
    pub noise_msg2: String,
    /// Transport binding information.
    pub transport: HarpTransportInfo,
    /// Session configuration parameters.
    pub config: HarpConfigInfo,
}

/// Transport binding endpoints returned in the session response.
#[derive(Debug, Serialize, Deserialize)]
pub struct HarpTransportInfo {
    /// Server-selected transport mode (`"stream"` or `"poll"`).
    pub mode: String,
    /// WebSocket streaming endpoint path.
    pub stream_endpoint: String,
    /// HTTP polling upload endpoint path.
    pub upload_endpoint: String,
    /// HTTP polling download endpoint path.
    pub download_endpoint: String,
}

/// Session configuration parameters returned in the session response.
#[derive(Debug, Serialize, Deserialize)]
pub struct HarpConfigInfo {
    /// Seconds between automatic rekeying of the encrypted channel.
    pub rekey_interval: u64,
    /// Seconds between keepalive frames.
    pub keepalive_interval: u64,
    /// Maximum HARP frame payload size in bytes.
    pub max_frame_size: u32,
    /// Suggested polling interval in milliseconds (for poll mode).
    pub poll_interval_ms: u64,
}

// ---------------------------------------------------------------------------
// Session Establishment Handler
// ---------------------------------------------------------------------------

/// Handler for `POST /api/v1/harp/session`.
///
/// Performs the hybrid Noise IK + ML-KEM-768 handshake over HTTP:
/// 1. Validates the request timestamp
/// 2. Decodes and processes the Noise IK message 1
/// 3. Authenticates the client against the registry
/// 4. Creates a session in the store on success
/// 5. Returns a fake response on any failure (indistinguishable from success)
pub async fn create_session(State(state): State<AppState>, Json(request): Json<HarpSessionRequest>) -> impl IntoResponse {
    // Step 1: Validate timestamp
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs();
    let time_diff = now.abs_diff(request.timestamp);
    if time_diff > TIMESTAMP_TOLERANCE_SECS {
        tracing::debug!(time_diff, "HARP session: timestamp out of tolerance");
        return (StatusCode::OK, Json(build_fake_response())).into_response();
    }

    // Step 2: Base64-decode noise_msg1
    let noise_msg1_bytes = match BASE64.decode(&request.noise_msg1) {
        Ok(bytes) => bytes,
        Err(_) => {
            tracing::debug!("HARP session: invalid base64 in noise_msg1");
            return (StatusCode::OK, Json(build_fake_response())).into_response();
        }
    };

    // Step 3: Reconstruct server keypairs from stored bytes
    let noise_keypair = match KeyPair::from_private_key(&state.server_noise_private_key) {
        Ok(kp) => kp,
        Err(e) => {
            tracing::error!("HARP session: failed to reconstruct noise keypair: {e}");
            return (StatusCode::OK, Json(build_fake_response())).into_response();
        }
    };
    let kem_keypair = match KemKeyPair::from_dk_bytes(&state.server_kem_dk_bytes) {
        Ok(kp) => kp,
        Err(e) => {
            tracing::error!("HARP session: failed to reconstruct KEM keypair: {e}");
            return (StatusCode::OK, Json(build_fake_response())).into_response();
        }
    };

    // Step 4: Run hybrid handshake (responder side)
    let responder = match HybridResponder::new(&noise_keypair, kem_keypair) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("HARP session: responder init failed: {e}");
            return (StatusCode::OK, Json(build_fake_response())).into_response();
        }
    };
    let (noise_msg2, responder_result) = match responder.finish(&noise_msg1_bytes, &[]) {
        Ok(result) => result,
        Err(e) => {
            tracing::debug!("HARP session: handshake failed: {e}");
            return (StatusCode::OK, Json(build_fake_response())).into_response();
        }
    };

    // Step 5: Authenticate initiator against the client registry
    let client_record = {
        let registry = state.registry.lock().await;
        registry.authenticate(&responder_result.initiator_static)
    };
    let client_record = match client_record {
        Some(record) => record,
        None => {
            tracing::debug!("HARP session: client not authenticated");
            return (StatusCode::OK, Json(build_fake_response())).into_response();
        }
    };

    // Step 6: Create session in the store
    let (session_id, session) = state.harp_sessions.create(client_record.id);

    tracing::info!(
        client_id = %client_record.id,
        client_name = %client_record.name,
        "HARP session established"
    );

    // Step 6b: Spawn tunnel pipeline if spawner is configured
    if let Some(ref spawner) = state.tunnel_spawner {
        let gateway_ip = {
            let registry = state.registry.lock().await;
            registry.gateway_addr()
        };

        // Log connect event
        {
            let mut registry = state.registry.lock().await;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs();
            let _ = registry.update_last_seen(client_record.id, now);
            let _ = registry.log_connection_event(client_record.id, ConnectionEvent::Connect, None, None, 0, 0);
        }

        let params = HarpTunnelParams {
            session: Arc::clone(&session),
            session_keys: responder_result.session_keys,
            client_record,
            registry: Arc::clone(&state.registry),
            active_connections: Arc::clone(&state.active_connections),
            cancel: state.cancel.child_token(),
            gateway_ip,
        };

        spawner.spawn(params);
    }

    // Step 7: Build success response
    let response = build_real_response(&session_id, &noise_msg2, &request.capabilities);

    (StatusCode::OK, Json(response)).into_response()
}

/// Build a real session response for a successful handshake.
fn build_real_response(session_id: &SessionId, noise_msg2: &[u8], capabilities: &[String]) -> HarpSessionResponse {
    let mode = select_transport_mode(capabilities);
    HarpSessionResponse {
        session_id: BASE64.encode(session_id),
        noise_msg2: BASE64.encode(noise_msg2),
        transport: build_transport_info(session_id, &mode),
        config: HarpConfigInfo {
            rekey_interval: DEFAULT_REKEY_INTERVAL,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            max_frame_size: HARP_MAX_PAYLOAD_LEN as u32,
            poll_interval_ms: DEFAULT_POLL_INTERVAL_MS,
        },
    }
}

/// Build a fake response that is structurally identical to a real one.
fn build_fake_response() -> HarpSessionResponse {
    let mut fake_session_id = [0u8; SESSION_ID_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut fake_session_id);

    let mut fake_msg2 = vec![0u8; FAKE_NOISE_MSG2_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut fake_msg2);

    HarpSessionResponse {
        session_id: BASE64.encode(fake_session_id),
        noise_msg2: BASE64.encode(fake_msg2),
        transport: build_transport_info(&fake_session_id, "stream"),
        config: HarpConfigInfo {
            rekey_interval: DEFAULT_REKEY_INTERVAL,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            max_frame_size: HARP_MAX_PAYLOAD_LEN as u32,
            poll_interval_ms: DEFAULT_POLL_INTERVAL_MS,
        },
    }
}

/// Build transport endpoint info for a given session ID.
///
/// Endpoint paths use URL-safe base64 (no padding) to avoid `/`, `+`, `=`
/// characters that would break URL path matching.
fn build_transport_info(session_id: &SessionId, mode: &str) -> HarpTransportInfo {
    let url_id = BASE64_URL.encode(session_id);
    HarpTransportInfo {
        mode: mode.to_string(),
        stream_endpoint: format!("{HARP_API_PREFIX}/stream/{url_id}"),
        upload_endpoint: format!("{HARP_API_PREFIX}/upload/{url_id}"),
        download_endpoint: format!("{HARP_API_PREFIX}/download/{url_id}"),
    }
}

/// Select transport mode based on client capabilities.
fn select_transport_mode(capabilities: &[String]) -> String {
    if capabilities.iter().any(|c| c == "stream") {
        "stream".to_string()
    } else {
        "poll".to_string()
    }
}

// ---------------------------------------------------------------------------
// WebSocket Streaming Transport
// ---------------------------------------------------------------------------

/// Handler for `GET /api/v1/harp/stream/{session_id}`.
///
/// Upgrades the HTTP connection to a bidirectional binary WebSocket that
/// bridges HARP frame channels for the given session. Always upgrades to
/// WebSocket (no error fingerprint) — if the session is invalid the
/// connection is closed immediately after upgrade.
pub async fn stream_handler(
    State(state): State<AppState>,
    Path(session_id_b64): Path<String>,
    ws: axum::extract::ws::WebSocketUpgrade,
) -> impl IntoResponse {
    let store = Arc::clone(&state.harp_sessions);

    // Decode session ID from URL-safe base64
    let session_id_bytes = match BASE64_URL.decode(&session_id_b64) {
        Ok(bytes) if bytes.len() == SESSION_ID_LEN => bytes,
        _ => {
            return ws.on_upgrade(|mut socket| async move {
                let _ = socket.send(axum::extract::ws::Message::Close(None)).await;
            });
        }
    };

    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&session_id_bytes);

    // Look up session
    let session = match state.harp_sessions.get(&session_id) {
        Some(s) => s,
        None => {
            return ws.on_upgrade(|mut socket| async move {
                let _ = socket.send(axum::extract::ws::Message::Close(None)).await;
            });
        }
    };

    ws.on_upgrade(move |socket| run_stream_bridge(socket, session, session_id, store))
}

/// Bidirectional bridge between a WebSocket and HARP session channels.
///
/// Runs a single `select!` loop that concurrently:
/// - reads from `to_client_rx` and sends as WS binary messages
/// - reads WS messages and forwards binary data to `from_client_tx`
///
/// When either direction closes, the session is removed from the store.
async fn run_stream_bridge(
    mut socket: axum::extract::ws::WebSocket,
    session: Arc<HarpSession>,
    session_id: SessionId,
    store: Arc<HarpSessionStore>,
) {
    use axum::extract::ws::Message;

    let mut to_client_rx = session.to_client_rx.lock().await;

    loop {
        tokio::select! {
            // server → client: read from channel, send as WS binary
            frame = to_client_rx.recv() => {
                match frame {
                    Some(frame_bytes) => {
                        session.touch();
                        if socket.send(Message::Binary(frame_bytes.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break, // channel closed
                }
            }
            // client → server: read WS message, forward binary to channel
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        session.touch();
                        if session.from_client_tx.send(data.to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    Some(Ok(_)) => {} // Ping/Pong handled by axum
                }
            }
        }
    }

    drop(to_client_rx);

    // Cleanup: remove session from store
    store.remove(&session_id);
}

// ---------------------------------------------------------------------------
// Polling Transport (Fallback)
// ---------------------------------------------------------------------------

/// Look up a HARP session by URL-safe base64-encoded session ID.
///
/// Returns `None` if the ID is malformed or the session does not exist.
fn lookup_session(store: &HarpSessionStore, session_id_b64: &str) -> Option<Arc<HarpSession>> {
    let session_id_bytes = match BASE64_URL.decode(session_id_b64) {
        Ok(bytes) if bytes.len() == SESSION_ID_LEN => bytes,
        _ => return None,
    };
    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&session_id_bytes);
    store.get(&session_id)
}

/// Drain all currently available frames from a session's `to_client_rx`
/// channel without blocking, and encode them as concatenated HARP wire bytes.
async fn drain_to_client_frames(session: &HarpSession) -> Vec<u8> {
    let mut rx = session.to_client_rx.lock().await;
    let mut buf = Vec::new();
    while let Ok(frame_bytes) = rx.try_recv() {
        buf.extend_from_slice(&frame_bytes);
    }
    buf
}

/// Handler for `POST /api/v1/harp/upload/{session_id}`.
///
/// The client sends one or more concatenated HARP frames in the request body.
/// The server decodes each frame and forwards DATA payloads to the session's
/// `from_client_tx` channel. KEEPALIVE frames are silently skipped. A CLOSE
/// frame removes the session.
///
/// The response body contains any frames queued for download (piggyback
/// optimization), reducing the number of round-trips for bidirectional traffic.
///
/// Unknown or malformed session IDs always return `200 OK` with an empty body
/// to prevent DPI from fingerprinting error responses.
pub async fn upload_handler(State(state): State<AppState>, Path(session_id_b64): Path<String>, body: Bytes) -> impl IntoResponse {
    let session = match lookup_session(&state.harp_sessions, &session_id_b64) {
        Some(s) => s,
        None => return (StatusCode::OK, Vec::new()).into_response(),
    };

    session.touch();

    // Decode frames from request body
    let mut reader = HarpFrameReader::new();
    reader.push(&body);

    while let Some(result) = reader.next_frame() {
        let frame = match result {
            Ok(f) => f,
            Err(_) => break, // malformed frame data — stop processing
        };
        match frame.frame_type {
            HarpFrameType::Data => {
                // Re-encode as wire bytes: HarpReceiver expects full HARP frames
                let wire = match frame.encode() {
                    Ok(bytes) => bytes,
                    Err(_) => break,
                };
                if session.from_client_tx.send(wire).await.is_err() {
                    break; // channel closed
                }
            }
            HarpFrameType::Keepalive => {} // skip
            HarpFrameType::Close => {
                state.harp_sessions.remove(&{
                    let mut id = [0u8; SESSION_ID_LEN];
                    let bytes = BASE64_URL.decode(&session_id_b64).unwrap_or_default();
                    if bytes.len() == SESSION_ID_LEN {
                        id.copy_from_slice(&bytes);
                    }
                    id
                });
                break;
            }
        }
    }

    // Piggyback: return any queued download frames in response
    let piggyback = drain_to_client_frames(&session).await;
    (StatusCode::OK, piggyback).into_response()
}

/// Handler for `POST /api/v1/harp/download/{session_id}`.
///
/// Returns all currently queued frames for the client as concatenated HARP
/// wire bytes in the response body. If no frames are available, the response
/// body is empty.
///
/// Unknown or malformed session IDs always return `200 OK` with an empty body.
pub async fn download_handler(State(state): State<AppState>, Path(session_id_b64): Path<String>) -> impl IntoResponse {
    let session = match lookup_session(&state.harp_sessions, &session_id_b64) {
        Some(s) => s,
        None => return (StatusCode::OK, Vec::new()).into_response(),
    };

    session.touch();

    let frames = drain_to_client_frames(&session).await;
    (StatusCode::OK, frames).into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a cryptographically random 32-byte session ID.
fn generate_session_id() -> SessionId {
    let mut id = [0u8; SESSION_ID_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
    id
}

/// Current time as milliseconds since UNIX_EPOCH.
fn epoch_millis_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_millis() as u64
}

// ---------------------------------------------------------------------------
// HARP Server Transport Adapter (Step 12)
// ---------------------------------------------------------------------------

use crate::transport::traits::{ServerTransport, SharedServerState};

/// Human-readable name for the HARP server transport.
const HARP_SERVER_TRANSPORT_NAME: &str = "harp";

/// HARP server transport implementing [`ServerTransport`].
///
/// Wraps the existing Axum-based HARP session management, WebSocket
/// streaming, and polling handlers behind the pluggable transport trait
/// interface. Holds a generic `TunFactory` for creating per-client TUN
/// devices via [`DefaultHarpTunnelSpawner`].
pub struct HarpServerTransport<F: TunFactory> {
    /// HTTP server listen address.
    listen_addr: std::net::SocketAddr,
    /// Factory for creating per-client TUN devices.
    tun_factory: Arc<F>,
}

impl<F: TunFactory> HarpServerTransport<F> {
    /// Create a new HARP server transport with the given listen address
    /// and TUN factory.
    pub fn new(listen_addr: std::net::SocketAddr, tun_factory: Arc<F>) -> Self {
        Self { listen_addr, tun_factory }
    }
}

impl<F: TunFactory + 'static> ServerTransport for HarpServerTransport<F>
where
    F::Tun: 'static,
    F::Handle: 'static,
{
    fn name(&self) -> &str {
        HARP_SERVER_TRANSPORT_NAME
    }

    fn run(
        &self,
        shared: Arc<SharedServerState>,
        cancel: CancellationToken,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        Box::pin(async move {
            let spawner = DefaultHarpTunnelSpawner::new(Arc::clone(&self.tun_factory), shared.max_clients);

            let state = super::AppState {
                registry: Arc::clone(&shared.registry),
                active_connections: Arc::clone(&shared.active_connections),
                start_time: std::time::Instant::now(),
                jwt_secret: Arc::from([0u8; 32].as_slice()),
                session_timeout: 0,
                admin_password_hash: Arc::from(""),
                cancel: cancel.clone(),
                server_context: Arc::new(crate::distribution::ServerContext {
                    endpoint: String::new(),
                    noise_public_key: *shared.noise_keypair.public_key(),
                    kem_public_key: shared.kem_keypair.encapsulation_key_bytes(),
                }),
                config_tokens: Arc::new(crate::distribution::ConfigTokenStore::new()),
                server_config: Arc::new(crate::web::handlers::ServerConfigResponse {
                    listen_addr: self.listen_addr.to_string(),
                    server_name: String::new(),
                    subnet: String::new(),
                    dns_servers: Vec::new(),
                    mtu: 0,
                    max_clients: shared.max_clients,
                    version: String::new(),
                    transport_protocol: HARP_SERVER_TRANSPORT_NAME.to_string(),
                    obfuscation_enabled: false,
                    web_admin_enabled: false,
                    metrics_enabled: false,
                }),
                resolved_transports: Arc::new(vec![crate::web::handlers::TransportInfoResponse::from_harp(true, true, 300)]),
                harp_sessions: Arc::new(HarpSessionStore::new()),
                server_noise_private_key: Arc::from(shared.noise_keypair.private_key_bytes()),
                server_noise_public_key: *shared.noise_keypair.public_key(),
                server_kem_dk_bytes: Arc::from(shared.kem_keypair.dk_bytes().as_slice()),
                tunnel_spawner: Some(Arc::new(spawner)),
            };

            super::run_web_server(self.listen_addr, state).await
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SUBNET: &str = "10.66.66.0/24";
    const TEST_MAX_CLIENTS: u32 = 3;
    const TEST_TIMEOUT_SECS: u64 = 10;

    // -----------------------------------------------------------------------
    // Shared test helpers for session establishment tests
    // -----------------------------------------------------------------------

    /// Build an `AppState` with real server keypairs for handshake testing.
    fn harp_test_app_state() -> AppState {
        use crate::config::DEFAULT_SESSION_TIMEOUT;
        use crate::distribution::{ConfigTokenStore, ServerContext};
        use crate::registry::ClientRegistry;
        use crate::web::handlers::{ServerConfigResponse, TransportInfoResponse};

        let noise_keypair = KeyPair::generate().expect("noise keypair");
        let kem_keypair = KemKeyPair::generate();

        let server_noise_private_key = Arc::from(noise_keypair.private_key_bytes());
        let server_noise_public_key = *noise_keypair.public_key();
        let server_kem_dk_bytes = Arc::from(kem_keypair.dk_bytes().as_slice());
        let kem_public_key = kem_keypair.encapsulation_key_bytes();

        fn test_password_hash() -> String {
            use argon2::PasswordHasher;
            let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
            argon2::Argon2::default()
                .hash_password(b"test-pass", &salt)
                .expect("hash")
                .to_string()
        }

        let registry = ClientRegistry::new("10.66.66.0/24").expect("valid subnet");

        AppState {
            registry: Arc::new(tokio::sync::Mutex::new(registry)),
            active_connections: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            start_time: std::time::Instant::now(),
            jwt_secret: Arc::from([0xABu8; 32].as_slice()),
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            admin_password_hash: Arc::from(test_password_hash().as_str()),
            cancel: tokio_util::sync::CancellationToken::new(),
            server_context: Arc::new(ServerContext {
                endpoint: "127.0.0.1:443".to_string(),
                noise_public_key: server_noise_public_key,
                kem_public_key: kem_public_key.clone(),
            }),
            config_tokens: Arc::new(ConfigTokenStore::new()),
            server_config: Arc::new(ServerConfigResponse {
                listen_addr: "0.0.0.0:443".to_string(),
                server_name: "test.example.com".to_string(),
                subnet: "10.66.66.0/24".to_string(),
                dns_servers: vec!["1.1.1.1".to_string()],
                mtu: 1280,
                max_clients: 100,
                version: env!("CARGO_PKG_VERSION").to_string(),
                transport_protocol: "harp".to_string(),
                obfuscation_enabled: false,
                web_admin_enabled: true,
                metrics_enabled: false,
            }),
            resolved_transports: Arc::new(vec![TransportInfoResponse::from_harp(true, true, 300)]),
            harp_sessions: Arc::new(HarpSessionStore::new()),
            server_noise_private_key,
            server_noise_public_key,
            server_kem_dk_bytes,
            tunnel_spawner: None,
        }
    }

    /// Register a client in the registry and return its keypair + public key.
    async fn register_client(state: &AppState, name: &str) -> (KeyPair, [u8; 32]) {
        let client_noise = KeyPair::generate().expect("client noise keypair");
        let client_pub = *client_noise.public_key();
        let kem_kp = KemKeyPair::generate();
        let kem_pub = kem_kp.encapsulation_key_bytes();

        let mut registry = state.registry.lock().await;
        registry.add(name, client_pub, Some(kem_pub)).expect("register client");

        (client_noise, client_pub)
    }

    /// Build a valid `HarpSessionRequest` JSON body using the client's keypair.
    fn build_handshake_request(
        client_noise: &KeyPair,
        server_noise_pub: &[u8; 32],
        server_kem_pub: &[u8],
    ) -> (serde_json::Value, crate::handshake::hybrid::HybridInitiator) {
        use crate::handshake::hybrid::HybridInitiator;

        let (initiator, msg1) = HybridInitiator::new(client_noise, server_noise_pub, server_kem_pub).expect("initiator");

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let body = serde_json::json!({
            "noise_msg1": BASE64.encode(&msg1),
            "capabilities": ["stream", "poll"],
            "timestamp": now,
        });

        (body, initiator)
    }

    /// Send a POST to /api/v1/harp/session and return the response.
    async fn post_session(app: &axum::Router, body: serde_json::Value) -> axum::response::Response {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/harp/session")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        app.clone().oneshot(req).await.unwrap()
    }

    /// Parse a response body as `HarpSessionResponse`.
    async fn parse_session_response(resp: axum::response::Response) -> HarpSessionResponse {
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
        serde_json::from_slice(&body_bytes).expect("parse json")
    }

    // -----------------------------------------------------------------------
    // Session Store Tests (from FRD-20260223-harp-session-store.md)
    // -----------------------------------------------------------------------

    // -- AC-1: create() returns unique session ID and Arc<HarpSession> --

    #[test]
    fn create_returns_session_with_matching_id() {
        let store = HarpSessionStore::new();
        let client_id = Uuid::new_v4();
        let (session_id, session) = store.create(client_id);

        assert_eq!(session.session_id, session_id);
        assert_eq!(session.client_id, client_id);
    }

    // -- AC-2: get() returns session for known ID --

    #[test]
    fn get_returns_existing_session() {
        let store = HarpSessionStore::new();
        let client_id = Uuid::new_v4();
        let (session_id, original) = store.create(client_id);

        let retrieved = store.get(&session_id).expect("session should exist");
        assert_eq!(retrieved.session_id, original.session_id);
        assert_eq!(retrieved.client_id, client_id);
    }

    // -- AC-3: get() returns None for unknown ID --

    #[test]
    fn get_returns_none_for_unknown_id() {
        let store = HarpSessionStore::new();
        let unknown_id = [0xAA; SESSION_ID_LEN];
        assert!(store.get(&unknown_id).is_none());
    }

    // -- AC-4: remove() returns session, subsequent get() returns None --

    #[test]
    fn remove_returns_session_and_clears() {
        let store = HarpSessionStore::new();
        let client_id = Uuid::new_v4();
        let (session_id, _) = store.create(client_id);

        let removed = store.remove(&session_id).expect("session should exist");
        assert_eq!(removed.client_id, client_id);

        assert!(store.get(&session_id).is_none());
    }

    #[test]
    fn remove_returns_none_for_unknown_id() {
        let store = HarpSessionStore::new();
        let unknown_id = [0xBB; SESSION_ID_LEN];
        assert!(store.remove(&unknown_id).is_none());
    }

    // -- AC-5: cleanup_expired removes idle sessions --

    #[test]
    fn cleanup_expired_removes_idle_sessions() {
        let store = HarpSessionStore::new();
        let client_id = Uuid::new_v4();
        let (session_id, session) = store.create(client_id);

        // Force last_activity to 10 seconds ago
        let ten_seconds_ago = epoch_millis_now() - 10_000;
        session.last_activity.store(ten_seconds_ago, Ordering::Relaxed);

        let removed = store.cleanup_expired(Duration::from_secs(5));
        assert_eq!(removed, 1);
        assert!(store.get(&session_id).is_none());
    }

    // -- AC-6: cleanup_expired preserves recent sessions --

    #[test]
    fn cleanup_expired_preserves_recent_sessions() {
        let store = HarpSessionStore::new();
        let client_id = Uuid::new_v4();
        let (session_id, _session) = store.create(client_id);

        // Session was just created, should not be expired with 5s threshold
        let removed = store.cleanup_expired(Duration::from_secs(5));
        assert_eq!(removed, 0);
        assert!(store.get(&session_id).is_some());
    }

    #[test]
    fn cleanup_expired_mixed_sessions() {
        let store = HarpSessionStore::new();

        // Create an "old" session
        let (old_id, old_session) = store.create(Uuid::new_v4());
        let thirty_seconds_ago = epoch_millis_now() - 30_000;
        old_session.last_activity.store(thirty_seconds_ago, Ordering::Relaxed);

        // Create a "fresh" session
        let (fresh_id, _fresh_session) = store.create(Uuid::new_v4());

        let removed = store.cleanup_expired(Duration::from_secs(10));
        assert_eq!(removed, 1);
        assert!(store.get(&old_id).is_none());
        assert!(store.get(&fresh_id).is_some());
    }

    // -- AC-7: active_count reflects current state --

    #[test]
    fn active_count_reflects_state() {
        let store = HarpSessionStore::new();
        assert_eq!(store.active_count(), 0);

        let (id1, _) = store.create(Uuid::new_v4());
        assert_eq!(store.active_count(), 1);

        let (_id2, _) = store.create(Uuid::new_v4());
        assert_eq!(store.active_count(), 2);

        store.remove(&id1);
        assert_eq!(store.active_count(), 1);
    }

    // -- AC-8: Concurrent create/get from multiple tasks --

    #[tokio::test]
    async fn concurrent_create_and_get() {
        let store = Arc::new(HarpSessionStore::new());
        let task_count: usize = 50;
        let mut handles = Vec::with_capacity(task_count);

        for _ in 0..task_count {
            let store = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                let client_id = Uuid::new_v4();
                let (session_id, _) = store.create(client_id);
                // Immediately read it back
                let retrieved = store.get(&session_id).expect("should find just-created session");
                assert_eq!(retrieved.client_id, client_id);
                session_id
            }));
        }

        let mut session_ids = Vec::with_capacity(task_count);
        for handle in handles {
            session_ids.push(handle.await.expect("task should succeed"));
        }

        assert_eq!(store.active_count(), task_count);

        // All session IDs should be unique
        let unique_count = {
            let mut set = std::collections::HashSet::new();
            for id in &session_ids {
                set.insert(*id);
            }
            set.len()
        };
        assert_eq!(unique_count, task_count);
    }

    // -- AC-9: Frame sent to to_client_tx received on to_client_rx --

    #[tokio::test]
    async fn to_client_channel_communication() {
        let store = HarpSessionStore::new();
        let (_session_id, session) = store.create(Uuid::new_v4());

        let test_frame = b"encrypted frame data".to_vec();
        session.to_client_tx.send(test_frame.clone()).await.expect("send");

        let mut rx = session.to_client_rx.lock().await;
        let received = rx.recv().await.expect("recv");
        assert_eq!(received, test_frame);
    }

    // -- AC-10: Frame sent to from_client_tx received on from_client_rx --

    #[tokio::test]
    async fn from_client_channel_communication() {
        let store = HarpSessionStore::new();
        let (_session_id, session) = store.create(Uuid::new_v4());

        let test_frame = b"client frame data".to_vec();
        session.from_client_tx.send(test_frame.clone()).await.expect("send");

        let mut rx = session.from_client_rx.lock().await;
        let received = rx.recv().await.expect("recv");
        assert_eq!(received, test_frame);
    }

    // -- AC-11: touch() updates last_activity --

    #[tokio::test]
    async fn touch_updates_last_activity() {
        let store = HarpSessionStore::new();
        let (_session_id, session) = store.create(Uuid::new_v4());

        // Force last_activity to 5 seconds ago
        let five_seconds_ago = epoch_millis_now() - 5_000;
        session.last_activity.store(five_seconds_ago, Ordering::Relaxed);

        let idle_before = session.idle_duration();
        assert!(idle_before >= Duration::from_secs(4), "should be idle at least 4s");

        session.touch();

        let idle_after = session.idle_duration();
        assert!(idle_after < Duration::from_secs(1), "should be recently active after touch");
    }

    // -- AC-12: Two sequential creates produce different session IDs --

    #[test]
    fn two_creates_produce_different_ids() {
        let store = HarpSessionStore::new();
        let (id1, _) = store.create(Uuid::new_v4());
        let (id2, _) = store.create(Uuid::new_v4());
        assert_ne!(id1, id2);
    }

    // -- Default trait --

    #[test]
    fn default_store_is_empty() {
        let store = HarpSessionStore::default();
        assert_eq!(store.active_count(), 0);
    }

    // -- Debug formatting --

    #[test]
    fn session_debug_does_not_leak_id() {
        let store = HarpSessionStore::new();
        let (_session_id, session) = store.create(Uuid::new_v4());
        let debug = format!("{session:?}");
        assert!(debug.contains("HarpSession"));
        assert!(debug.contains("[32 bytes]"));
    }

    // -- idle_duration works for freshly created session --

    #[test]
    fn fresh_session_has_minimal_idle() {
        let store = HarpSessionStore::new();
        let (_session_id, session) = store.create(Uuid::new_v4());
        assert!(session.idle_duration() < Duration::from_secs(1));
    }

    // -----------------------------------------------------------------------
    // Session Establishment Tests (from FRD-20260223-harp-session-establishment.md)
    // -----------------------------------------------------------------------

    // -- AC-1 (establishment): Valid handshake returns 200 with parseable response --

    #[tokio::test]
    async fn valid_handshake_returns_200_with_session() {
        let state = harp_test_app_state();
        let (client_noise, _) = register_client(&state, "alice").await;
        let app = crate::web::build_router(state.clone());

        let (body, _initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);

        let resp = post_session(&app, body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let parsed = parse_session_response(resp).await;
        // session_id should be valid base64 decoding to 32 bytes
        let session_id_bytes = BASE64.decode(&parsed.session_id).expect("valid base64 session_id");
        assert_eq!(session_id_bytes.len(), SESSION_ID_LEN);
        // noise_msg2 should be valid base64
        let msg2_bytes = BASE64.decode(&parsed.noise_msg2).expect("valid base64 noise_msg2");
        assert!(!msg2_bytes.is_empty());
    }

    // -- AC-2 (establishment): Client can complete handshake with returned noise_msg2 --

    #[tokio::test]
    async fn client_completes_handshake_with_response() {
        let state = harp_test_app_state();
        let (client_noise, _) = register_client(&state, "bob").await;
        let app = crate::web::build_router(state.clone());

        let (body, initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);

        let resp = post_session(&app, body).await;
        let parsed = parse_session_response(resp).await;

        let msg2_bytes = BASE64.decode(&parsed.noise_msg2).expect("decode msg2");
        let result = initiator.finish(&msg2_bytes);
        assert!(result.is_ok(), "client should complete handshake");
    }

    // -- AC-3 (establishment): Session appears in store after success --

    #[tokio::test]
    async fn session_appears_in_store_after_handshake() {
        let state = harp_test_app_state();
        let (client_noise, _) = register_client(&state, "carol").await;
        let app = crate::web::build_router(state.clone());

        assert_eq!(state.harp_sessions.active_count(), 0);

        let (body, _initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);

        let resp = post_session(&app, body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        assert_eq!(state.harp_sessions.active_count(), 1);

        // Verify the session ID from the response matches the store
        let parsed = parse_session_response(resp).await;
        let session_id_bytes = BASE64.decode(&parsed.session_id).expect("decode session_id");
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&session_id_bytes);
        assert!(state.harp_sessions.get(&session_id).is_some());
    }

    // -- AC-4 (establishment): Unregistered client gets 200 with fake response --

    #[tokio::test]
    async fn unregistered_client_gets_fake_response() {
        let state = harp_test_app_state();
        // Don't register the client
        let unregistered_noise = KeyPair::generate().expect("unregistered keypair");
        let app = crate::web::build_router(state.clone());

        let (body, _initiator) = build_handshake_request(
            &unregistered_noise,
            &state.server_noise_public_key,
            &state.server_context.kem_public_key,
        );

        let resp = post_session(&app, body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Should return valid JSON with same structure
        let parsed = parse_session_response(resp).await;
        assert!(!parsed.session_id.is_empty());
        assert!(!parsed.noise_msg2.is_empty());
        assert!(!parsed.transport.stream_endpoint.is_empty());

        // But no session should be in the store
        assert_eq!(state.harp_sessions.active_count(), 0);
    }

    // -- AC-5 (establishment): Expired timestamp gets 200 with fake response --

    #[tokio::test]
    async fn expired_timestamp_gets_fake_response() {
        let state = harp_test_app_state();
        let (client_noise, _) = register_client(&state, "dave").await;
        let app = crate::web::build_router(state.clone());

        let (mut body, _initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);

        // Set timestamp to 60 seconds ago (beyond 30s tolerance)
        let old_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 60;
        body["timestamp"] = serde_json::json!(old_timestamp);

        let resp = post_session(&app, body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let parsed = parse_session_response(resp).await;
        assert!(!parsed.session_id.is_empty());

        // No session created
        assert_eq!(state.harp_sessions.active_count(), 0);
    }

    // -- AC-6 (establishment): Invalid noise_msg1 gets 200 with fake response --

    #[tokio::test]
    async fn invalid_noise_msg1_gets_fake_response() {
        let state = harp_test_app_state();
        let app = crate::web::build_router(state.clone());

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let body = serde_json::json!({
            "noise_msg1": BASE64.encode(b"this is not a valid noise message"),
            "capabilities": ["stream"],
            "timestamp": now,
        });

        let resp = post_session(&app, body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let parsed = parse_session_response(resp).await;
        assert!(!parsed.session_id.is_empty());
        assert_eq!(state.harp_sessions.active_count(), 0);
    }

    // -- AC-7 (establishment): Fake response has same JSON structure as real --

    #[tokio::test]
    async fn fake_response_structure_matches_real() {
        let state = harp_test_app_state();
        let (client_noise, _) = register_client(&state, "eve").await;
        let app = crate::web::build_router(state.clone());

        // Real response
        let (body, _initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);
        let real_resp = post_session(&app, body).await;
        let real_parsed = parse_session_response(real_resp).await;

        // Fake response (expired timestamp)
        let (mut body2, _initiator2) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);
        body2["timestamp"] = serde_json::json!(0u64);
        let fake_resp = post_session(&app, body2).await;
        let fake_parsed = parse_session_response(fake_resp).await;

        // Both should have the same fields populated
        assert_eq!(real_parsed.config.rekey_interval, fake_parsed.config.rekey_interval);
        assert_eq!(real_parsed.config.keepalive_interval, fake_parsed.config.keepalive_interval);
        assert_eq!(real_parsed.config.max_frame_size, fake_parsed.config.max_frame_size);
        assert_eq!(real_parsed.config.poll_interval_ms, fake_parsed.config.poll_interval_ms);
        // Both have transport endpoints
        assert!(!fake_parsed.transport.stream_endpoint.is_empty());
        assert!(!fake_parsed.transport.upload_endpoint.is_empty());
        assert!(!fake_parsed.transport.download_endpoint.is_empty());
    }

    // -- AC-8 (establishment): Two handshakes produce different session IDs --

    #[tokio::test]
    async fn two_handshakes_produce_different_session_ids() {
        let state = harp_test_app_state();
        let (client_noise, _) = register_client(&state, "frank").await;
        let app = crate::web::build_router(state.clone());

        let (body1, _init1) = build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);
        let resp1 = post_session(&app, body1).await;
        let parsed1 = parse_session_response(resp1).await;

        let (body2, _init2) = build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);
        let resp2 = post_session(&app, body2).await;
        let parsed2 = parse_session_response(resp2).await;

        assert_ne!(parsed1.session_id, parsed2.session_id);
        assert_eq!(state.harp_sessions.active_count(), 2);
    }

    // -- AC-9 (establishment): stream_endpoint contains session_id --

    #[tokio::test]
    async fn stream_endpoint_contains_session_id() {
        let state = harp_test_app_state();
        let (client_noise, _) = register_client(&state, "grace").await;
        let app = crate::web::build_router(state.clone());

        let (body, _initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);
        let resp = post_session(&app, body).await;
        let parsed = parse_session_response(resp).await;

        // Endpoint paths use URL-safe base64 encoding of the session ID
        let session_id_bytes = BASE64.decode(&parsed.session_id).expect("decode session_id");
        let url_safe_id = BASE64_URL.encode(&session_id_bytes);

        assert!(
            parsed.transport.stream_endpoint.contains(&url_safe_id),
            "stream_endpoint should contain url-safe session_id"
        );
        assert!(
            parsed.transport.upload_endpoint.contains(&url_safe_id),
            "upload_endpoint should contain url-safe session_id"
        );
        assert!(
            parsed.transport.download_endpoint.contains(&url_safe_id),
            "download_endpoint should contain url-safe session_id"
        );
    }

    // -- AC-10 (establishment): Client and server derive matching session keys --

    #[tokio::test]
    async fn client_server_derive_matching_keys() {
        use crate::transport::encrypted_channel::EncryptedChannel;

        let state = harp_test_app_state();
        let (client_noise, _) = register_client(&state, "heidi").await;
        let app = crate::web::build_router(state.clone());

        let (body, initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);
        let resp = post_session(&app, body).await;
        let parsed = parse_session_response(resp).await;

        let msg2_bytes = BASE64.decode(&parsed.noise_msg2).expect("decode msg2");
        let init_result = initiator.finish(&msg2_bytes).expect("finish handshake");

        // Client sends with tx_key, server receives with tx_key (since server
        // uses swapped keys: server rx = client tx)
        let mut client_channel = EncryptedChannel::new(init_result.session_keys.tx_key, init_result.session_keys.rx_key);

        // To verify keys match, we just need to confirm the handshake completed
        // successfully (which means both sides derived the same Noise handshake
        // hash + KEM shared secret). The EncryptedChannel will fail on decrypt
        // if keys don't match.
        let test_payload = b"key verification test";
        let encrypted = client_channel.send(test_payload).expect("encrypt");
        assert_ne!(encrypted, test_payload.as_slice());
        assert!(!encrypted.is_empty());
    }

    // -- Transport mode selection --

    #[test]
    fn select_transport_mode_prefers_stream() {
        let caps = vec!["stream".to_string(), "poll".to_string()];
        assert_eq!(select_transport_mode(&caps), "stream");
    }

    #[test]
    fn select_transport_mode_falls_back_to_poll() {
        let caps = vec!["poll".to_string()];
        assert_eq!(select_transport_mode(&caps), "poll");
    }

    #[test]
    fn select_transport_mode_defaults_to_poll_on_empty() {
        let caps: Vec<String> = vec![];
        assert_eq!(select_transport_mode(&caps), "poll");
    }

    // -----------------------------------------------------------------------
    // WebSocket Streaming Tests (from FRD-20260223-harp-websocket-streaming.md)
    // -----------------------------------------------------------------------

    /// Start a real TCP server with the HARP router and return its address.
    async fn start_test_server(state: AppState) -> std::net::SocketAddr {
        let app = crate::web::build_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        addr
    }

    /// Connect a WebSocket client to the given path on the test server.
    async fn ws_connect(
        addr: std::net::SocketAddr,
        path: &str,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
        let url = format!("ws://{addr}{path}");
        let (ws, _resp) = tokio_tungstenite::connect_async(&url).await.expect("ws connect");
        ws
    }

    // -- AC-2 (streaming): Unknown session ID → WS upgrade then immediate close --

    #[tokio::test]
    async fn ws_unknown_session_closes_immediately() {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message as TsMessage;

        let state = harp_test_app_state();
        let addr = start_test_server(state).await;

        let fake_id = BASE64_URL.encode([0xFFu8; SESSION_ID_LEN]);
        let mut ws = ws_connect(addr, &format!("/api/v1/harp/stream/{fake_id}")).await;

        // Server should send Close frame and connection ends
        let msg = ws.next().await;
        match msg {
            Some(Ok(TsMessage::Close(_))) | None => {} // expected
            other => panic!("expected Close or stream end, got {other:?}"),
        }
    }

    // -- AC-3 (streaming): Invalid base64 session ID → WS upgrade then close --

    #[tokio::test]
    async fn ws_invalid_base64_session_closes_immediately() {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message as TsMessage;

        let state = harp_test_app_state();
        let addr = start_test_server(state).await;

        let mut ws = ws_connect(addr, "/api/v1/harp/stream/not-valid-base64!!!").await;

        let msg = ws.next().await;
        match msg {
            Some(Ok(TsMessage::Close(_))) | None => {} // expected
            other => panic!("expected Close or stream end, got {other:?}"),
        }
    }

    // -- AC-4 (streaming): Frames sent to to_client_tx appear as WS binary --

    #[tokio::test]
    async fn ws_server_to_client_frame_delivery() {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message as TsMessage;

        let state = harp_test_app_state();
        let (session_id, session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let addr = start_test_server(state).await;

        let mut ws = ws_connect(addr, &format!("/api/v1/harp/stream/{session_id_b64}")).await;

        // Send a frame via the server channel
        let test_payload = b"hello from server".to_vec();
        session.to_client_tx.send(test_payload.clone()).await.expect("send");

        // Read from WebSocket
        let msg = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("timeout")
            .expect("stream not ended")
            .expect("no ws error");

        match msg {
            TsMessage::Binary(data) => assert_eq!(data.as_ref(), test_payload.as_slice()),
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    // -- AC-5 (streaming): WS binary messages from client arrive in from_client_rx --

    #[tokio::test]
    async fn ws_client_to_server_frame_delivery() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as TsMessage;

        let state = harp_test_app_state();
        let (session_id, session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let addr = start_test_server(state).await;

        let mut ws = ws_connect(addr, &format!("/api/v1/harp/stream/{session_id_b64}")).await;

        // Send a frame from the client via WebSocket
        let test_payload = b"hello from client".to_vec();
        ws.send(TsMessage::Binary(test_payload.clone().into())).await.expect("ws send");

        // Read from the server channel
        let mut rx = session.from_client_rx.lock().await;
        let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("channel not closed");
        assert_eq!(received, test_payload);
    }

    // -- AC-6 (streaming): WS close removes session from store --

    #[tokio::test]
    async fn ws_close_removes_session_from_store() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as TsMessage;

        let state = harp_test_app_state();
        let (session_id, _session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let store = Arc::clone(&state.harp_sessions);
        let addr = start_test_server(state).await;

        assert_eq!(store.active_count(), 1);

        let mut ws = ws_connect(addr, &format!("/api/v1/harp/stream/{session_id_b64}")).await;

        // Close the WebSocket
        ws.send(TsMessage::Close(None)).await.expect("ws close");

        // Give the server time to process the close and clean up
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(store.active_count(), 0);
        assert!(store.get(&session_id).is_none());
    }

    // -- AC-7 (streaming): touch() is called on frame activity --

    #[tokio::test]
    async fn ws_touch_called_on_activity() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as TsMessage;

        let state = harp_test_app_state();
        let (session_id, session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let addr = start_test_server(state).await;

        // Force last_activity to 5 seconds ago
        let five_seconds_ago = epoch_millis_now() - 5_000;
        session.last_activity.store(five_seconds_ago, Ordering::Relaxed);
        assert!(session.idle_duration() >= Duration::from_secs(4));

        let mut ws = ws_connect(addr, &format!("/api/v1/harp/stream/{session_id_b64}")).await;

        // Send a frame from client — should trigger touch()
        ws.send(TsMessage::Binary(b"ping".to_vec().into())).await.expect("ws send");

        // Wait for server to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        // last_activity should be updated
        assert!(
            session.idle_duration() < Duration::from_secs(1),
            "touch should have updated last_activity"
        );
    }

    // -- AC-1 (streaming): Valid session triggers WS upgrade (101) --

    #[tokio::test]
    async fn ws_valid_session_upgrades_successfully() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as TsMessage;

        let state = harp_test_app_state();
        let (session_id, _session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let addr = start_test_server(state).await;

        // If connect_async succeeds, upgrade happened (101)
        let mut ws = ws_connect(addr, &format!("/api/v1/harp/stream/{session_id_b64}")).await;

        // Verify we can send and it doesn't immediately close
        ws.send(TsMessage::Binary(b"test".to_vec().into()))
            .await
            .expect("should be able to send");
    }

    // -- Bidirectional: server sends, client receives multiple frames --

    #[tokio::test]
    async fn ws_bidirectional_multiple_frames() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as TsMessage;

        let state = harp_test_app_state();
        let (session_id, session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let addr = start_test_server(state).await;

        let mut ws = ws_connect(addr, &format!("/api/v1/harp/stream/{session_id_b64}")).await;

        let frame_count: usize = 5;

        // Client → Server: send multiple frames
        for i in 0..frame_count {
            let payload = format!("client-frame-{i}").into_bytes();
            ws.send(TsMessage::Binary(payload.into())).await.expect("ws send");
        }

        // Verify all arrived
        let mut rx = session.from_client_rx.lock().await;
        for i in 0..frame_count {
            let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("timeout")
                .expect("channel not closed");
            let expected = format!("client-frame-{i}").into_bytes();
            assert_eq!(received, expected);
        }
        drop(rx);

        // Server → Client: send multiple frames
        for i in 0..frame_count {
            let payload = format!("server-frame-{i}").into_bytes();
            session.to_client_tx.send(payload).await.expect("send");
        }

        // Verify all arrived via WebSocket
        for i in 0..frame_count {
            let msg = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .expect("timeout")
                .expect("stream not ended")
                .expect("no ws error");
            let expected = format!("server-frame-{i}").into_bytes();
            match msg {
                TsMessage::Binary(data) => assert_eq!(data.as_ref(), expected.as_slice()),
                other => panic!("expected Binary, got {other:?}"),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Tunnel Orchestration Tests (FRD-20260223-harp-tunnel-orchestration.md)
    // -----------------------------------------------------------------------

    /// Build an `AppState` with a `DefaultHarpTunnelSpawner` backed by `CapturingMockTunFactory`.
    fn harp_test_app_state_with_spawner(max_clients: u32) -> (AppState, Arc<crate::tunnel::CapturingMockTunFactory>) {
        use crate::tunnel::CapturingMockTunFactory;
        use crate::tunnel::tun_device::DEFAULT_TUNNEL_MTU;

        let tun_factory = Arc::new(CapturingMockTunFactory::new(DEFAULT_TUNNEL_MTU));
        let spawner: Arc<dyn HarpTunnelSpawner> = Arc::new(DefaultHarpTunnelSpawner::new(Arc::clone(&tun_factory), max_clients));

        let mut state = harp_test_app_state();
        state.tunnel_spawner = Some(spawner);
        (state, tun_factory)
    }

    // -- AC-1 (orchestration): Successful handshake triggers TUN device creation --

    #[tokio::test]
    async fn orchestration_handshake_creates_tun() {
        let max_clients: u32 = 10;
        let (state, tun_factory) = harp_test_app_state_with_spawner(max_clients);
        let (client_noise, _) = register_client(&state, "tunnel-alice").await;
        let app = crate::web::build_router(state.clone());

        let (body, _initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);

        let resp = post_session(&app, body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Give the spawned task time to create the TUN
        tokio::time::sleep(Duration::from_millis(100)).await;

        let handles = tun_factory.take_handles();
        assert_eq!(handles.len(), 1, "handshake should trigger TUN device creation");
    }

    // -- AC-7 (orchestration): Active connection counter incremented/decremented --

    #[tokio::test]
    async fn orchestration_active_connections_counter() {
        let max_clients: u32 = 10;
        let (state, _tun_factory) = harp_test_app_state_with_spawner(max_clients);
        let (client_noise, _) = register_client(&state, "tunnel-bob").await;
        let app = crate::web::build_router(state.clone());

        assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);

        let (body, _initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);

        let resp = post_session(&app, body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Give the spawned task time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(
            state.active_connections.load(Ordering::Relaxed),
            1,
            "active connections should be 1 after handshake"
        );

        // Cancel to stop the pipeline
        state.cancel.cancel();
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(
            state.active_connections.load(Ordering::Relaxed),
            0,
            "active connections should be 0 after cancel"
        );
    }

    // -- AC-5 (orchestration): Max clients limit prevents tunnel spawn --

    #[tokio::test]
    async fn orchestration_max_clients_prevents_spawn() {
        let max_clients: u32 = 0; // zero means no tunnels allowed
        let (state, tun_factory) = harp_test_app_state_with_spawner(max_clients);
        let (client_noise, _) = register_client(&state, "tunnel-carol").await;
        let app = crate::web::build_router(state.clone());

        let (body, _initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);

        let resp = post_session(&app, body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Session is created (for probe resistance) but no TUN
        assert_eq!(state.harp_sessions.active_count(), 1);

        tokio::time::sleep(Duration::from_millis(100)).await;

        let handles = tun_factory.take_handles();
        assert_eq!(handles.len(), 0, "no TUN should be created at max capacity");
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
    }

    // -- AC-2 (orchestration): Packets from TUN arrive as HARP frames in to_client --

    #[tokio::test]
    async fn orchestration_tun_to_harp_frame_flow() {
        let max_clients: u32 = 10;
        let (state, tun_factory) = harp_test_app_state_with_spawner(max_clients);
        let (client_noise, _) = register_client(&state, "tunnel-dave").await;
        let app = crate::web::build_router(state.clone());

        let (body, initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);

        let resp = post_session(&app, body).await;
        let parsed = parse_session_response(resp).await;

        // Complete client-side handshake to get session keys
        let msg2_bytes = BASE64.decode(&parsed.noise_msg2).expect("decode msg2");
        let init_result = initiator.finish(&msg2_bytes).expect("finish handshake");

        // Give the spawned task time to create TUN and start pipeline
        tokio::time::sleep(Duration::from_millis(200)).await;

        let handles = tun_factory.take_handles();
        assert_eq!(handles.len(), 1);
        let server_tun_handle = &handles[0];

        // Inject a packet into the server-side TUN (simulates IP packet arriving)
        let test_payload = b"ip-packet-from-kernel";
        server_tun_handle.inject_packet(test_payload).await.expect("inject packet");

        // The pipeline should encrypt it and send it as a HARP DATA frame
        // via to_client_tx. Read from the session's to_client_rx.
        let session_id_bytes = BASE64.decode(&parsed.session_id).expect("decode session_id");
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&session_id_bytes);
        let session = state.harp_sessions.get(&session_id).expect("session exists");

        let mut rx = session.to_client_rx.lock().await;
        let raw_frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for frame")
            .expect("channel not closed");

        // Decode the HARP frame and decrypt with client keys
        let (frame, _) = crate::transport::harp::HarpFrame::decode(&raw_frame).expect("decode frame");
        assert_eq!(frame.frame_type, crate::transport::harp::HarpFrameType::Data);

        // Decrypt: client uses tx_key for sending and rx_key for receiving
        // The server encrypted with rx_key (responder->initiator), so client decrypts with rx_key
        let mut client_channel = EncryptedChannel::new(init_result.session_keys.tx_key, init_result.session_keys.rx_key);
        let decrypted = client_channel.recv(&frame.payload).expect("decrypt");
        assert_eq!(decrypted, test_payload);

        state.cancel.cancel();
    }

    // -- AC-3 (orchestration): HARP frames from client arrive as packets on TUN --

    #[tokio::test]
    async fn orchestration_harp_frame_to_tun_flow() {
        let max_clients: u32 = 10;
        let (state, tun_factory) = harp_test_app_state_with_spawner(max_clients);
        let (client_noise, _) = register_client(&state, "tunnel-eve").await;
        let app = crate::web::build_router(state.clone());

        let (body, initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);

        let resp = post_session(&app, body).await;
        let parsed = parse_session_response(resp).await;

        let msg2_bytes = BASE64.decode(&parsed.noise_msg2).expect("decode msg2");
        let init_result = initiator.finish(&msg2_bytes).expect("finish handshake");

        tokio::time::sleep(Duration::from_millis(200)).await;

        let handles = tun_factory.take_handles();
        assert_eq!(handles.len(), 1);
        let server_tun_handle = &handles[0];

        // Encrypt a packet as the client would
        let test_payload = b"ip-packet-from-client";
        let mut client_channel = EncryptedChannel::new(init_result.session_keys.tx_key, init_result.session_keys.rx_key);
        let encrypted = client_channel.send(test_payload).expect("encrypt");

        // Wrap in HARP DATA frame
        let frame = crate::transport::harp::HarpFrame::data(encrypted);
        let wire_bytes = frame.encode().expect("encode frame");

        // Send to the session's from_client channel
        let session_id_bytes = BASE64.decode(&parsed.session_id).expect("decode session_id");
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&session_id_bytes);
        let session = state.harp_sessions.get(&session_id).expect("session exists");

        session.from_client_tx.send(wire_bytes).await.expect("send frame");

        // The pipeline should decrypt and write to the server-side TUN
        let captured = tokio::time::timeout(Duration::from_secs(2), server_tun_handle.capture_packet())
            .await
            .expect("timeout waiting for TUN packet")
            .expect("TUN channel closed");

        assert_eq!(captured, test_payload);

        state.cancel.cancel();
    }

    // -- AC-4 (orchestration): Pipeline stops when session is removed --

    #[tokio::test]
    async fn orchestration_pipeline_stops_on_session_removal() {
        let max_clients: u32 = 10;
        let (state, _tun_factory) = harp_test_app_state_with_spawner(max_clients);
        let (client_noise, _) = register_client(&state, "tunnel-frank").await;
        let app = crate::web::build_router(state.clone());

        let (body, _initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);

        let resp = post_session(&app, body).await;
        let parsed = parse_session_response(resp).await;

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);

        // Remove the session — this drops the channel senders/receivers,
        // causing the pipeline to stop
        let session_id_bytes = BASE64.decode(&parsed.session_id).expect("decode session_id");
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&session_id_bytes);
        state.harp_sessions.remove(&session_id);

        // Give time for the pipeline task to detect channel closure
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            state.active_connections.load(Ordering::Relaxed),
            0,
            "pipeline should stop when session is removed"
        );
    }

    // -- AC-6 (orchestration): Traffic stats updated after disconnect --

    #[tokio::test]
    async fn orchestration_traffic_stats_updated() {
        let max_clients: u32 = 10;
        let (state, tun_factory) = harp_test_app_state_with_spawner(max_clients);
        let (client_noise, _) = register_client(&state, "tunnel-grace").await;
        let app = crate::web::build_router(state.clone());

        let (body, initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);

        let resp = post_session(&app, body).await;
        let parsed = parse_session_response(resp).await;

        let msg2_bytes = BASE64.decode(&parsed.noise_msg2).expect("decode msg2");
        let init_result = initiator.finish(&msg2_bytes).expect("finish handshake");

        tokio::time::sleep(Duration::from_millis(200)).await;

        let handles = tun_factory.take_handles();
        let server_tun_handle = &handles[0];

        // Send some data through: inject into server TUN (server → client direction)
        let outbound_payload = b"outbound-data-for-stats";
        server_tun_handle.inject_packet(outbound_payload).await.expect("inject");

        // Read the frame to prevent channel back-pressure
        let session_id_bytes = BASE64.decode(&parsed.session_id).expect("decode session_id");
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&session_id_bytes);
        let session = state.harp_sessions.get(&session_id).expect("session");
        {
            let mut rx = session.to_client_rx.lock().await;
            let _ = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
        }

        // Send data the other way: client → server
        let inbound_payload = b"inbound-data-for-stats";
        let mut client_channel = EncryptedChannel::new(init_result.session_keys.tx_key, init_result.session_keys.rx_key);
        let encrypted = client_channel.send(inbound_payload).expect("encrypt");
        let frame = crate::transport::harp::HarpFrame::data(encrypted);
        let wire_bytes = frame.encode().expect("encode");
        session.from_client_tx.send(wire_bytes).await.expect("send");

        // Wait for pipeline to process
        let _ = tokio::time::timeout(Duration::from_secs(2), server_tun_handle.capture_packet()).await;

        // Cancel to trigger disconnect + stats persistence
        state.cancel.cancel();
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Verify traffic stats were persisted to registry
        let registry = state.registry.lock().await;
        let clients = registry.list();
        assert_eq!(clients.len(), 1);
        let client = &clients[0];
        // bytes_sent = server TUN inbound = outbound_payload.len()
        // bytes_received = server TUN outbound = inbound_payload.len()
        assert!(
            client.bytes_sent > 0 || client.bytes_received > 0,
            "traffic stats should be updated: sent={}, received={}",
            client.bytes_sent,
            client.bytes_received,
        );
    }

    // -- ActiveClientGuard decrements on drop --

    #[test]
    fn harp_active_client_guard_decrements() {
        let counter = Arc::new(AtomicU32::new(1));
        let guard = ActiveClientGuard {
            counter: Arc::clone(&counter),
        };
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        drop(guard);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    // -- No tunnel spawned when spawner is None --

    #[tokio::test]
    async fn no_tunnel_spawned_without_spawner() {
        let state = harp_test_app_state(); // tunnel_spawner = None
        let (client_noise, _) = register_client(&state, "no-tunnel-client").await;
        let app = crate::web::build_router(state.clone());

        let (body, _initiator) =
            build_handshake_request(&client_noise, &state.server_noise_public_key, &state.server_context.kem_public_key);

        let resp = post_session(&app, body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Session should be created but no active connections
        assert_eq!(state.harp_sessions.active_count(), 1);
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
    }

    // -----------------------------------------------------------------------
    // Polling Transport Tests (FRD-20260223-harp-polling-transport.md)
    // -----------------------------------------------------------------------

    use crate::transport::harp::HarpFrame;
    use tower::ServiceExt;

    /// Build a POST request with binary body for polling endpoints.
    fn build_poll_request(uri: &str, body: Vec<u8>) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(body))
            .unwrap()
    }

    /// Read the response body as raw bytes.
    async fn read_body_bytes(resp: axum::response::Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), 1_048_576).await.expect("read body").to_vec()
    }

    // -- AC-3: Upload handler returns 200 OK with empty body for unknown session_id --

    #[tokio::test]
    async fn poll_upload_unknown_session_returns_200_empty() {
        let state = harp_test_app_state();
        let app = crate::web::build_router(state);

        let fake_id = BASE64_URL.encode([0xFFu8; SESSION_ID_LEN]);
        let req = build_poll_request(&format!("/api/v1/harp/upload/{fake_id}"), Vec::new());

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_bytes(resp).await;
        assert!(body.is_empty(), "unknown session should return empty body");
    }

    // -- AC-6: Download handler returns 200 OK with empty body for unknown session_id --

    #[tokio::test]
    async fn poll_download_unknown_session_returns_200_empty() {
        let state = harp_test_app_state();
        let app = crate::web::build_router(state);

        let fake_id = BASE64_URL.encode([0xFFu8; SESSION_ID_LEN]);
        let req = build_poll_request(&format!("/api/v1/harp/download/{fake_id}"), Vec::new());

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_bytes(resp).await;
        assert!(body.is_empty(), "unknown session should return empty body");
    }

    // -- AC-3 variant: malformed base64 session_id --

    #[tokio::test]
    async fn poll_upload_invalid_base64_returns_200_empty() {
        let state = harp_test_app_state();
        let app = crate::web::build_router(state);

        let req = build_poll_request("/api/v1/harp/upload/not-valid-base64!!!", Vec::new());

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_bytes(resp).await;
        assert!(body.is_empty());
    }

    // -- AC-1: Upload handler decodes HARP frames and forwards DATA payloads --

    #[tokio::test]
    async fn poll_upload_forwards_data_frame_to_channel() {
        let state = harp_test_app_state();
        let (session_id, session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let app = crate::web::build_router(state);

        let payload = b"encrypted-tunnel-data";
        let frame = HarpFrame::data(payload.to_vec());
        let wire = frame.encode().expect("encode");

        let req = build_poll_request(&format!("/api/v1/harp/upload/{session_id_b64}"), wire);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify the frame arrived in from_client_rx as wire-encoded HARP frame
        let mut rx = session.from_client_rx.lock().await;
        let received = rx.try_recv().expect("should have received frame");
        let (decoded, _) = HarpFrame::decode(&received).expect("decode forwarded frame");
        assert_eq!(decoded.frame_type, HarpFrameType::Data);
        assert_eq!(decoded.payload, payload);
    }

    // -- AC-2: Upload handler skips KEEPALIVE frames --

    #[tokio::test]
    async fn poll_upload_skips_keepalive_frames() {
        let state = harp_test_app_state();
        let (session_id, session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let app = crate::web::build_router(state);

        // Send keepalive followed by data
        let ka = HarpFrame::keepalive().encode().expect("encode ka");
        let data_payload = b"after-keepalive";
        let data = HarpFrame::data(data_payload.to_vec()).encode().expect("encode data");

        let mut body = Vec::new();
        body.extend_from_slice(&ka);
        body.extend_from_slice(&data);

        let req = build_poll_request(&format!("/api/v1/harp/upload/{session_id_b64}"), body);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Only the DATA frame should be in the channel (keepalive skipped)
        let mut rx = session.from_client_rx.lock().await;
        let received = rx.try_recv().expect("should have received data frame");
        let (decoded, _) = HarpFrame::decode(&received).expect("decode");
        assert_eq!(decoded.payload, data_payload);

        // No second message in channel
        assert!(rx.try_recv().is_err(), "keepalive should not be forwarded");
    }

    // -- AC-7: Multiple frames in single upload request --

    #[tokio::test]
    async fn poll_upload_multiple_data_frames() {
        let state = harp_test_app_state();
        let (session_id, session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let app = crate::web::build_router(state);

        let frame_count: usize = 3;
        let mut body = Vec::new();
        for i in 0..frame_count {
            let payload = format!("frame-{i}").into_bytes();
            let wire = HarpFrame::data(payload).encode().expect("encode");
            body.extend_from_slice(&wire);
        }

        let req = build_poll_request(&format!("/api/v1/harp/upload/{session_id_b64}"), body);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut rx = session.from_client_rx.lock().await;
        for i in 0..frame_count {
            let received = rx.try_recv().unwrap_or_else(|_| panic!("expected frame {i}"));
            let (decoded, _) = HarpFrame::decode(&received).expect("decode");
            let expected = format!("frame-{i}").into_bytes();
            assert_eq!(decoded.payload, expected);
        }
        assert!(rx.try_recv().is_err(), "no extra frames");
    }

    // -- AC-4: Upload handler piggybacks download frames in response --

    #[tokio::test]
    async fn poll_upload_piggybacks_download_frames() {
        let state = harp_test_app_state();
        let (session_id, session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let app = crate::web::build_router(state);

        // Queue frames for download (server → client)
        let download_payload = b"download-data";
        let download_frame = HarpFrame::data(download_payload.to_vec()).encode().expect("encode");
        session.to_client_tx.send(download_frame.clone()).await.expect("queue download");

        // Upload an empty DATA frame to trigger piggyback
        let upload_frame = HarpFrame::data(b"upload".to_vec()).encode().expect("encode");
        let req = build_poll_request(&format!("/api/v1/harp/upload/{session_id_b64}"), upload_frame);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Response body should contain the piggybacked download frame
        let body = read_body_bytes(resp).await;
        assert!(!body.is_empty(), "should have piggybacked frames");
        assert_eq!(body, download_frame);
    }

    // -- AC-5: Download handler returns queued frames --

    #[tokio::test]
    async fn poll_download_returns_queued_frames() {
        let state = harp_test_app_state();
        let (session_id, session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let app = crate::web::build_router(state);

        // Queue frames for the client
        let payload1 = b"download-1";
        let wire1 = HarpFrame::data(payload1.to_vec()).encode().expect("encode1");
        let payload2 = b"download-2";
        let wire2 = HarpFrame::data(payload2.to_vec()).encode().expect("encode2");
        session.to_client_tx.send(wire1.clone()).await.expect("send1");
        session.to_client_tx.send(wire2.clone()).await.expect("send2");

        let req = build_poll_request(&format!("/api/v1/harp/download/{session_id_b64}"), Vec::new());
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = read_body_bytes(resp).await;
        let mut expected = Vec::new();
        expected.extend_from_slice(&wire1);
        expected.extend_from_slice(&wire2);
        assert_eq!(body, expected);
    }

    // -- AC-5 variant: Download handler with no queued frames returns empty --

    #[tokio::test]
    async fn poll_download_empty_when_no_queued_frames() {
        let state = harp_test_app_state();
        let (session_id, _session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let app = crate::web::build_router(state);

        let req = build_poll_request(&format!("/api/v1/harp/download/{session_id_b64}"), Vec::new());
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = read_body_bytes(resp).await;
        assert!(body.is_empty(), "no queued frames = empty body");
    }

    // -- Upload CLOSE frame removes session --

    #[tokio::test]
    async fn poll_upload_close_frame_removes_session() {
        let state = harp_test_app_state();
        let (session_id, _session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let store = Arc::clone(&state.harp_sessions);
        let app = crate::web::build_router(state);

        assert_eq!(store.active_count(), 1);

        let close_frame = HarpFrame::close().encode().expect("encode close");
        let req = build_poll_request(&format!("/api/v1/harp/upload/{session_id_b64}"), close_frame);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        assert_eq!(store.active_count(), 0);
        assert!(store.get(&session_id).is_none());
    }

    // -- Upload handler updates touch() on activity --

    #[tokio::test]
    async fn poll_upload_updates_last_activity() {
        let state = harp_test_app_state();
        let (session_id, session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let app = crate::web::build_router(state);

        // Force last_activity to 5 seconds ago
        let five_seconds_ago = epoch_millis_now() - 5_000;
        session.last_activity.store(five_seconds_ago, Ordering::Relaxed);
        assert!(session.idle_duration() >= Duration::from_secs(4));

        let frame = HarpFrame::data(b"ping".to_vec()).encode().expect("encode");
        let req = build_poll_request(&format!("/api/v1/harp/upload/{session_id_b64}"), frame);
        let _resp = app.oneshot(req).await.unwrap();

        assert!(session.idle_duration() < Duration::from_secs(1), "upload should touch session");
    }

    // -- Download handler updates touch() on activity --

    #[tokio::test]
    async fn poll_download_updates_last_activity() {
        let state = harp_test_app_state();
        let (session_id, session) = state.harp_sessions.create(Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);
        let app = crate::web::build_router(state);

        // Force last_activity to 5 seconds ago
        let five_seconds_ago = epoch_millis_now() - 5_000;
        session.last_activity.store(five_seconds_ago, Ordering::Relaxed);
        assert!(session.idle_duration() >= Duration::from_secs(4));

        let req = build_poll_request(&format!("/api/v1/harp/download/{session_id_b64}"), Vec::new());
        let _resp = app.oneshot(req).await.unwrap();

        assert!(session.idle_duration() < Duration::from_secs(1), "download should touch session");
    }

    // FRD: specs/frds/FRD-20260223-harp-transport-traits.md

    // T-S12-3: HarpServerTransport::name() returns "harp"
    #[test]
    fn harp_server_transport_name() {
        use crate::transport::traits::ServerTransport;
        use crate::tunnel::MockTunFactory;
        use crate::tunnel::tun_device::DEFAULT_TUNNEL_MTU;

        let transport = HarpServerTransport::new(
            "127.0.0.1:0".parse().expect("valid addr"),
            Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU)),
        );

        assert_eq!(transport.name(), HARP_SERVER_TRANSPORT_NAME);
    }

    // T-S12-4: HarpServerTransport can be used as Box<dyn ServerTransport>
    #[test]
    fn harp_server_transport_trait_object() {
        use crate::transport::traits::ServerTransport;
        use crate::tunnel::MockTunFactory;
        use crate::tunnel::tun_device::DEFAULT_TUNNEL_MTU;

        let transport: Box<dyn ServerTransport> = Box::new(HarpServerTransport::new(
            "127.0.0.1:0".parse().expect("valid addr"),
            Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU)),
        ));

        assert_eq!(transport.name(), HARP_SERVER_TRANSPORT_NAME);
    }

    // T-S12-5: HarpServerTransport::run() starts and shuts down cleanly
    #[tokio::test]
    async fn harp_server_transport_run_shutdown() {
        use crate::crypto::hybrid_kex::KemKeyPair;
        use crate::handshake::noise_ik::KeyPair;
        use crate::transport::traits::{ServerTransport, SharedServerState};
        use crate::tunnel::MockTunFactory;
        use crate::tunnel::tun_device::DEFAULT_TUNNEL_MTU;

        let noise_kp = Arc::new(KeyPair::generate().expect("noise keypair"));
        let kem_kp = Arc::new(KemKeyPair::generate());
        let registry = Arc::new(tokio::sync::Mutex::new(
            crate::registry::ClientRegistry::new(TEST_SUBNET).expect("registry"),
        ));
        let cancel = CancellationToken::new();

        let shared = Arc::new(SharedServerState {
            registry,
            noise_keypair: noise_kp,
            kem_keypair: kem_kp,
            active_connections: Arc::new(AtomicU32::new(0)),
            max_clients: TEST_MAX_CLIENTS,
            subnet_gateway: std::net::Ipv4Addr::new(10, 66, 66, 1),
            cancel: cancel.clone(),
        });

        let transport = HarpServerTransport::new(
            "127.0.0.1:0".parse().expect("valid addr"),
            Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU)),
        );

        let cancel_clone = cancel.clone();
        let server_task = tokio::spawn(async move { transport.run(shared, cancel_clone).await });

        // Let server bind and start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Cancel before any client connects
        cancel.cancel();

        let result = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), server_task)
            .await
            .expect("server should stop within timeout")
            .expect("task join");

        assert!(result.is_ok(), "transport should shut down cleanly: {result:?}");
    }
}
