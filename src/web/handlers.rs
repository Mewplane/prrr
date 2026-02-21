// FRD: specs/frds/FRD-P006.md

//! REST API endpoint handlers.
//!
//! Each handler is a thin async function that reads/writes to [`AppState`]
//! and returns JSON responses. Domain logic lives in [`ClientRegistry`].

use std::sync::atomic::Ordering;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::errors::ApiError;
use super::state::AppState;
use crate::handshake::noise_ik::{KeyPair, PUBLIC_KEY_LEN};

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// `GET /api/v1/server/status` response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerStatusResponse {
    pub status: String,
    pub uptime_seconds: u64,
    pub version: String,
    pub connected_clients: u32,
    pub total_clients: usize,
}

/// Client info in list/detail responses.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientResponse {
    pub id: Uuid,
    pub name: String,
    pub public_key: String,
    pub ip_address: String,
    pub created_at: u64,
    pub last_seen: Option<u64>,
    pub status: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// `GET /api/v1/clients` response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientListResponse {
    pub clients: Vec<ClientResponse>,
}

/// `POST /api/v1/clients` request.
#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    pub public_key: Option<String>,
    pub pq_public_key: Option<String>,
}

/// `POST /api/v1/clients` response.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateClientResponse {
    pub id: Uuid,
    pub name: String,
    pub ip_address: String,
    pub public_key: String,
    pub private_key: Option<String>,
}

/// Generic status response for mutations.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: String,
}

/// `GET /api/v1/stats/overview` response.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatsOverviewResponse {
    pub clients: ClientStats,
    pub uptime_seconds: u64,
}

/// Client statistics within stats overview.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientStats {
    pub total: usize,
    pub connected: u32,
    pub suspended: usize,
}

/// `GET /api/v1/server/config` response — non-sensitive server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigResponse {
    pub listen_addr: String,
    pub server_name: String,
    pub subnet: String,
    pub dns_servers: Vec<String>,
    pub mtu: u16,
    pub max_clients: u32,
    pub version: String,
    pub transport_protocol: String,
    pub obfuscation_enabled: bool,
    pub web_admin_enabled: bool,
    pub metrics_enabled: bool,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/server/status`
pub async fn server_status(State(state): State<AppState>) -> Result<Json<ServerStatusResponse>, ApiError> {
    let registry = state.registry.lock().await;
    let connected = state.active_connections.load(Ordering::Relaxed);
    let total = registry.count();
    let uptime = state.start_time.elapsed().as_secs();

    Ok(Json(ServerStatusResponse {
        status: "running".to_string(),
        uptime_seconds: uptime,
        version: env!("CARGO_PKG_VERSION").to_string(),
        connected_clients: connected,
        total_clients: total,
    }))
}

/// `GET /api/v1/server/config`
pub async fn server_config(State(state): State<AppState>) -> Result<Json<ServerConfigResponse>, ApiError> {
    Ok(Json((*state.server_config).clone()))
}

/// `GET /api/v1/clients`
pub async fn list_clients(State(state): State<AppState>) -> Result<Json<ClientListResponse>, ApiError> {
    let registry = state.registry.lock().await;
    let clients = registry.list().iter().map(client_to_response).collect();
    Ok(Json(ClientListResponse { clients }))
}

/// `GET /api/v1/clients/{id}`
pub async fn get_client(State(state): State<AppState>, Path(id): Path<Uuid>) -> Result<Json<ClientResponse>, ApiError> {
    let registry = state.registry.lock().await;
    let record = registry
        .get(id)
        .ok_or_else(|| ApiError::NotFound(format!("client not found: {id}")))?;
    Ok(Json(client_to_response(&record)))
}

/// `POST /api/v1/clients`
pub async fn create_client(
    State(state): State<AppState>,
    Json(req): Json<CreateClientRequest>,
) -> Result<(StatusCode, Json<CreateClientResponse>), ApiError> {
    if req.name.is_empty() {
        return Err(ApiError::BadRequest("client name must not be empty".into()));
    }

    let (public_key_bytes, private_key_b64) = match &req.public_key {
        Some(b64) => {
            let bytes = BASE64
                .decode(b64)
                .map_err(|e| ApiError::BadRequest(format!("invalid base64 public key: {e}")))?;
            let key: [u8; PUBLIC_KEY_LEN] = bytes
                .try_into()
                .map_err(|v: Vec<u8>| ApiError::BadRequest(format!("public key must be {PUBLIC_KEY_LEN} bytes, got {}", v.len())))?;
            (key, None)
        }
        None => {
            let keypair = KeyPair::generate().map_err(|e| ApiError::Internal(format!("key generation failed: {e}")))?;
            let private_b64 = BASE64.encode(keypair.private_key_bytes());
            let pub_key = *keypair.public_key();
            (pub_key, Some(private_b64))
        }
    };

    let pq_public_key = match &req.pq_public_key {
        Some(b64) => {
            let bytes = BASE64
                .decode(b64)
                .map_err(|e| ApiError::BadRequest(format!("invalid base64 PQ public key: {e}")))?;
            Some(bytes)
        }
        None => None,
    };

    let mut registry = state.registry.lock().await;
    let record = registry.add(&req.name, public_key_bytes, pq_public_key)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateClientResponse {
            id: record.id,
            name: record.name.clone(),
            ip_address: record.ip_address.to_string(),
            public_key: BASE64.encode(record.public_key),
            private_key: private_key_b64,
        }),
    ))
}

/// `DELETE /api/v1/clients/{id}`
pub async fn delete_client(State(state): State<AppState>, Path(id): Path<Uuid>) -> Result<Json<StatusResponse>, ApiError> {
    let mut registry = state.registry.lock().await;
    registry.remove(id)?;
    Ok(Json(StatusResponse {
        status: "revoked".to_string(),
    }))
}

/// `POST /api/v1/clients/{id}/suspend`
pub async fn suspend_client(State(state): State<AppState>, Path(id): Path<Uuid>) -> Result<Json<StatusResponse>, ApiError> {
    let mut registry = state.registry.lock().await;
    registry.suspend(id)?;
    Ok(Json(StatusResponse {
        status: "suspended".to_string(),
    }))
}

/// `POST /api/v1/clients/{id}/resume`
pub async fn resume_client(State(state): State<AppState>, Path(id): Path<Uuid>) -> Result<Json<StatusResponse>, ApiError> {
    let mut registry = state.registry.lock().await;
    registry.reactivate(id)?;
    Ok(Json(StatusResponse {
        status: "active".to_string(),
    }))
}

/// `GET /api/v1/stats/overview`
pub async fn stats_overview(State(state): State<AppState>) -> Result<Json<StatsOverviewResponse>, ApiError> {
    let registry = state.registry.lock().await;
    let connected = state.active_connections.load(Ordering::Relaxed);
    let total = registry.count();
    let suspended = registry.suspended_count();
    let uptime = state.start_time.elapsed().as_secs();

    Ok(Json(StatsOverviewResponse {
        clients: ClientStats {
            total,
            connected,
            suspended,
        },
        uptime_seconds: uptime,
    }))
}

// ---------------------------------------------------------------------------
// P-009: Client distribution endpoints
// ---------------------------------------------------------------------------

/// `GET /api/v1/clients/{id}/config` — returns client TOML config as text.
pub async fn get_client_config(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, [(String, String); 1], String), ApiError> {
    let registry = state.registry.lock().await;
    let record = registry
        .get(id)
        .ok_or_else(|| ApiError::NotFound(format!("client not found: {id}")))?;

    let config =
        crate::distribution::generate_client_config(&state.server_context, &record).map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok((
        StatusCode::OK,
        [("content-type".to_string(), "text/plain; charset=utf-8".to_string())],
        config,
    ))
}

/// `GET /api/v1/clients/{id}/qr` — returns SVG QR code image.
pub async fn get_client_qr(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, [(String, String); 1], String), ApiError> {
    let registry = state.registry.lock().await;
    let record = registry
        .get(id)
        .ok_or_else(|| ApiError::NotFound(format!("client not found: {id}")))?;

    let config =
        crate::distribution::generate_client_config(&state.server_context, &record).map_err(|e| ApiError::Internal(e.to_string()))?;

    let svg = crate::distribution::generate_qr_svg(&config).map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok((StatusCode::OK, [("content-type".to_string(), "image/svg+xml".to_string())], svg))
}

/// `POST /api/v1/clients/{id}/config-url` response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigUrlResponse {
    /// Token for config retrieval.
    pub token: String,
    /// Full URL path to retrieve the config.
    pub url: String,
}

/// Config token URL path prefix.
const CONFIG_TOKEN_PATH_PREFIX: &str = "/c/";

/// `POST /api/v1/clients/{id}/config-url` — creates a short URL token.
pub async fn create_config_url(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<ConfigUrlResponse>), ApiError> {
    let registry = state.registry.lock().await;
    let record = registry
        .get(id)
        .ok_or_else(|| ApiError::NotFound(format!("client not found: {id}")))?;

    let config =
        crate::distribution::generate_client_config(&state.server_context, &record).map_err(|e| ApiError::Internal(e.to_string()))?;

    let token = state.config_tokens.insert(config).await;
    let url = format!("{CONFIG_TOKEN_PATH_PREFIX}{token}");

    Ok((StatusCode::CREATED, Json(ConfigUrlResponse { token, url })))
}

/// `GET /c/{token}` — public endpoint to retrieve config by token (no auth).
pub async fn get_config_by_token(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<(StatusCode, [(String, String); 1], String), ApiError> {
    let config = state
        .config_tokens
        .get(&token)
        .await
        .ok_or_else(|| ApiError::NotFound("token not found or expired".to_string()))?;

    Ok((
        StatusCode::OK,
        [("content-type".to_string(), "text/plain; charset=utf-8".to_string())],
        config,
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a [`ClientRecord`] to an API response struct.
fn client_to_response(record: &crate::registry::ClientRecord) -> ClientResponse {
    ClientResponse {
        id: record.id,
        name: record.name.clone(),
        public_key: BASE64.encode(record.public_key),
        ip_address: record.ip_address.to_string(),
        created_at: record.created_at,
        last_seen: record.last_seen,
        status: format!("{:?}", record.status).to_lowercase(),
        bytes_sent: record.bytes_sent,
        bytes_received: record.bytes_received,
    }
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-P006.md
    use super::*;
    use crate::config::DEFAULT_SESSION_TIMEOUT;
    use crate::registry::ClientRegistry;
    use crate::web::AppState;

    use std::sync::Arc;
    use std::sync::atomic::AtomicU32;

    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, post};
    use tokio::sync::Mutex;
    use tokio_util::sync::CancellationToken;
    use tower::ServiceExt;

    fn test_jwt_secret() -> Arc<[u8]> {
        Arc::from([0xABu8; 32].as_slice())
    }

    fn test_password_hash() -> String {
        use argon2::PasswordHasher;
        let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        argon2::Argon2::default()
            .hash_password(b"test-password", &salt)
            .expect("hash")
            .to_string()
    }

    fn test_server_config() -> ServerConfigResponse {
        ServerConfigResponse {
            listen_addr: "0.0.0.0:443".to_string(),
            server_name: "www.google.com".to_string(),
            subnet: "10.66.66.0/24".to_string(),
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            mtu: 1280,
            max_clients: 100,
            version: env!("CARGO_PKG_VERSION").to_string(),
            transport_protocol: "masque".to_string(),
            obfuscation_enabled: false,
            web_admin_enabled: true,
            metrics_enabled: false,
        }
    }

    fn test_app_state() -> AppState {
        use crate::distribution::{ConfigTokenStore, ServerContext};
        let registry = ClientRegistry::new("10.66.66.0/24").expect("valid subnet");
        AppState {
            registry: Arc::new(Mutex::new(registry)),
            active_connections: Arc::new(AtomicU32::new(0)),
            start_time: std::time::Instant::now(),
            jwt_secret: test_jwt_secret(),
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            admin_password_hash: Arc::from(test_password_hash().as_str()),
            cancel: CancellationToken::new(),
            server_context: Arc::new(ServerContext {
                endpoint: "127.0.0.1:443".to_string(),
                noise_public_key: [0xAA; 32],
                kem_public_key: vec![0xBB; 64],
            }),
            config_tokens: Arc::new(ConfigTokenStore::new()),
            server_config: Arc::new(test_server_config()),
        }
    }

    fn test_router(state: AppState) -> Router {
        Router::new()
            .route("/api/v1/server/status", get(server_status))
            .route("/api/v1/server/config", get(server_config))
            .route("/api/v1/clients", get(list_clients).post(create_client))
            .route("/api/v1/clients/{id}", get(get_client).delete(delete_client))
            .route("/api/v1/clients/{id}/suspend", post(suspend_client))
            .route("/api/v1/clients/{id}/resume", post(resume_client))
            .route("/api/v1/clients/{id}/config", get(get_client_config))
            .route("/api/v1/clients/{id}/qr", get(get_client_qr))
            .route("/api/v1/clients/{id}/config-url", post(create_config_url))
            .route("/api/v1/stats/overview", get(stats_overview))
            .route("/c/{token}", get(get_config_by_token))
            .with_state(state)
    }

    async fn parse_json<T: serde::de::DeserializeOwned>(response: axum::response::Response) -> T {
        let body_bytes = axum::body::to_bytes(response.into_body(), 1_048_576).await.expect("read body");
        serde_json::from_slice(&body_bytes).expect("parse json")
    }

    fn json_request(method: &str, uri: &str, body: Option<serde_json::Value>) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let body = body.map_or_else(Body::empty, |v| Body::from(serde_json::to_vec(&v).unwrap()));
        builder.body(body).unwrap()
    }

    // ---- Server status tests ----

    #[tokio::test]
    async fn server_status_response() {
        let state = test_app_state();
        state.active_connections.store(3, Ordering::Relaxed);
        let app = test_router(state);

        let resp = app.oneshot(json_request("GET", "/api/v1/server/status", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: ServerStatusResponse = parse_json(resp).await;
        assert_eq!(body.status, "running");
        assert_eq!(body.connected_clients, 3);
        assert_eq!(body.total_clients, 0);
        assert_eq!(body.version, env!("CARGO_PKG_VERSION"));
    }

    // ---- Server config tests (P-009B) ----

    // AC-B19: GET /api/v1/server/config returns JSON with expected fields
    #[tokio::test]
    async fn server_config_response() {
        let state = test_app_state();
        let app = test_router(state);

        let resp = app.oneshot(json_request("GET", "/api/v1/server/config", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: ServerConfigResponse = parse_json(resp).await;
        assert_eq!(body.listen_addr, "0.0.0.0:443");
        assert_eq!(body.server_name, "www.google.com");
        assert_eq!(body.subnet, "10.66.66.0/24");
        assert_eq!(body.dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(body.mtu, 1280);
        assert_eq!(body.max_clients, 100);
        assert_eq!(body.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(body.transport_protocol, "masque");
        assert!(!body.obfuscation_enabled);
        assert!(body.web_admin_enabled);
        assert!(!body.metrics_enabled);
    }

    // ---- List clients tests ----

    #[tokio::test]
    async fn list_clients_empty() {
        let state = test_app_state();
        let app = test_router(state);

        let resp = app.oneshot(json_request("GET", "/api/v1/clients", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: ClientListResponse = parse_json(resp).await;
        assert!(body.clients.is_empty());
    }

    #[tokio::test]
    async fn list_clients_populated() {
        let state = test_app_state();
        {
            let mut reg = state.registry.lock().await;
            reg.add("alice", [0x01; PUBLIC_KEY_LEN], None).unwrap();
            reg.add("bob", [0x02; PUBLIC_KEY_LEN], None).unwrap();
        }
        let app = test_router(state);

        let resp = app.oneshot(json_request("GET", "/api/v1/clients", None)).await.unwrap();
        let body: ClientListResponse = parse_json(resp).await;
        assert_eq!(body.clients.len(), 2);
    }

    // ---- Get client tests ----

    #[tokio::test]
    async fn get_client_found() {
        let state = test_app_state();
        let id = {
            let mut reg = state.registry.lock().await;
            reg.add("alice", [0x01; PUBLIC_KEY_LEN], None).unwrap().id
        };
        let app = test_router(state);

        let resp = app
            .oneshot(json_request("GET", &format!("/api/v1/clients/{id}"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: ClientResponse = parse_json(resp).await;
        assert_eq!(body.name, "alice");
        assert_eq!(body.id, id);
        assert_eq!(body.status, "active");
    }

    #[tokio::test]
    async fn get_client_not_found() {
        let state = test_app_state();
        let app = test_router(state);
        let id = Uuid::new_v4();

        let resp = app
            .oneshot(json_request("GET", &format!("/api/v1/clients/{id}"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ---- Create client tests ----

    #[tokio::test]
    async fn create_client_with_key() {
        let state = test_app_state();
        let app = test_router(state);

        let pub_key = BASE64.encode([0xAA; PUBLIC_KEY_LEN]);
        let body = serde_json::json!({"name": "alice", "public_key": pub_key});
        let resp = app.oneshot(json_request("POST", "/api/v1/clients", Some(body))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body: CreateClientResponse = parse_json(resp).await;
        assert_eq!(body.name, "alice");
        assert!(body.private_key.is_none());
        assert_eq!(body.public_key, pub_key);
    }

    #[tokio::test]
    async fn create_client_auto_key() {
        let state = test_app_state();
        let app = test_router(state);

        let body = serde_json::json!({"name": "bob"});
        let resp = app.oneshot(json_request("POST", "/api/v1/clients", Some(body))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body: CreateClientResponse = parse_json(resp).await;
        assert_eq!(body.name, "bob");
        assert!(body.private_key.is_some());
        assert!(!body.public_key.is_empty());
    }

    #[tokio::test]
    async fn create_client_duplicate_name() {
        let state = test_app_state();
        {
            let mut reg = state.registry.lock().await;
            reg.add("alice", [0x01; PUBLIC_KEY_LEN], None).unwrap();
        }
        let app = test_router(state);

        let body = serde_json::json!({"name": "alice"});
        let resp = app.oneshot(json_request("POST", "/api/v1/clients", Some(body))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn create_client_empty_name() {
        let state = test_app_state();
        let app = test_router(state);

        let body = serde_json::json!({"name": ""});
        let resp = app.oneshot(json_request("POST", "/api/v1/clients", Some(body))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_client_invalid_key() {
        let state = test_app_state();
        let app = test_router(state);

        let body = serde_json::json!({"name": "alice", "public_key": "not-valid-base64!!!"});
        let resp = app.oneshot(json_request("POST", "/api/v1/clients", Some(body))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_client_wrong_key_length() {
        let state = test_app_state();
        let app = test_router(state);

        let short_key = BASE64.encode([0xBB; 16]); // 16 bytes, not 32
        let body = serde_json::json!({"name": "alice", "public_key": short_key});
        let resp = app.oneshot(json_request("POST", "/api/v1/clients", Some(body))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ---- Delete client tests ----

    #[tokio::test]
    async fn delete_client_exists() {
        let state = test_app_state();
        let id = {
            let mut reg = state.registry.lock().await;
            reg.add("alice", [0x01; PUBLIC_KEY_LEN], None).unwrap().id
        };
        let app = test_router(state);

        let resp = app
            .oneshot(json_request("DELETE", &format!("/api/v1/clients/{id}"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: StatusResponse = parse_json(resp).await;
        assert_eq!(body.status, "revoked");
    }

    #[tokio::test]
    async fn delete_client_not_found() {
        let state = test_app_state();
        let app = test_router(state);
        let id = Uuid::new_v4();

        let resp = app
            .oneshot(json_request("DELETE", &format!("/api/v1/clients/{id}"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ---- Suspend client tests ----

    #[tokio::test]
    async fn suspend_client_exists() {
        let state = test_app_state();
        let id = {
            let mut reg = state.registry.lock().await;
            reg.add("alice", [0x01; PUBLIC_KEY_LEN], None).unwrap().id
        };
        let app = test_router(state);

        let resp = app
            .oneshot(json_request("POST", &format!("/api/v1/clients/{id}/suspend"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: StatusResponse = parse_json(resp).await;
        assert_eq!(body.status, "suspended");
    }

    #[tokio::test]
    async fn suspend_client_not_found() {
        let state = test_app_state();
        let app = test_router(state);
        let id = Uuid::new_v4();

        let resp = app
            .oneshot(json_request("POST", &format!("/api/v1/clients/{id}/suspend"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ---- Resume client tests ----

    #[tokio::test]
    async fn resume_client_exists() {
        let state = test_app_state();
        let id = {
            let mut reg = state.registry.lock().await;
            let record = reg.add("alice", [0x01; PUBLIC_KEY_LEN], None).unwrap();
            let id = record.id;
            reg.suspend(id).unwrap();
            id
        };
        let app = test_router(state);

        let resp = app
            .oneshot(json_request("POST", &format!("/api/v1/clients/{id}/resume"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: StatusResponse = parse_json(resp).await;
        assert_eq!(body.status, "active");
    }

    #[tokio::test]
    async fn resume_client_not_found() {
        let state = test_app_state();
        let app = test_router(state);
        let id = Uuid::new_v4();

        let resp = app
            .oneshot(json_request("POST", &format!("/api/v1/clients/{id}/resume"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ---- Stats overview tests ----

    #[tokio::test]
    async fn stats_overview_empty() {
        let state = test_app_state();
        let app = test_router(state);

        let resp = app.oneshot(json_request("GET", "/api/v1/stats/overview", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: StatsOverviewResponse = parse_json(resp).await;
        assert_eq!(body.clients.total, 0);
        assert_eq!(body.clients.connected, 0);
        assert_eq!(body.clients.suspended, 0);
    }

    #[tokio::test]
    async fn stats_overview_with_clients() {
        let state = test_app_state();
        state.active_connections.store(1, Ordering::Relaxed);
        {
            let mut reg = state.registry.lock().await;
            let record = reg.add("alice", [0x01; PUBLIC_KEY_LEN], None).unwrap();
            let bob = reg.add("bob", [0x02; PUBLIC_KEY_LEN], None).unwrap();
            reg.suspend(bob.id).unwrap();
            // alice is active, bob is suspended, both in count
            let _ = record;
        }
        let app = test_router(state);

        let resp = app.oneshot(json_request("GET", "/api/v1/stats/overview", None)).await.unwrap();
        let body: StatsOverviewResponse = parse_json(resp).await;
        assert_eq!(body.clients.total, 2);
        assert_eq!(body.clients.connected, 1);
        assert_eq!(body.clients.suspended, 1);
    }

    // ---- P-009: Client distribution endpoint tests ----

    // AC-13: GET /api/v1/clients/{id}/config returns TOML text with 200 OK
    #[tokio::test]
    async fn api_get_client_config() {
        let state = test_app_state();
        let id = {
            let mut reg = state.registry.lock().await;
            reg.add("alice", [0x01; PUBLIC_KEY_LEN], None).unwrap().id
        };
        let app = test_router(state);

        let resp = app
            .oneshot(json_request("GET", &format!("/api/v1/clients/{id}/config"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let content_type = resp.headers().get("content-type").expect("content-type header").to_str().unwrap();
        assert!(content_type.contains("text/plain"), "expected text/plain, got {content_type}");

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
        let body = std::str::from_utf8(&body_bytes).expect("valid UTF-8");

        // Must be valid TOML with expected sections
        let parsed: toml::Value = toml::from_str(body).expect("valid TOML");
        assert!(parsed.get("client").is_some(), "missing [client] section");
        assert!(parsed.get("server").is_some(), "missing [server] section");
        assert!(parsed.get("interface").is_some(), "missing [interface] section");

        let client_name = parsed["client"]["name"].as_str().expect("client name");
        assert_eq!(client_name, "alice");
    }

    // AC-14: GET /api/v1/clients/{id}/config returns 404 for unknown client
    #[tokio::test]
    async fn api_get_client_config_not_found() {
        let state = test_app_state();
        let app = test_router(state);
        let id = Uuid::new_v4();

        let resp = app
            .oneshot(json_request("GET", &format!("/api/v1/clients/{id}/config"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // AC-15: GET /api/v1/clients/{id}/qr returns SVG image with 200 OK
    #[tokio::test]
    async fn api_get_client_qr() {
        let state = test_app_state();
        let id = {
            let mut reg = state.registry.lock().await;
            reg.add("alice", [0x01; PUBLIC_KEY_LEN], None).unwrap().id
        };
        let app = test_router(state);

        let resp = app
            .oneshot(json_request("GET", &format!("/api/v1/clients/{id}/qr"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let content_type = resp.headers().get("content-type").expect("content-type header").to_str().unwrap();
        assert!(content_type.contains("image/svg+xml"), "expected image/svg+xml, got {content_type}");

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
        let body = std::str::from_utf8(&body_bytes).expect("valid UTF-8");
        assert!(body.contains("<svg"), "response must contain SVG element");
        assert!(body.contains("</svg>"), "response must contain closing SVG element");
    }

    // AC-16: POST /api/v1/clients/{id}/config-url returns JSON with token URL
    #[tokio::test]
    async fn api_create_config_url() {
        let state = test_app_state();
        let id = {
            let mut reg = state.registry.lock().await;
            reg.add("alice", [0x01; PUBLIC_KEY_LEN], None).unwrap().id
        };
        let app = test_router(state);

        let resp = app
            .clone()
            .oneshot(json_request("POST", &format!("/api/v1/clients/{id}/config-url"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body: ConfigUrlResponse = parse_json(resp).await;
        assert!(!body.token.is_empty(), "token must not be empty");
        assert!(body.url.starts_with("/c/"), "url must start with /c/");
        assert!(body.url.contains(&body.token), "url must contain the token");
    }

    // AC-17: GET /c/{token} returns TOML config without authentication
    #[tokio::test]
    async fn api_get_config_by_token() {
        let state = test_app_state();
        let id = {
            let mut reg = state.registry.lock().await;
            reg.add("alice", [0x01; PUBLIC_KEY_LEN], None).unwrap().id
        };
        let app = test_router(state);

        // First create a config URL token
        let resp = app
            .clone()
            .oneshot(json_request("POST", &format!("/api/v1/clients/{id}/config-url"), None))
            .await
            .unwrap();
        let url_resp: ConfigUrlResponse = parse_json(resp).await;

        // Then retrieve config using the token (no auth required)
        let resp = app.oneshot(json_request("GET", &url_resp.url, None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let content_type = resp.headers().get("content-type").expect("content-type header").to_str().unwrap();
        assert!(content_type.contains("text/plain"), "expected text/plain, got {content_type}");

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
        let body = std::str::from_utf8(&body_bytes).expect("valid UTF-8");
        let parsed: toml::Value = toml::from_str(body).expect("valid TOML");
        assert_eq!(parsed["client"]["name"].as_str(), Some("alice"));
    }

    // AC-18: GET /c/{token} returns 404 for expired/unknown token
    #[tokio::test]
    async fn api_get_config_by_token_not_found() {
        let state = test_app_state();
        let app = test_router(state);

        let resp = app
            .oneshot(json_request("GET", "/c/deadbeefdeadbeefdeadbeefdeadbeef", None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // Additional: QR endpoint returns 404 for unknown client
    #[tokio::test]
    async fn api_get_client_qr_not_found() {
        let state = test_app_state();
        let app = test_router(state);
        let id = Uuid::new_v4();

        let resp = app
            .oneshot(json_request("GET", &format!("/api/v1/clients/{id}/qr"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // Additional: config-url endpoint returns 404 for unknown client
    #[tokio::test]
    async fn api_create_config_url_not_found() {
        let state = test_app_state();
        let app = test_router(state);
        let id = Uuid::new_v4();

        let resp = app
            .oneshot(json_request("POST", &format!("/api/v1/clients/{id}/config-url"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // P-009 R2: Client response includes traffic counters
    #[tokio::test]
    async fn client_response_includes_traffic() {
        let state = test_app_state();
        let id = {
            let mut reg = state.registry.lock().await;
            let c = reg.add("alice", [0x01; PUBLIC_KEY_LEN], None).unwrap();
            reg.update_traffic(c.id, 12345, 67890).unwrap();
            c.id
        };
        let app = test_router(state);

        let resp = app
            .oneshot(json_request("GET", &format!("/api/v1/clients/{id}"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: ClientResponse = parse_json(resp).await;
        assert_eq!(body.bytes_sent, 12345);
        assert_eq!(body.bytes_received, 67890);
    }
}
