// FRD: specs/frds/FRD-P006.md, specs/frds/FRD-P007.md, specs/frds/FRD-20260223-web-ui-logo-integration.md

//! REST API backend and web frontend for VPN administration.
//!
//! Provides [`run_web_server`] to start an HTTP server on the admin
//! port alongside the VPN server. Shares state with the VPN server via
//! [`AppState`]. Serves the embedded SPA frontend at the root path.

pub mod auth;
pub mod errors;
pub mod handlers;
/// HARP session management for the HTTPS API Relay Protocol.
pub mod harp;
pub mod spa;
pub mod state;

pub use state::AppState;

use std::net::SocketAddr;

use axum::Router;
use axum::routing::{delete, get, post};
use tower_http::cors::{Any, CorsLayer};

/// API version prefix for all routes.
const API_V1_PREFIX: &str = "/api/v1";

/// Build the axum Router with all API routes.
///
/// Routes under `/api/v1/auth/*` are public.
/// All other routes are protected by JWT Bearer token middleware.
pub fn build_router(state: AppState) -> Router {
    let auth_routes = Router::new().route("/auth/login", post(auth::login));

    let protected_routes = Router::new()
        .route("/server/status", get(handlers::server_status))
        .route("/server/config", get(handlers::server_config))
        .route("/server/transports", get(handlers::server_transports))
        .route("/clients", get(handlers::list_clients).post(handlers::create_client))
        .route("/clients/{id}", get(handlers::get_client).delete(handlers::delete_client))
        .route("/clients/{id}/suspend", post(handlers::suspend_client))
        .route("/clients/{id}/resume", post(handlers::resume_client))
        .route("/clients/{id}/config", get(handlers::get_client_config))
        .route("/clients/{id}/qr", get(handlers::get_client_qr))
        .route("/clients/{id}/config-url", post(handlers::create_config_url))
        .route("/stats/overview", get(handlers::stats_overview))
        .route("/stats/traffic", get(handlers::stats_traffic))
        .route("/harp/sessions", get(handlers::list_harp_sessions))
        .route("/harp/sessions/{session_id_hex}", delete(handlers::terminate_harp_session))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth::require_auth));

    let harp_routes = Router::new()
        .route("/harp/session", post(harp::create_session))
        .route("/harp/stream/{session_id}", get(harp::stream_handler))
        .route("/harp/upload/{session_id}", post(harp::h2_upload_handler))
        .route(
            "/harp/download/{session_id}",
            get(harp::h2_download_handler).post(harp::poll_download_handler),
        );

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let base = Router::new()
        .route("/favicon.ico", get(spa::logo_handler))
        .route("/admin", get(spa::spa_handler))
        .route("/assets/logo_w.png", get(spa::logo_handler))
        .route("/assets/logo_w_text.png", get(spa::logo_text_handler))
        .route("/c/{token}", get(handlers::get_config_by_token))
        .nest(API_V1_PREFIX, auth_routes.merge(protected_routes).merge(harp_routes));

    if state.cover_page_enabled {
        base.route("/", get(spa::cover_handler))
            .fallback(get(spa::cover_handler))
            .layer(cors)
            .with_state(state)
    } else {
        base.route("/", get(spa::spa_handler))
            .fallback(get(spa::spa_handler))
            .layer(cors)
            .with_state(state)
    }
}

/// Start the web admin HTTP server.
///
/// Binds to `listen_addr` and serves the REST API.
/// Runs until the cancellation token in `state` is triggered.
pub async fn run_web_server(listen_addr: SocketAddr, state: AppState) -> anyhow::Result<()> {
    let app = build_router(state.clone());
    let cancel = state.cancel.clone();

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;
    tracing::info!("web admin listening on http://{local_addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await?;

    tracing::info!("web admin server stopped");
    Ok(())
}

/// Start the web server with TLS (HTTPS).
///
/// Uses `axum-server` with rustls to serve the same router over HTTPS.
/// `tls_cert` and `tls_key` are paths to PEM-encoded certificate chain and
/// private key files (e.g. from Let's Encrypt).
pub async fn run_web_server_tls(listen_addr: SocketAddr, state: AppState, tls_cert: &str, tls_key: &str) -> anyhow::Result<()> {
    let app = build_router(state.clone());
    let cancel = state.cancel.clone();

    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(tls_cert, tls_key)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load TLS config: {e}"))?;

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();

    tokio::spawn(async move {
        cancel.cancelled().await;
        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
    });

    tracing::info!("HARP transport listening on https://{listen_addr}");

    axum_server::bind_rustls(listen_addr, rustls_config)
        .handle(handle)
        .serve(app.into_make_service())
        .await?;

    tracing::info!("HARP TLS server stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-P006.md
    use super::*;
    use crate::config::DEFAULT_SESSION_TIMEOUT;
    use crate::registry::ClientRegistry;
    use crate::web::auth::LoginResponse;
    use crate::web::handlers::{ClientListResponse, CreateClientResponse, ServerStatusResponse, StatusResponse};

    use std::sync::Arc;
    use std::sync::atomic::AtomicU32;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tokio::sync::Mutex;
    use tokio_util::sync::CancellationToken;
    use tower::ServiceExt;

    fn test_password_hash() -> String {
        use argon2::PasswordHasher;
        let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        argon2::Argon2::default()
            .hash_password(b"admin-pass", &salt)
            .expect("hash")
            .to_string()
    }

    fn test_app_state() -> AppState {
        use crate::distribution::{ConfigTokenStore, ServerContext};
        use crate::web::handlers::{ServerConfigResponse, TransportInfoResponse};
        use crate::web::harp::HarpSessionStore;
        let registry = ClientRegistry::new("10.66.66.0/24").expect("valid subnet");
        AppState {
            registry: Arc::new(Mutex::new(registry)),
            active_connections: Arc::new(AtomicU32::new(0)),
            start_time: std::time::Instant::now(),
            jwt_secret: Arc::from([0xABu8; 32].as_slice()),
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            admin_password_hash: Arc::from(test_password_hash().as_str()),
            cancel: CancellationToken::new(),
            server_context: Arc::new(ServerContext {
                endpoint: "127.0.0.1:443".to_string(),
                server_name: "localhost".to_string(),
                noise_public_key: [0xAA; 32],
                kem_public_key: vec![0xBB; 64],
                dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
                mtu: 1100,
                transport_protocol: "harp".to_string(),
            }),
            config_tokens: Arc::new(ConfigTokenStore::new()),
            server_config: Arc::new(ServerConfigResponse {
                listen_addr: "0.0.0.0:443".to_string(),
                server_name: "www.google.com".to_string(),
                subnet: "10.66.66.0/24".to_string(),
                dns_servers: vec!["1.1.1.1".to_string()],
                mtu: 1100,
                max_clients: 100,
                version: env!("CARGO_PKG_VERSION").to_string(),
                transport_protocol: "masque".to_string(),
                obfuscation_enabled: false,
                web_admin_enabled: true,
                metrics_enabled: false,
            }),
            resolved_transports: Arc::new(vec![TransportInfoResponse::from_harp(true, true, 300)]),
            harp_sessions: Arc::new(HarpSessionStore::new()),
            server_noise_private_key: Arc::from([0u8; 32].as_slice()),
            server_noise_public_key: [0u8; 32],
            server_kem_dk_bytes: Arc::from([0u8; 0].as_slice()),
            tunnel_spawner: None,
            cover_page_enabled: true,
            trust_proxy_headers: false,
            h2_streaming_enabled: true,
            active_clients: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    async fn parse_json<T: serde::de::DeserializeOwned>(response: axum::response::Response) -> T {
        let body_bytes = axum::body::to_bytes(response.into_body(), 1_048_576).await.expect("read body");
        serde_json::from_slice(&body_bytes).expect("parse json")
    }

    async fn login_and_get_token(app: &Router, password: &str) -> String {
        let body = serde_json::json!({"username": "admin", "password": password});
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "login should succeed");
        let login: LoginResponse = parse_json(resp).await;
        login.token
    }

    fn authed_request(method: &str, uri: &str, token: &str, body: Option<serde_json::Value>) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"));
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let body = body.map_or_else(Body::empty, |v| Body::from(serde_json::to_vec(&v).unwrap()));
        builder.body(body).unwrap()
    }

    #[tokio::test]
    async fn full_crud_flow_through_router() {
        let state = test_app_state();
        let app = build_router(state);

        // 1. Login
        let token = login_and_get_token(&app, "admin-pass").await;

        // 2. List clients — empty
        let resp = app
            .clone()
            .oneshot(authed_request("GET", "/api/v1/clients", &token, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let list: ClientListResponse = parse_json(resp).await;
        assert!(list.clients.is_empty());

        // 3. Create client (auto-generate key)
        let resp = app
            .clone()
            .oneshot(authed_request(
                "POST",
                "/api/v1/clients",
                &token,
                Some(serde_json::json!({"name": "alice"})),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let created: CreateClientResponse = parse_json(resp).await;
        assert_eq!(created.name, "alice");
        assert!(created.private_key.is_some());

        // 4. Get client
        let resp = app
            .clone()
            .oneshot(authed_request("GET", &format!("/api/v1/clients/{}", created.id), &token, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 5. Suspend client
        let resp = app
            .clone()
            .oneshot(authed_request(
                "POST",
                &format!("/api/v1/clients/{}/suspend", created.id),
                &token,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let status: StatusResponse = parse_json(resp).await;
        assert_eq!(status.status, "suspended");

        // 6. Resume client
        let resp = app
            .clone()
            .oneshot(authed_request(
                "POST",
                &format!("/api/v1/clients/{}/resume", created.id),
                &token,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let status: StatusResponse = parse_json(resp).await;
        assert_eq!(status.status, "active");

        // 7. Delete client
        let resp = app
            .clone()
            .oneshot(authed_request("DELETE", &format!("/api/v1/clients/{}", created.id), &token, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let status: StatusResponse = parse_json(resp).await;
        assert_eq!(status.status, "revoked");

        // 8. Server status
        let resp = app
            .clone()
            .oneshot(authed_request("GET", "/api/v1/server/status", &token, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let status: ServerStatusResponse = parse_json(resp).await;
        assert_eq!(status.status, "running");
    }

    #[tokio::test]
    async fn protected_routes_reject_without_auth() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/server/status")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // AC-B20: GET /api/v1/server/config requires authentication
    #[tokio::test]
    async fn server_config_requires_auth() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/server/config")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // AC-B19: GET /api/v1/server/config returns JSON with auth
    #[tokio::test]
    async fn server_config_returns_json_with_auth() {
        use crate::web::handlers::ServerConfigResponse;

        let state = test_app_state();
        let app = build_router(state);
        let token = login_and_get_token(&app, "admin-pass").await;

        let resp = app
            .clone()
            .oneshot(authed_request("GET", "/api/v1/server/config", &token, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: ServerConfigResponse = parse_json(resp).await;
        assert_eq!(body.server_name, "www.google.com");
        assert_eq!(body.version, env!("CARGO_PKG_VERSION"));
    }

    // AC-3: GET /api/v1/server/transports requires authentication
    #[tokio::test]
    async fn server_transports_requires_auth() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/server/transports")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // AC-1: GET /api/v1/server/transports returns transport list with auth
    #[tokio::test]
    async fn server_transports_returns_list_with_auth() {
        use crate::web::handlers::TransportListResponse;

        let state = test_app_state();
        let app = build_router(state);
        let token = login_and_get_token(&app, "admin-pass").await;

        let resp = app
            .clone()
            .oneshot(authed_request("GET", "/api/v1/server/transports", &token, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: TransportListResponse = parse_json(resp).await;
        assert!(!body.transports.is_empty(), "transports list must not be empty");
        assert_eq!(body.transports[0].name, "harp");
    }

    #[tokio::test]
    async fn cors_preflight_returns_headers() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/server/status")
            .header("origin", "http://localhost:3000")
            .header("access-control-request-method", "GET")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key("access-control-allow-origin"));
    }

    #[tokio::test]
    async fn server_graceful_shutdown() {
        let state = test_app_state();
        let cancel = state.cancel.clone();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let server_handle = tokio::spawn(run_web_server(listen_addr, state));

        // Give server time to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Cancel and verify clean shutdown
        cancel.cancel();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle)
            .await
            .expect("server should stop within timeout")
            .expect("join should succeed");
        assert!(result.is_ok(), "server should shut down cleanly");
    }

    #[tokio::test]
    async fn shared_active_count() {
        let state = test_app_state();
        // Simulate VPN server updating active connections
        state.active_connections.store(7, std::sync::atomic::Ordering::Relaxed);

        let app = build_router(state);
        let token = login_and_get_token(&app, "admin-pass").await;

        let resp = app
            .clone()
            .oneshot(authed_request("GET", "/api/v1/server/status", &token, None))
            .await
            .unwrap();
        let status: ServerStatusResponse = parse_json(resp).await;
        assert_eq!(status.connected_clients, 7);
    }

    // --- Logo asset route integration tests (FRD-20260223-web-ui-logo-integration) ---

    #[tokio::test]
    async fn logo_route_returns_png() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/assets/logo_w.png")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("valid header value");
        assert_eq!(content_type, "image/png", "logo route must return image/png");
        let body = axum::body::to_bytes(resp.into_body(), 1_048_576).await.unwrap();
        assert!(!body.is_empty(), "logo body must not be empty");
    }

    #[tokio::test]
    async fn logo_text_route_returns_png() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/assets/logo_w_text.png")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("valid header value");
        assert_eq!(content_type, "image/png", "logo text route must return image/png");
        let body = axum::body::to_bytes(resp.into_body(), 1_048_576).await.unwrap();
        assert!(!body.is_empty(), "logo text body must not be empty");
    }

    // --- Cover page + SPA routing integration tests (FRD-20260224-cover-page-handler) ---

    // AC-1: GET / returns cover HTML with "PRRR Vision"
    #[tokio::test]
    async fn cover_root_serves_cover_html() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder().method("GET").uri("/").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("valid header value");
        assert!(content_type.contains("text/html"), "expected text/html, got {content_type}");
        let body = axum::body::to_bytes(resp.into_body(), 1_048_576).await.unwrap();
        let html = std::str::from_utf8(&body).expect("valid utf-8");
        assert!(html.contains("PRRR Vision"), "root must serve cover page with PRRR Vision branding");
    }

    // AC-2: GET / has Server: nginx/1.24.0
    #[tokio::test]
    async fn cover_root_has_nginx_server_header() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder().method("GET").uri("/").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let server = resp
            .headers()
            .get("server")
            .expect("server header")
            .to_str()
            .expect("valid header value");
        assert_eq!(server, "nginx/1.24.0");
    }

    // AC-3: GET /admin returns SPA HTML
    #[tokio::test]
    async fn admin_serves_spa() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder().method("GET").uri("/admin").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1_048_576).await.unwrap();
        let html = std::str::from_utf8(&body).expect("valid utf-8");
        assert!(html.contains("prrr - Admin"), "/admin must serve SPA with prrr - Admin title");
    }

    // AC-5: GET /favicon.ico returns PNG
    #[tokio::test]
    async fn favicon_serves_logo() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder().method("GET").uri("/favicon.ico").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("valid header value");
        assert_eq!(content_type, "image/png");
    }

    // AC-6: Fallback serves cover HTML (not SPA)
    #[tokio::test]
    async fn fallback_serves_cover() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/some-random-path")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1_048_576).await.unwrap();
        let html = std::str::from_utf8(&body).expect("valid utf-8");
        assert!(html.contains("PRRR Vision"), "fallback must serve cover page, not SPA");
    }

    // AC-3: Router with cover_page_enabled=false serves SPA at /
    #[tokio::test]
    async fn cover_disabled_root_serves_spa() {
        let mut state = test_app_state();
        state.cover_page_enabled = false;
        let app = build_router(state);

        let req = Request::builder().method("GET").uri("/").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1_048_576).await.unwrap();
        let html = std::str::from_utf8(&body).expect("valid utf-8");
        assert!(html.contains("prrr - Admin"), "with cover disabled, / must serve SPA");
    }

    #[tokio::test]
    async fn api_routes_not_captured_by_fallback() {
        let state = test_app_state();
        let app = build_router(state);

        // API route without auth should return 401, not SPA HTML
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/server/status")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // --- Traffic stats integration tests (FRD-20260223-client-traffic-stats-ui) ---

    // AC-11: Traffic endpoint requires authentication
    #[tokio::test]
    async fn stats_traffic_requires_auth() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/stats/traffic")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // Traffic endpoint returns data with auth
    #[tokio::test]
    async fn stats_traffic_returns_data_with_auth() {
        use crate::web::handlers::TrafficStatsResponse;

        let state = test_app_state();
        let app = build_router(state);
        let token = login_and_get_token(&app, "admin-pass").await;

        let resp = app
            .clone()
            .oneshot(authed_request("GET", "/api/v1/stats/traffic", &token, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: TrafficStatsResponse = parse_json(resp).await;
        assert_eq!(body.total_bytes_sent, 0);
        assert_eq!(body.total_bytes_received, 0);
        assert_eq!(body.client_count, 0);
    }

    // --- HARP session management integration tests (FRD-20260223-harp-session-management-ui) ---

    // AC-2: Session list requires auth
    #[tokio::test]
    async fn harp_sessions_list_requires_auth() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/harp/sessions")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // Session list returns data with auth
    #[tokio::test]
    async fn harp_sessions_list_with_auth() {
        use crate::web::handlers::HarpSessionListResponse;

        let state = test_app_state();
        let _ = state.harp_sessions.create(uuid::Uuid::new_v4());
        let app = build_router(state);
        let token = login_and_get_token(&app, "admin-pass").await;

        let resp = app
            .clone()
            .oneshot(authed_request("GET", "/api/v1/harp/sessions", &token, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: HarpSessionListResponse = parse_json(resp).await;
        assert_eq!(body.sessions.len(), 1);
    }

    // Terminate session requires auth
    #[tokio::test]
    async fn harp_session_terminate_requires_auth() {
        let state = test_app_state();
        let app = build_router(state);

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/harp/sessions/deadbeef12345678")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
