// FRD: specs/frds/FRD-P006.md

//! JWT authentication for the web admin API.
//!
//! Provides password verification via Argon2id, JWT token creation and
//! validation (HS256), a login handler, and an axum middleware that
//! enforces Bearer token authentication on protected routes.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use super::errors::ApiError;
use super::state::AppState;

/// Expected admin username (single-user auth model).
const ADMIN_USERNAME: &str = "admin";

/// JWT algorithm used for signing and verification.
const JWT_ALGORITHM: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::HS256;

/// JWT claims payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (always "admin" for single-user auth).
    pub sub: String,
    /// Expiration time (Unix timestamp in seconds).
    pub exp: u64,
    /// Issued at (Unix timestamp in seconds).
    pub iat: u64,
}

/// Login request body.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Login response body.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_in: u64,
}

/// Handle `POST /api/v1/auth/login`.
///
/// Validates username/password against the configured Argon2id hash.
/// Returns a signed JWT token on success.
pub async fn login(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<LoginRequest>,
) -> Result<axum::Json<LoginResponse>, ApiError> {
    if req.username != ADMIN_USERNAME {
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }

    if !verify_password(&req.password, &state.admin_password_hash)? {
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }

    let (token, expires_in) = create_token(&state.jwt_secret, state.session_timeout)?;
    Ok(axum::Json(LoginResponse { token, expires_in }))
}

/// Axum middleware: validate JWT Bearer token on protected routes.
///
/// Extracts the `Authorization: Bearer <token>` header, decodes and
/// validates the JWT. Returns 401 Unauthorized on failure.
pub async fn require_auth(State(state): State<AppState>, request: Request<axum::body::Body>, next: Next) -> Result<Response, ApiError> {
    let auth_header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("missing authorization header".into()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::Unauthorized("invalid authorization scheme".into()))?;

    verify_token(&state.jwt_secret, token)?;

    Ok(next.run(request).await)
}

/// Create a signed JWT token string.
fn create_token(secret: &[u8], session_timeout: u64) -> Result<(String, u64), ApiError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ApiError::Internal(format!("system clock error: {e}")))?
        .as_secs();

    let claims = Claims {
        sub: ADMIN_USERNAME.to_string(),
        exp: now + session_timeout,
        iat: now,
    };

    let token = jsonwebtoken::encode(&Header::new(JWT_ALGORITHM), &claims, &EncodingKey::from_secret(secret))
        .map_err(|e| ApiError::Internal(format!("JWT encoding error: {e}")))?;

    Ok((token, session_timeout))
}

/// Verify and decode a JWT token string. Returns claims on success.
fn verify_token(secret: &[u8], token: &str) -> Result<Claims, ApiError> {
    let mut validation = Validation::new(JWT_ALGORITHM);
    validation.set_required_spec_claims(&["sub", "exp", "iat"]);

    let token_data = jsonwebtoken::decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
        .map_err(|e| ApiError::Unauthorized(format!("invalid token: {e}")))?;

    Ok(token_data.claims)
}

/// Verify a plaintext password against an Argon2id PHC hash string.
fn verify_password(password: &str, hash: &str) -> Result<bool, ApiError> {
    use argon2::PasswordVerifier;

    let parsed_hash = argon2::PasswordHash::new(hash).map_err(|e| ApiError::Internal(format!("invalid password hash format: {e}")))?;

    match argon2::Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(ApiError::Internal(format!("password verification error: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-P006.md
    use super::*;
    use crate::web::AppState;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU32;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use tokio::sync::Mutex;
    use tokio_util::sync::CancellationToken;
    use tower::ServiceExt;

    use crate::config::DEFAULT_SESSION_TIMEOUT;
    use crate::registry::ClientRegistry;

    /// Test password: "test-password-123"
    /// Generated with: echo -n "test-password-123" | argon2 testsalt -id -t 2 -m 16 -p 1 -l 32 -e
    const TEST_PASSWORD: &str = "test-password-123";

    fn test_password_hash() -> String {
        use argon2::PasswordHasher;
        let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        argon2::Argon2::default()
            .hash_password(TEST_PASSWORD.as_bytes(), &salt)
            .expect("hash password")
            .to_string()
    }

    fn test_jwt_secret() -> Arc<[u8]> {
        Arc::from([0xABu8; 32].as_slice())
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
            jwt_secret: test_jwt_secret(),
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            admin_password_hash: Arc::from(test_password_hash().as_str()),
            cancel: CancellationToken::new(),
            server_context: Arc::new(ServerContext {
                endpoint: "127.0.0.1:443".to_string(),
                server_name: "localhost".to_string(),
                noise_public_key: [0xAA; 32],
                kem_public_key: vec![0xBB; 64],
                dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
                mtu: 1280,
                transport_protocol: "harp".to_string(),
            }),
            config_tokens: Arc::new(ConfigTokenStore::new()),
            server_config: Arc::new(ServerConfigResponse {
                listen_addr: "0.0.0.0:443".to_string(),
                server_name: "www.google.com".to_string(),
                subnet: "10.66.66.0/24".to_string(),
                dns_servers: vec!["1.1.1.1".to_string()],
                mtu: 1280,
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
        }
    }

    async fn parse_json_body<T: serde::de::DeserializeOwned>(response: axum::response::Response) -> T {
        let body_bytes = axum::body::to_bytes(response.into_body(), 1_048_576).await.expect("read body");
        serde_json::from_slice(&body_bytes).expect("parse json")
    }

    // ---- Password verification tests ----

    #[test]
    fn verify_password_correct() {
        let hash = test_password_hash();
        assert!(verify_password(TEST_PASSWORD, &hash).expect("no error"));
    }

    #[test]
    fn verify_password_wrong() {
        let hash = test_password_hash();
        assert!(!verify_password("wrong-password", &hash).expect("no error"));
    }

    #[test]
    fn verify_password_malformed_hash() {
        let result = verify_password("anything", "not-a-valid-hash");
        assert!(result.is_err());
    }

    // ---- JWT tests ----

    #[test]
    fn jwt_create_and_verify() {
        let secret = [0xCDu8; 32];
        let (token, expires_in) = create_token(&secret, DEFAULT_SESSION_TIMEOUT).expect("create token");
        assert_eq!(expires_in, DEFAULT_SESSION_TIMEOUT);
        assert!(!token.is_empty());

        let claims = verify_token(&secret, &token).expect("verify token");
        assert_eq!(claims.sub, ADMIN_USERNAME);
    }

    #[test]
    fn jwt_expired_token_rejected() {
        let secret = [0xCDu8; 32];
        // Create a token with 0 second timeout (already expired)
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let claims = Claims {
            sub: ADMIN_USERNAME.to_string(),
            exp: now - 120, // 2 minutes in the past (well beyond default leeway)
            iat: now - 180,
        };
        let token = jsonwebtoken::encode(&Header::new(JWT_ALGORITHM), &claims, &EncodingKey::from_secret(&secret)).expect("encode");

        let result = verify_token(&secret, &token);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid token"));
    }

    #[test]
    fn jwt_wrong_secret_rejected() {
        let secret_a = [0x01u8; 32];
        let secret_b = [0x02u8; 32];
        let (token, _) = create_token(&secret_a, DEFAULT_SESSION_TIMEOUT).expect("create");
        let result = verify_token(&secret_b, &token);
        assert!(result.is_err());
    }

    #[test]
    fn jwt_tampered_token_rejected() {
        let secret = [0xCDu8; 32];
        let (mut token, _) = create_token(&secret, DEFAULT_SESSION_TIMEOUT).expect("create");
        // Tamper with the last character
        let last = token.pop().unwrap();
        token.push(if last == 'A' { 'B' } else { 'A' });
        let result = verify_token(&secret, &token);
        assert!(result.is_err());
    }

    // ---- Login handler tests ----

    fn login_router(state: AppState) -> Router {
        Router::new().route("/api/v1/auth/login", post(login)).with_state(state)
    }

    #[tokio::test]
    async fn login_valid_credentials() {
        let state = test_app_state();
        let app = login_router(state);

        let body = serde_json::json!({"username": "admin", "password": TEST_PASSWORD});
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let login_resp: LoginResponse = parse_json_body(response).await;
        assert!(!login_resp.token.is_empty());
        assert_eq!(login_resp.expires_in, DEFAULT_SESSION_TIMEOUT);
    }

    #[tokio::test]
    async fn login_wrong_password() {
        let state = test_app_state();
        let app = login_router(state);

        let body = serde_json::json!({"username": "admin", "password": "wrong"});
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_wrong_username() {
        let state = test_app_state();
        let app = login_router(state);

        let body = serde_json::json!({"username": "root", "password": TEST_PASSWORD});
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ---- Auth middleware tests ----

    async fn protected_handler() -> Json<serde_json::Value> {
        Json(serde_json::json!({"status": "ok"}))
    }

    fn auth_test_router(state: AppState) -> Router {
        Router::new()
            .route("/protected", get(protected_handler))
            .layer(axum::middleware::from_fn_with_state(state.clone(), require_auth))
            .with_state(state)
    }

    #[tokio::test]
    async fn auth_rejects_no_token() {
        let state = test_app_state();
        let app = auth_test_router(state);

        let request = Request::builder().method("GET").uri("/protected").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_rejects_invalid_token() {
        let state = test_app_state();
        let app = auth_test_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/protected")
            .header("authorization", "Bearer invalid-token-here")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_accepts_valid_token() {
        let state = test_app_state();
        let (token, _) = create_token(&state.jwt_secret, state.session_timeout).expect("create token");
        let app = auth_test_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/protected")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
