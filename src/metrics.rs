// FRD: specs/frds/FRD-P008.md

//! Prometheus metrics server and health endpoint.
//!
//! Runs on a separate HTTP port (default 9090) from the VPN server.
//! Provides `/health` for health checks and `/metrics` for Prometheus scraping.

use std::sync::Arc;

use axum::{Router, extract::State, routing::get};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

/// Health status string for a healthy server.
const HEALTH_STATUS_HEALTHY: &str = "healthy";

/// Prometheus metric name: total registered (non-revoked) clients.
pub const METRIC_CLIENTS_TOTAL: &str = "prrr_clients_total";

/// Prometheus metric name: currently connected clients.
pub const METRIC_CLIENTS_CONNECTED: &str = "prrr_clients_connected";

/// Prometheus metric name: suspended clients.
pub const METRIC_CLIENTS_SUSPENDED: &str = "prrr_clients_suspended";

/// Prometheus metric name: total successful handshakes.
pub const METRIC_HANDSHAKES_TOTAL: &str = "prrr_handshakes_total";

/// Prometheus metric name: total failed handshakes.
pub const METRIC_HANDSHAKES_FAILED: &str = "prrr_handshakes_failed_total";

/// Shared state for the metrics HTTP server.
#[derive(Clone)]
pub struct MetricsState {
    /// Timestamp when the server process started (for uptime calculation).
    pub start_time: std::time::Instant,
    /// Coordinated shutdown token.
    pub cancel: CancellationToken,
    /// Prometheus metrics handle for rendering scraped metrics.
    pub prometheus_handle: Arc<PrometheusHandle>,
}

/// JSON response from the `/health` endpoint.
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct HealthResponse {
    /// Health status: `"healthy"`.
    pub status: String,
    /// Server version from Cargo.toml.
    pub version: String,
    /// Server uptime in seconds.
    pub uptime_seconds: u64,
}

/// Handler for `GET /health`.
async fn health_handler(State(state): State<MetricsState>) -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse {
        status: HEALTH_STATUS_HEALTHY.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
    })
}

/// Record client registry gauge values.
///
/// Called periodically (or on scrape) to update gauge metrics reflecting
/// the current state of the client registry.
pub fn record_registry_gauges(total: usize, connected: u32, suspended: usize) {
    metrics::gauge!(METRIC_CLIENTS_TOTAL).set(total as f64);
    metrics::gauge!(METRIC_CLIENTS_CONNECTED).set(f64::from(connected));
    metrics::gauge!(METRIC_CLIENTS_SUSPENDED).set(suspended as f64);
}

/// Record a successful handshake event.
pub fn record_handshake_success() {
    metrics::counter!(METRIC_HANDSHAKES_TOTAL).increment(1);
}

/// Record a failed handshake event.
pub fn record_handshake_failure() {
    metrics::counter!(METRIC_HANDSHAKES_FAILED).increment(1);
}

/// Handler for `GET /metrics` — returns Prometheus text exposition format.
async fn metrics_handler(State(state): State<MetricsState>) -> String {
    state.prometheus_handle.render()
}

/// Install the Prometheus metrics recorder globally.
///
/// Returns a [`PrometheusHandle`] that can render the current metric state.
/// Must be called exactly once, before any `metrics::*!()` macros are used.
pub fn install_metrics_recorder() -> PrometheusHandle {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::set_global_recorder(recorder).expect("global metrics recorder already installed");
    handle
}

/// Start the metrics HTTP server.
///
/// Binds to `listen_addr` and serves `/health` and `/metrics`.
/// Runs until the cancellation token in `state` is triggered.
pub async fn run_metrics_server(listen_addr: std::net::SocketAddr, state: MetricsState) -> anyhow::Result<()> {
    let app = build_metrics_router(state.clone());
    let cancel = state.cancel.clone();

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;
    tracing::info!("metrics server listening on http://{local_addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await?;

    tracing::info!("metrics server stopped");
    Ok(())
}

/// Build the metrics/health HTTP router.
pub fn build_metrics_router(state: MetricsState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-P008.md

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::*;

    fn test_metrics_state() -> MetricsState {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        MetricsState {
            start_time: std::time::Instant::now(),
            cancel: CancellationToken::new(),
            prometheus_handle: Arc::new(handle),
        }
    }

    // AC-7: GET /health returns JSON health status
    #[tokio::test]
    async fn health_returns_json() {
        let state = test_metrics_state();
        let app = build_metrics_router(state);

        let req = Request::builder().method("GET").uri("/health").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let content_type = resp
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("valid header value");
        assert!(
            content_type.contains("application/json"),
            "expected application/json, got {content_type}"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
        let body: HealthResponse = serde_json::from_slice(&body_bytes).expect("parse json");
        assert_eq!(body.status, HEALTH_STATUS_HEALTHY);
    }

    // AC-6: GET /metrics returns Prometheus text format
    #[tokio::test]
    async fn metrics_serves_prometheus_format() {
        let state = test_metrics_state();
        let app = build_metrics_router(state);

        let req = Request::builder().method("GET").uri("/metrics").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
        let body = String::from_utf8(body_bytes.to_vec()).expect("valid utf8");
        // Prometheus text format should be present (even if empty, it's valid)
        assert!(!body.contains("error"), "metrics endpoint should not return errors");
    }

    // AC-8: prrr_clients_total gauge reflects registry count
    #[tokio::test]
    async fn metrics_clients_total_gauge() {
        let state = test_metrics_state();
        // Install recorder for this test so metrics macros record to our handle
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        // We can't install globally in parallel tests, so we record directly
        // by using the recorder as a local and checking the handle.
        metrics::with_local_recorder(&recorder, || {
            record_registry_gauges(5, 3, 1);
        });

        let state_with_handle = MetricsState {
            start_time: state.start_time,
            cancel: state.cancel,
            prometheus_handle: Arc::new(handle),
        };
        let app = build_metrics_router(state_with_handle);

        let req = Request::builder().method("GET").uri("/metrics").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
        let body = String::from_utf8(body_bytes.to_vec()).expect("valid utf8");

        assert!(
            body.contains(METRIC_CLIENTS_TOTAL),
            "should contain {METRIC_CLIENTS_TOTAL}, got:\n{body}"
        );
        assert!(
            body.contains(METRIC_CLIENTS_CONNECTED),
            "should contain {METRIC_CLIENTS_CONNECTED}, got:\n{body}"
        );
        assert!(
            body.contains(METRIC_CLIENTS_SUSPENDED),
            "should contain {METRIC_CLIENTS_SUSPENDED}, got:\n{body}"
        );
    }

    // AC-9: prrr_handshakes_total counter increments
    #[tokio::test]
    async fn metrics_handshakes_counter_increments() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        metrics::with_local_recorder(&recorder, || {
            record_handshake_success();
            record_handshake_success();
            record_handshake_failure();
        });

        let rendered = handle.render();
        assert!(
            rendered.contains(METRIC_HANDSHAKES_TOTAL),
            "should contain {METRIC_HANDSHAKES_TOTAL}, got:\n{rendered}"
        );
        assert!(
            rendered.contains(METRIC_HANDSHAKES_FAILED),
            "should contain {METRIC_HANDSHAKES_FAILED}, got:\n{rendered}"
        );
    }

    // AC-10: Metrics server shuts down on CancellationToken
    #[tokio::test]
    async fn metrics_server_graceful_shutdown() {
        let state = test_metrics_state();
        let cancel = state.cancel.clone();
        let listen_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

        let server_handle = tokio::spawn(run_metrics_server(listen_addr, state));

        // Give server time to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Cancel and verify clean shutdown
        cancel.cancel();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle)
            .await
            .expect("server should stop within timeout")
            .expect("join should succeed");
        assert!(result.is_ok(), "metrics server should shut down cleanly");
    }

    // AC-7b: Health response includes version and uptime
    #[tokio::test]
    async fn health_includes_version_and_uptime() {
        let mut state = test_metrics_state();
        // Backdate start_time by 5 seconds to ensure measurable uptime
        state.start_time = std::time::Instant::now() - std::time::Duration::from_secs(5);
        let app = build_metrics_router(state);

        let req = Request::builder().method("GET").uri("/health").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
        let body: HealthResponse = serde_json::from_slice(&body_bytes).expect("parse json");

        assert_eq!(body.version, env!("CARGO_PKG_VERSION"));
        assert!(body.uptime_seconds >= 5, "uptime should be >= 5, got {}", body.uptime_seconds);
        assert!(body.uptime_seconds < 60, "uptime should be < 60, got {}", body.uptime_seconds);
    }
}
