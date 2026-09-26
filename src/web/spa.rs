// FRD: specs/frds/FRD-P007.md, specs/frds/FRD-20260223-web-ui-logo-integration.md

//! Single-page application handler and embedded static assets.
//!
//! Serves the embedded SPA HTML for all non-API routes, enabling
//! client-side hash routing in the browser. Also serves logo images
//! as static assets embedded at compile time.

use axum::{
    http::header,
    response::{Html, IntoResponse},
};

/// Embedded SPA HTML (Preact + HTM from CDN, single file).
const SPA_HTML: &str = include_str!("../../assets/index.html");

/// Embedded cover landing page HTML ("PRRR Vision" surveillance company).
const COVER_HTML: &str = include_str!("../../assets/cover.html");

/// Embedded cat logo image (white, no text).
const LOGO_PNG: &[u8] = include_bytes!("../../assets/logo_w.png");

/// Embedded cat logo image with text.
const LOGO_TEXT_PNG: &[u8] = include_bytes!("../../assets/logo_w_text.png");

/// Content-Type header value for PNG images.
const PNG_CONTENT_TYPE: &str = "image/png";

/// Server header value mimicking nginx (DPI evasion).
const NGINX_SERVER_HEADER: &str = "nginx/1.24.0";

/// Cache-Control for the cover page.
const COVER_CACHE_CONTROL: &str = "public, max-age=3600";

/// Expected CDN host in the SPA HTML (used in tests).
#[cfg(test)]
const EXPECTED_CDN_HOST: &str = "esm.sh";

/// Expected app mount element ID (used in tests).
#[cfg(test)]
const EXPECTED_MOUNT_ID: &str = "app";

/// Expected page title substring (used in tests).
#[cfg(test)]
const EXPECTED_TITLE: &str = "prrr";

/// Serve the cover landing page with nginx-like response headers.
///
/// Returns `cover.html` with headers that make the server appear as a
/// standard nginx web server serving a legitimate business website.
pub async fn cover_handler() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::SERVER, NGINX_SERVER_HEADER),
            (header::HeaderName::from_static("x-content-type-options"), "nosniff"),
            (header::CACHE_CONTROL, COVER_CACHE_CONTROL),
        ],
        COVER_HTML,
    )
}

/// Serve the embedded SPA HTML.
///
/// Returns the full `index.html` with `Content-Type: text/html`.
/// Used for `GET /admin` and admin sub-routes.
pub async fn spa_handler() -> Html<&'static str> {
    Html(SPA_HTML)
}

/// Serve the embedded cat logo (`logo_w.png`).
///
/// Returns the PNG image with `Content-Type: image/png`.
/// Used for the sidebar brand and browser favicon.
pub async fn logo_handler() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, PNG_CONTENT_TYPE)], LOGO_PNG)
}

/// Serve the embedded cat logo with text (`logo_w_text.png`).
///
/// Returns the PNG image with `Content-Type: image/png`.
/// Used on the login page.
pub async fn logo_text_handler() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, PNG_CONTENT_TYPE)], LOGO_TEXT_PNG)
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-P007.md, specs/frds/FRD-20260223-web-ui-logo-integration.md
    use axum::response::IntoResponse;

    use super::*;

    #[tokio::test]
    async fn spa_handler_returns_html() {
        let response = spa_handler().await.into_response();
        assert_eq!(response.status(), 200);
        let content_type = response
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("valid header value");
        assert!(content_type.contains("text/html"), "expected text/html, got {content_type}");
    }

    #[tokio::test]
    async fn spa_html_contains_preact_import() {
        let response = spa_handler().await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 1_048_576).await.expect("read body");
        let html_str = std::str::from_utf8(&body).expect("valid utf-8");
        assert!(
            html_str.contains(EXPECTED_CDN_HOST),
            "SPA HTML must import from {EXPECTED_CDN_HOST}"
        );
    }

    #[tokio::test]
    async fn spa_html_contains_app_mount() {
        let response = spa_handler().await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 1_048_576).await.expect("read body");
        let html_str = std::str::from_utf8(&body).expect("valid utf-8");
        let mount_attr = format!("id=\"{EXPECTED_MOUNT_ID}\"");
        assert!(
            html_str.contains(&mount_attr),
            "SPA HTML must contain mount element with {mount_attr}"
        );
    }

    // P-009B: SPA contains Settings nav item
    #[tokio::test]
    async fn spa_html_contains_settings_nav() {
        let response = spa_handler().await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 1_048_576).await.expect("read body");
        let html_str = std::str::from_utf8(&body).expect("valid utf-8");
        assert!(html_str.contains("Settings"), "SPA HTML must contain Settings navigation item");
    }

    // P-009B: SPA contains QR code button
    #[tokio::test]
    async fn spa_html_contains_qr_button() {
        let response = spa_handler().await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 1_048_576).await.expect("read body");
        let html_str = std::str::from_utf8(&body).expect("valid utf-8");
        assert!(html_str.contains("Show QR Code"), "SPA HTML must contain Show QR Code button");
    }

    // P-009B: SPA contains Share URL button
    #[tokio::test]
    async fn spa_html_contains_share_url_button() {
        let response = spa_handler().await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 1_048_576).await.expect("read body");
        let html_str = std::str::from_utf8(&body).expect("valid utf-8");
        assert!(html_str.contains("Share URL"), "SPA HTML must contain Share URL button");
    }

    // P-009B: SPA contains Download Config button
    #[tokio::test]
    async fn spa_html_contains_download_config_button() {
        let response = spa_handler().await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 1_048_576).await.expect("read body");
        let html_str = std::str::from_utf8(&body).expect("valid utf-8");
        assert!(html_str.contains("Download Config"), "SPA HTML must contain Download Config button");
    }

    #[tokio::test]
    async fn spa_html_contains_title() {
        let response = spa_handler().await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 1_048_576).await.expect("read body");
        let html_str = std::str::from_utf8(&body).expect("valid utf-8");
        assert!(
            html_str.contains(&format!("<title>{EXPECTED_TITLE}")),
            "SPA HTML must contain <title> with '{EXPECTED_TITLE}'"
        );
    }

    // -----------------------------------------------------------------------
    // FRD: specs/frds/FRD-20260224-cover-page-handler.md
    // Step 2.2: Cover page handler
    // -----------------------------------------------------------------------

    /// Expected branding text in the cover HTML.
    const EXPECTED_COVER_BRANDING: &str = "PRRR Vision";

    // AC-1: cover_handler returns 200 with text/html containing "PRRR Vision"
    #[tokio::test]
    async fn cover_handler_returns_html() {
        let response = cover_handler().await.into_response();
        assert_eq!(response.status(), 200);
        let content_type = response
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("valid header value");
        assert!(content_type.contains("text/html"), "expected text/html, got {content_type}");
    }

    // AC-1b: cover handler body contains "PRRR Vision"
    #[tokio::test]
    async fn cover_handler_contains_branding() {
        let response = cover_handler().await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 1_048_576).await.expect("read body");
        let html_str = std::str::from_utf8(&body).expect("valid utf-8");
        assert!(
            html_str.contains(EXPECTED_COVER_BRANDING),
            "cover HTML must contain {EXPECTED_COVER_BRANDING}"
        );
    }

    // AC-2: cover handler response has Server: nginx/1.24.0 header
    #[tokio::test]
    async fn cover_handler_has_nginx_server_header() {
        let response = cover_handler().await.into_response();
        let server = response
            .headers()
            .get("server")
            .expect("server header")
            .to_str()
            .expect("valid header value");
        assert_eq!(server, NGINX_SERVER_HEADER, "Server header must be nginx/1.24.0");
    }

    // AC-2b: cover handler has X-Content-Type-Options: nosniff
    #[tokio::test]
    async fn cover_handler_has_nosniff_header() {
        let response = cover_handler().await.into_response();
        let xcto = response
            .headers()
            .get("x-content-type-options")
            .expect("x-content-type-options header")
            .to_str()
            .expect("valid header value");
        assert_eq!(xcto, "nosniff");
    }

    // AC-2c: cover handler has Cache-Control: public, max-age=3600
    #[tokio::test]
    async fn cover_handler_has_cache_control() {
        let response = cover_handler().await.into_response();
        let cc = response
            .headers()
            .get("cache-control")
            .expect("cache-control header")
            .to_str()
            .expect("valid header value");
        assert_eq!(cc, COVER_CACHE_CONTROL);
    }

    // --- Logo handler tests (FRD-20260223-web-ui-logo-integration) ---

    /// Expected size of logo_w.png in bytes.
    const EXPECTED_LOGO_SIZE: usize = 41_408;

    /// Expected size of logo_w_text.png in bytes.
    const EXPECTED_LOGO_TEXT_SIZE: usize = 84_620;

    // AC-1: logo_handler returns 200 with image/png
    #[tokio::test]
    async fn logo_handler_returns_png() {
        let response = logo_handler().await.into_response();
        assert_eq!(response.status(), 200);
        let content_type = response
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("valid header value");
        assert_eq!(content_type, PNG_CONTENT_TYPE, "expected image/png content type");
    }

    // AC-3: logo_handler body length matches embedded file size
    #[tokio::test]
    async fn logo_handler_body_size() {
        let response = logo_handler().await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 1_048_576).await.expect("read body");
        assert_eq!(body.len(), EXPECTED_LOGO_SIZE, "logo_w.png body size must match embedded file");
    }

    // AC-2: logo_text_handler returns 200 with image/png
    #[tokio::test]
    async fn logo_text_handler_returns_png() {
        let response = logo_text_handler().await.into_response();
        assert_eq!(response.status(), 200);
        let content_type = response
            .headers()
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("valid header value");
        assert_eq!(content_type, PNG_CONTENT_TYPE, "expected image/png content type");
    }

    // AC-4: logo_text_handler body length matches embedded file size
    #[tokio::test]
    async fn logo_text_handler_body_size() {
        let response = logo_text_handler().await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 1_048_576).await.expect("read body");
        assert_eq!(
            body.len(),
            EXPECTED_LOGO_TEXT_SIZE,
            "logo_w_text.png body size must match embedded file"
        );
    }

    // AC-5: SPA HTML sidebar contains logo img tag
    #[tokio::test]
    async fn spa_html_contains_logo_sidebar() {
        assert!(
            SPA_HTML.contains(r#"src="/assets/logo_w.png""#),
            "SPA HTML sidebar must reference /assets/logo_w.png"
        );
        assert!(SPA_HTML.contains(r#"alt="prrr""#), "SPA HTML logo must have alt=\"prrr\" attribute");
    }

    // AC-6: SPA HTML login page contains text logo img tag
    #[tokio::test]
    async fn spa_html_contains_logo_login() {
        assert!(
            SPA_HTML.contains(r#"src="/assets/logo_w_text.png""#),
            "SPA HTML login must reference /assets/logo_w_text.png"
        );
    }

    // AC-7: SPA HTML head contains favicon link
    #[tokio::test]
    async fn spa_html_contains_favicon() {
        assert!(SPA_HTML.contains(r#"rel="icon""#), "SPA HTML must contain favicon link element");
        assert!(
            SPA_HTML.contains("/assets/logo_w.png"),
            "SPA HTML favicon must reference /assets/logo_w.png"
        );
    }

    // --- Transport visibility tests (FRD-20260223-transport-visibility-ui) ---

    // AC-5: Settings page displays transport section
    #[tokio::test]
    async fn spa_html_contains_transport_section() {
        assert!(SPA_HTML.contains("Transports"), "SPA HTML Settings must contain Transports heading");
    }

    // AC-6: Dashboard displays HARP Sessions card
    #[tokio::test]
    async fn spa_html_contains_harp_session_card() {
        assert!(
            SPA_HTML.contains("HARP Sessions"),
            "SPA HTML Dashboard must contain HARP Sessions card"
        );
    }

    // AC-7 (Step 4): Client table has Transport column
    #[tokio::test]
    async fn spa_html_contains_transport_column() {
        assert!(
            SPA_HTML.contains("<th>Transport</th>"),
            "SPA HTML client table must contain Transport column header"
        );
    }

    // API object has getTransports method
    #[tokio::test]
    async fn spa_html_contains_get_transports_api() {
        assert!(SPA_HTML.contains("getTransports"), "SPA HTML API must contain getTransports method");
    }

    // --- Traffic stats UI tests (FRD-20260223-client-traffic-stats-ui) ---

    // AC-1/AC-2/AC-3: formatBytes helper exists in SPA
    #[tokio::test]
    async fn spa_html_contains_format_bytes() {
        assert!(
            SPA_HTML.contains("formatBytes"),
            "SPA HTML must contain formatBytes helper function"
        );
    }

    // AC-4: Client table has Traffic column header
    #[tokio::test]
    async fn spa_html_contains_traffic_column() {
        assert!(
            SPA_HTML.contains("<th>Traffic</th>"),
            "SPA HTML client table must contain Traffic column header"
        );
    }

    // AC-5: Client table shows formatted bytes per row
    #[tokio::test]
    async fn spa_html_contains_traffic_cell() {
        assert!(
            SPA_HTML.contains("c.bytes_sent"),
            "SPA HTML must reference bytes_sent in client table"
        );
        assert!(
            SPA_HTML.contains("c.bytes_received"),
            "SPA HTML must reference bytes_received in client table"
        );
    }

    // AC-6: Dashboard has Total Sent card
    #[tokio::test]
    async fn spa_html_contains_total_sent_card() {
        assert!(SPA_HTML.contains("Total Sent"), "SPA HTML Dashboard must contain Total Sent card");
    }

    // AC-7: Dashboard has Total Received card
    #[tokio::test]
    async fn spa_html_contains_total_received_card() {
        assert!(
            SPA_HTML.contains("Total Received"),
            "SPA HTML Dashboard must contain Total Received card"
        );
    }

    // API object has getTrafficStats method
    #[tokio::test]
    async fn spa_html_contains_get_traffic_stats_api() {
        assert!(
            SPA_HTML.contains("getTrafficStats"),
            "SPA HTML API must contain getTrafficStats method"
        );
    }

    // --- HARP Session Management UI tests (FRD-20260223-harp-session-management-ui) ---

    // AC-6: Sessions page exists at #/sessions route
    #[tokio::test]
    async fn spa_html_contains_sessions_route() {
        assert!(SPA_HTML.contains("#/sessions"), "SPA HTML must contain #/sessions route");
    }

    // AC-7: Sessions table has correct column headers
    #[tokio::test]
    async fn spa_html_contains_sessions_table_headers() {
        assert!(SPA_HTML.contains("<th>Session ID</th>"), "SPA must have Session ID column");
        assert!(SPA_HTML.contains("<th>Started</th>"), "SPA must have Started column");
        assert!(SPA_HTML.contains("<th>Last Active</th>"), "SPA must have Last Active column");
        assert!(SPA_HTML.contains("<th>Idle</th>"), "SPA must have Idle column");
    }

    // AC-8: Sidebar has "Sessions" nav item
    #[tokio::test]
    async fn spa_html_contains_sessions_nav_item() {
        assert!(SPA_HTML.contains(r#"Sessions"#), "SPA sidebar must contain Sessions nav item");
        assert!(SPA_HTML.contains("SessionsPage"), "SPA must contain SessionsPage component");
    }

    // AC-9: Terminate button exists in session rows
    #[tokio::test]
    async fn spa_html_contains_terminate_button() {
        assert!(SPA_HTML.contains("Terminate"), "SPA Sessions page must contain Terminate button");
    }

    // AC-10: Session count badge shown in sidebar
    #[tokio::test]
    async fn spa_html_contains_session_count_badge() {
        assert!(
            SPA_HTML.contains("sessionCount"),
            "SPA sidebar must reference sessionCount for badge"
        );
    }

    // API object has getHarpSessions method
    #[tokio::test]
    async fn spa_html_contains_get_harp_sessions_api() {
        assert!(
            SPA_HTML.contains("getHarpSessions"),
            "SPA HTML API must contain getHarpSessions method"
        );
    }

    // API object has terminateHarpSession method
    #[tokio::test]
    async fn spa_html_contains_terminate_harp_session_api() {
        assert!(
            SPA_HTML.contains("terminateHarpSession"),
            "SPA HTML API must contain terminateHarpSession method"
        );
    }

    // Sessions page shows "Active HARP Sessions" table title
    #[tokio::test]
    async fn spa_html_contains_active_harp_sessions_title() {
        assert!(
            SPA_HTML.contains("Active HARP Sessions"),
            "SPA Sessions page must contain 'Active HARP Sessions' table title"
        );
    }

    // Sessions page shows "No active sessions." empty state
    #[tokio::test]
    async fn spa_html_contains_sessions_empty_state() {
        assert!(
            SPA_HTML.contains("No active sessions."),
            "SPA Sessions page must contain empty state message"
        );
    }
}
