// FRD: specs/frds/FRD-P007.md

//! Single-page application handler.
//!
//! Serves the embedded SPA HTML for all non-API routes, enabling
//! client-side hash routing in the browser.

use axum::response::Html;

/// Embedded SPA HTML (Preact + HTM from CDN, single file).
const SPA_HTML: &str = include_str!("../../assets/index.html");

/// Expected CDN host in the SPA HTML (used in tests).
#[cfg(test)]
const EXPECTED_CDN_HOST: &str = "esm.sh";

/// Expected app mount element ID (used in tests).
#[cfg(test)]
const EXPECTED_MOUNT_ID: &str = "app";

/// Expected page title substring (used in tests).
#[cfg(test)]
const EXPECTED_TITLE: &str = "prrr";

/// Serve the embedded SPA HTML.
///
/// Returns the full `index.html` with `Content-Type: text/html`.
/// Used for both `GET /` (root) and the router fallback (all
/// unmatched paths) to support client-side routing.
pub async fn spa_handler() -> Html<&'static str> {
    Html(SPA_HTML)
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-P007.md
    use super::*;
    use axum::response::IntoResponse;

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
}
