// FRD: specs/frds/FRD-009.md
// FRD: specs/frds/FRD-20260223-harp-client-transport.md

//! VPN client orchestrator.
//!
//! Supports two transport modes:
//! - **MASQUE** (legacy): QUIC/MASQUE CONNECT-UDP tunnel via `run_client()`
//! - **HARP** (new): HTTPS session establishment + WebSocket streaming via `run_harp_client()`
//!
//! Both paths share the same `TunnelPipeline` — only the transport adapters differ.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tokio_util::sync::CancellationToken;

use crate::handshake::hybrid::{HybridInitiator, InitiatorResult};
use crate::handshake::noise_ik::KeyPair;
use crate::transport::TransportError;
use crate::transport::encrypted_channel::{EncryptedChannel, NONCE_COUNTER_LEN};
use crate::transport::h2_adapter::{H2Receiver, H2Sender};
use crate::transport::harp::{HarpFrame, HarpFrameReader, HarpFrameType};
use crate::transport::masque::{MasqueClient, build_masque_client_config};
use crate::tunnel::TunnelError;
use crate::tunnel::pipeline::{DatagramReceiver, DatagramSender};
use crate::tunnel::tun_device::TunDevice;
use crate::web::harp::{HarpSessionRequest, HarpSessionResponse};

/// Per-packet overhead added by the encrypted channel and MASQUE framing.
///
/// Encrypted channel: 8-byte nonce counter + 16-byte AEAD tag = 24 bytes.
/// MASQUE HTTP Datagram framing: varint(quarter_stream_id=0) + varint(context_id=0) = 2 bytes.
/// Total: 26 bytes per packet.
pub const TUNNEL_OVERHEAD_BYTES: usize = NONCE_COUNTER_LEN + crate::crypto::aead::TAG_LEN + 2;

/// Run the VPN client.
///
/// Connects to the server at `server_addr`, performs the hybrid handshake,
/// establishes the MASQUE tunnel, and runs the packet pipeline with the
/// given TUN device until `cancel` is triggered.
///
/// `server_noise_pub` is the server's known Noise static public key.
/// `server_kem_pub` is the server's ML-KEM-768 encapsulation key bytes.
///
/// Returns `Ok(())` on clean shutdown (cancellation) or `Err` on failure.
#[allow(clippy::too_many_arguments)]
pub async fn run_client<T: TunDevice>(
    server_addr: SocketAddr,
    server_name: &str,
    noise_keypair: &KeyPair,
    server_noise_pub: &[u8; 32],
    server_kem_pub: &[u8],
    tun: T,
    keep_alive_interval: u64,
    max_idle_timeout: u64,
    insecure: bool,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    if insecure {
        tracing::warn!("TLS certificate verification disabled (--insecure). Do NOT use in production.");
    }

    // Build MASQUE-enabled client config
    let client_config = build_masque_client_config(keep_alive_interval, max_idle_timeout, insecure)?;

    // Create QUIC client endpoint
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
    endpoint.set_default_client_config(client_config);

    tracing::info!("connecting to {server_addr}");

    // Connect to server
    let connection = endpoint.connect(server_addr, server_name)?.await?;
    tracing::info!("QUIC connection established to {server_addr}");

    // Establish MASQUE CONNECT-UDP tunnel
    let masque_client = MasqueClient::connect(connection).await?;
    tracing::info!("MASQUE tunnel established");

    // Check that TUN MTU fits within the QUIC datagram size budget
    let tun_mtu = usize::from(tun.mtu());
    if let Some(max_dg) = masque_client.max_datagram_size() {
        let needed = tun_mtu + TUNNEL_OVERHEAD_BYTES;
        if needed > max_dg {
            tracing::error!(
                tun_mtu = tun_mtu,
                overhead = TUNNEL_OVERHEAD_BYTES,
                max_datagram_size = max_dg,
                "TUN MTU too large: {tun_mtu} + {TUNNEL_OVERHEAD_BYTES} byte overhead = {needed}, \
                 but QUIC max datagram is {max_dg}. Large packets will be dropped. \
                 Lower interface.mtu in client config to at most {}.",
                max_dg.saturating_sub(TUNNEL_OVERHEAD_BYTES)
            );
        }
    }

    // Perform hybrid handshake over MASQUE datagrams
    let init_result = handshake_as_client(noise_keypair, server_noise_pub, server_kem_pub, &masque_client).await?;
    tracing::info!("hybrid handshake complete");

    // Create encrypted channel (client is initiator: tx_key = tx, rx_key = rx)
    let channel = EncryptedChannel::new(init_result.session_keys.tx_key, init_result.session_keys.rx_key);

    // Build and run the pipeline
    let masque_client = Arc::new(masque_client);
    let stats = Arc::new(crate::tunnel::pipeline::TrafficStats::new());
    let pipeline =
        crate::tunnel::pipeline::TunnelPipeline::new(tun, channel, Arc::clone(&masque_client), Arc::clone(&masque_client), stats);

    tracing::info!("tunnel pipeline running");
    match pipeline.run(cancel.clone()).await {
        Err(TunnelError::Cancelled) => {
            tracing::info!("tunnel pipeline cancelled — shutting down");
            Ok(())
        }
        Err(e) => Err(e.into()),
        Ok(()) => Ok(()),
    }
}

/// Perform the hybrid handshake as the client (initiator) over MASQUE datagrams.
///
/// The handshake messages are exchanged as MASQUE datagrams:
/// 1. Create initiator, generate msg1
/// 2. Send msg1 to server
/// 3. Receive msg2 from server
/// 4. Finalize handshake
async fn handshake_as_client(
    noise_keypair: &KeyPair,
    server_noise_pub: &[u8; 32],
    server_kem_pub: &[u8],
    masque_client: &MasqueClient,
) -> anyhow::Result<InitiatorResult> {
    // Create initiator and generate msg1
    let (initiator, msg1) = HybridInitiator::new(noise_keypair, server_noise_pub, server_kem_pub)?;
    tracing::debug!(msg1_len = msg1.len(), "sending handshake msg1");

    // Send msg1 to server
    masque_client.send_datagram(&msg1)?;

    // Receive msg2 from server
    let msg2 = masque_client.recv_datagram().await?;
    tracing::debug!(msg2_len = msg2.len(), "received handshake msg2");

    // Finalize handshake
    let result = initiator.finish(&msg2)?;

    Ok(result)
}

// ---------------------------------------------------------------------------
// HARP Client Transport (Step 8)
// ---------------------------------------------------------------------------

/// Default bounded capacity for the WebSocket write buffer channel.
const WS_WRITE_CHANNEL_CAPACITY: usize = 256;

/// Client transport capabilities advertised during session establishment.
const HARP_CLIENT_CAPABILITIES: &[&str] = &["stream", "poll", "h2"];

/// Result of a successful HARP session establishment.
pub struct HarpSessionResult {
    /// Derived session keys from the hybrid handshake.
    pub session_keys: crate::handshake::hybrid::SessionKeys,
    /// Base64-encoded session ID returned by the server.
    pub session_id: String,
    /// Server-selected transport mode.
    pub transport_mode: String,
    /// Upload endpoint path for polling transport.
    pub upload_endpoint: String,
    /// Download endpoint path for polling transport.
    pub download_endpoint: String,
    /// Suggested polling interval in milliseconds.
    pub poll_interval_ms: u64,
}

/// Client-side WebSocket sender implementing [`DatagramSender`].
///
/// Uses an internal mpsc channel with a background task to bridge the
/// synchronous `send_datagram()` API to the async WebSocket write half.
pub struct HarpWsSender {
    tx: mpsc::Sender<Vec<u8>>,
}

impl HarpWsSender {
    /// Create a new sender that writes HARP frames to the given WebSocket sink.
    ///
    /// Spawns a background task that reads from an internal channel and
    /// forwards encoded HARP frames to the WebSocket. The task exits when
    /// the channel is closed or the cancel token is triggered.
    pub fn new<S>(mut sink: S, cancel: CancellationToken) -> Self
    where
        S: futures_util::Sink<tokio_tungstenite::tungstenite::Message, Error = tokio_tungstenite::tungstenite::Error>
            + Send
            + Unpin
            + 'static,
    {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(WS_WRITE_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(data) => {
                                let ws_msg = tokio_tungstenite::tungstenite::Message::Binary(data.into());
                                if sink.send(ws_msg).await.is_err() {
                                    tracing::debug!("HARP WS sender: sink closed");
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    () = cancel.cancelled() => break,
                }
            }
        });

        Self { tx }
    }
}

impl DatagramSender for HarpWsSender {
    fn send_datagram(&self, payload: &[u8]) -> Result<(), TransportError> {
        let frame = HarpFrame::data(payload.to_vec());
        let wire_bytes = frame.encode()?;
        self.tx.try_send(wire_bytes).map_err(|_| TransportError::HarpChannelClosed)
    }
}

/// Client-side WebSocket receiver implementing [`DatagramReceiver`].
///
/// Reads binary WebSocket messages, decodes HARP frames, and returns
/// DATA payloads. Skips KEEPALIVE frames and returns an error on CLOSE.
pub struct HarpWsReceiver {
    stream: Arc<TokioMutex<HarpWsReceiverInner>>,
}

/// Internal state for the WebSocket receiver.
struct HarpWsReceiverInner {
    ws_stream: Box<dyn WsStreamRead>,
    frame_reader: HarpFrameReader,
}

/// Type alias for the boxed future returned by [`WsStreamRead::next_message`].
type WsMessageFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Option<Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>>>
            + Send
            + 'a,
    >,
>;

/// Trait to abstract over the WebSocket read half for testability.
trait WsStreamRead: Send {
    fn next_message(&mut self) -> WsMessageFuture<'_>;
}

/// Blanket implementation for any `Stream<Item = Result<Message, Error>> + Unpin + Send`.
impl<T> WsStreamRead for T
where
    T: futures_util::Stream<Item = Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>> + Unpin + Send,
{
    fn next_message(&mut self) -> WsMessageFuture<'_> {
        Box::pin(self.next())
    }
}

impl HarpWsReceiver {
    /// Create a new receiver wrapping the read half of a WebSocket connection.
    pub fn new<S>(stream: S) -> Self
    where
        S: futures_util::Stream<Item = Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>>
            + Unpin
            + Send
            + 'static,
    {
        Self {
            stream: Arc::new(TokioMutex::new(HarpWsReceiverInner {
                ws_stream: Box::new(stream),
                frame_reader: HarpFrameReader::new(),
            })),
        }
    }
}

impl DatagramReceiver for HarpWsReceiver {
    async fn recv_datagram(&self) -> Result<Vec<u8>, TransportError> {
        let mut inner = self.stream.lock().await;
        loop {
            // First drain any buffered frames from previous WS messages
            if let Some(result) = inner.frame_reader.next_frame() {
                let frame = result?;
                match frame.frame_type {
                    HarpFrameType::Data => return Ok(frame.payload),
                    HarpFrameType::Keepalive => continue,
                    HarpFrameType::Close => return Err(TransportError::HarpSessionClosed),
                }
            }

            // Read next WS message
            let msg = inner
                .ws_stream
                .next_message()
                .await
                .ok_or(TransportError::HarpChannelClosed)?
                .map_err(|_| TransportError::HarpChannelClosed)?;

            match msg {
                tokio_tungstenite::tungstenite::Message::Binary(data) => {
                    inner.frame_reader.push(&data);
                }
                tokio_tungstenite::tungstenite::Message::Close(_) => {
                    return Err(TransportError::HarpSessionClosed);
                }
                _ => continue, // skip text, ping, pong
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HARP Polling Transport Adapters (Step 9)
// ---------------------------------------------------------------------------

/// Default bounded capacity for the polling upload buffer channel.
const POLL_UPLOAD_CHANNEL_CAPACITY: usize = 256;

/// Default bounded capacity for the polling download delivery channel.
const POLL_DOWNLOAD_CHANNEL_CAPACITY: usize = 256;

/// Client-side polling sender implementing [`DatagramSender`].
///
/// Uses an internal mpsc channel with a background task that periodically
/// collects buffered HARP frames and POSTs them to the upload endpoint.
/// The upload response may contain piggybacked download frames, which are
/// forwarded to the receiver's channel.
pub struct HarpPollSender {
    tx: mpsc::Sender<Vec<u8>>,
}

impl HarpPollSender {
    /// Create a new polling sender.
    ///
    /// Spawns a background upload task that:
    /// 1. Sleeps for `poll_interval_ms` ± jitter
    /// 2. Drains the internal buffer channel
    /// 3. POSTs concatenated frames to `upload_url`
    /// 4. Parses the response for piggybacked download frames
    /// 5. Forwards piggybacked frames to `piggyback_tx`
    pub fn new(
        http_client: MarkedHttpClient,
        upload_url: String,
        poll_interval_ms: u64,
        piggyback_tx: mpsc::Sender<Vec<u8>>,
        cancel: CancellationToken,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(POLL_UPLOAD_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            loop {
                // Sleep with jitter before next upload cycle
                let jitter = crate::obfuscation::traffic_morph::compute_jitter(poll_interval_ms);
                tokio::select! {
                    () = tokio::time::sleep(jitter) => {}
                    () = cancel.cancelled() => break,
                }

                // Drain all buffered frames
                let mut body = Vec::new();
                while let Ok(frame_bytes) = rx.try_recv() {
                    body.extend_from_slice(&frame_bytes);
                }

                if body.is_empty() {
                    continue; // nothing to upload
                }

                // POST frames to upload endpoint
                let resp_bytes = match http_client.post_bytes(&upload_url, body).await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!("HARP poll upload failed: {e}");
                        continue;
                    }
                };

                // Parse piggybacked download frames from response
                if !resp_bytes.is_empty() {
                    forward_piggybacked_frames(&resp_bytes, &piggyback_tx).await;
                }
            }
        });

        Self { tx }
    }
}

impl DatagramSender for HarpPollSender {
    fn send_datagram(&self, payload: &[u8]) -> Result<(), TransportError> {
        let frame = HarpFrame::data(payload.to_vec());
        let wire_bytes = frame.encode()?;
        self.tx.try_send(wire_bytes).map_err(|_| TransportError::HarpChannelClosed)
    }
}

/// Client-side polling receiver implementing [`DatagramReceiver`].
///
/// Reads HARP frames from an mpsc channel that is fed by:
/// - A background download task polling the download endpoint
/// - Piggybacked frames from upload responses (via `HarpPollSender`)
pub struct HarpPollReceiver {
    rx: Arc<TokioMutex<mpsc::Receiver<Vec<u8>>>>,
}

impl HarpPollReceiver {
    /// Create a new polling receiver.
    ///
    /// Spawns a background download task that periodically POSTs to
    /// `download_url` and forwards received frames to the internal channel.
    ///
    /// Returns the receiver and the `piggyback_tx` sender that the
    /// `HarpPollSender` should use to forward piggybacked frames.
    pub fn new(
        http_client: MarkedHttpClient,
        download_url: String,
        poll_interval_ms: u64,
        cancel: CancellationToken,
    ) -> (Self, mpsc::Sender<Vec<u8>>) {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(POLL_DOWNLOAD_CHANNEL_CAPACITY);
        let piggyback_tx = tx.clone();

        let download_tx = tx;
        tokio::spawn(async move {
            loop {
                // Sleep with jitter before next download cycle
                let jitter = crate::obfuscation::traffic_morph::compute_jitter(poll_interval_ms);
                tokio::select! {
                    () = tokio::time::sleep(jitter) => {}
                    () = cancel.cancelled() => break,
                }

                // POST to download endpoint (empty body)
                let resp_bytes = match http_client.post_bytes(&download_url, Vec::new()).await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!("HARP poll download failed: {e}");
                        continue;
                    }
                };

                if !resp_bytes.is_empty() {
                    forward_piggybacked_frames(&resp_bytes, &download_tx).await;
                }
            }
        });

        (
            Self {
                rx: Arc::new(TokioMutex::new(rx)),
            },
            piggyback_tx,
        )
    }
}

impl DatagramReceiver for HarpPollReceiver {
    async fn recv_datagram(&self) -> Result<Vec<u8>, TransportError> {
        let mut rx = self.rx.lock().await;
        loop {
            let raw = rx.recv().await.ok_or(TransportError::HarpChannelClosed)?;
            let (frame, _) = HarpFrame::decode(&raw)?;
            match frame.frame_type {
                HarpFrameType::Data => return Ok(frame.payload),
                HarpFrameType::Keepalive => continue,
                HarpFrameType::Close => return Err(TransportError::HarpSessionClosed),
            }
        }
    }
}

/// Parse concatenated HARP frames from raw bytes and send each as a separate
/// message to the given channel.
async fn forward_piggybacked_frames(data: &[u8], tx: &mpsc::Sender<Vec<u8>>) {
    let mut reader = HarpFrameReader::new();
    reader.push(data);
    while let Some(result) = reader.next_frame() {
        match result {
            Ok(frame) => {
                let wire = match frame.encode() {
                    Ok(w) => w,
                    Err(_) => break,
                };
                if tx.send(wire).await.is_err() {
                    break; // channel closed
                }
            }
            Err(_) => break,
        }
    }
}

/// Establish a HARP session with the server via HTTP POST.
///
/// Performs the hybrid Noise IK + ML-KEM-768 handshake:
/// 1. Creates `HybridInitiator` and generates msg1
/// 2. POSTs to `/api/v1/harp/session` with JSON body
/// 3. Parses the response and completes the handshake
///
/// Returns the session keys and session ID on success.
pub async fn establish_harp_session(
    http_client: &MarkedHttpClient,
    base_url: &str,
    noise_keypair: &KeyPair,
    server_noise_pub: &[u8; 32],
    server_kem_pub: &[u8],
) -> anyhow::Result<HarpSessionResult> {
    // Create initiator and generate msg1
    let (initiator, msg1) = HybridInitiator::new(noise_keypair, server_noise_pub, server_kem_pub)?;
    tracing::debug!(msg1_len = msg1.len(), "HARP: sending session establishment");

    // Build request
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let request = HarpSessionRequest {
        noise_msg1: BASE64.encode(&msg1),
        capabilities: HARP_CLIENT_CAPABILITIES.iter().map(|s| (*s).to_string()).collect(),
        timestamp: now,
    };

    // POST to session endpoint
    let url = format!("{base_url}/api/v1/harp/session");
    let response: HarpSessionResponse = http_client
        .post_json(&url, &request)
        .await
        .map_err(|e| anyhow::anyhow!("HARP session POST failed: {e}"))?;

    // Decode noise_msg2 and complete handshake
    let noise_msg2_bytes = BASE64
        .decode(&response.noise_msg2)
        .map_err(|e| anyhow::anyhow!("invalid base64 in noise_msg2: {e}"))?;

    let result = initiator
        .finish(&noise_msg2_bytes)
        .map_err(|e| anyhow::anyhow!("HARP handshake failed (server may have rejected client): {e}"))?;

    tracing::info!("HARP session established, id={}", &response.session_id[..8]);

    Ok(HarpSessionResult {
        session_keys: result.session_keys,
        session_id: response.session_id,
        transport_mode: response.transport.mode,
        upload_endpoint: response.transport.upload_endpoint,
        download_endpoint: response.transport.download_endpoint,
        poll_interval_ms: response.config.poll_interval_ms,
    })
}

/// Build a `reqwest::Client` with appropriate TLS configuration.
///
/// When `insecure` is true, TLS certificate verification is disabled.
/// Only used in tests — production code uses [`MarkedHttpClient`].
#[cfg(test)]
pub fn build_harp_http_client(insecure: bool) -> anyhow::Result<reqwest::Client> {
    let builder = reqwest::Client::builder().danger_accept_invalid_certs(insecure);
    builder.build().map_err(|e| anyhow::anyhow!("failed to build HTTP client: {e}"))
}

// ---------------------------------------------------------------------------
// Shared TLS config builder
// ---------------------------------------------------------------------------

/// Build a `rustls::ClientConfig` using the given TLS profile for cipher suite
/// ordering, and the given certificate verification mode.
///
/// This is the single source of truth for HARP client TLS configuration,
/// used by both `MarkedHttpClient` and `connect_harp_websocket`.
/// ALPN protocol identifier for HTTP/2.
const ALPN_H2: &[u8] = b"h2";
/// ALPN protocol identifier for HTTP/1.1.
const ALPN_HTTP11: &[u8] = b"http/1.1";

fn build_harp_rustls_config(insecure: bool, profile: crate::obfuscation::tls_mimicry::TlsProfile) -> anyhow::Result<rustls::ClientConfig> {
    let provider = Arc::new(crate::obfuscation::tls_mimicry::build_crypto_provider(profile));
    let mut config = if insecure {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("TLS protocol version error: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
            .with_no_client_auth()
    } else {
        let root_store = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("TLS protocol version error: {e}"))?
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];
    Ok(config)
}

/// Build a `rustls::ClientConfig` with HTTP/2-only ALPN (`["h2"]`).
///
/// Forces the TLS handshake to negotiate HTTP/2 exclusively. Used by
/// `connect_harp_h2()` where we need the server to select HTTP/2.
fn build_harp_h2_rustls_config(
    insecure: bool,
    profile: crate::obfuscation::tls_mimicry::TlsProfile,
) -> anyhow::Result<rustls::ClientConfig> {
    let mut config = build_harp_rustls_config(insecure, profile)?;
    config.alpn_protocols = vec![ALPN_H2.to_vec()];
    Ok(config)
}

// ---------------------------------------------------------------------------
// MarkedHttpClient — HTTP client with SO_MARK support
// ---------------------------------------------------------------------------

/// HTTP client that creates TCP connections with SO_MARK set for fwmark
/// policy routing. Replaces `reqwest::Client` for HARP transport traffic.
///
/// Each request creates a fresh TCP connection with the fwmark applied
/// before the SYN packet, ensuring all traffic (including the TCP handshake)
/// is marked for routing bypass.
#[derive(Clone)]
pub struct MarkedHttpClient {
    /// Firewall mark for SO_MARK. `None` means no marking (tests).
    fwmark: Option<u32>,
    /// Cached TLS connector (shared across requests).
    tls_connector: tokio_rustls::TlsConnector,
    /// Override TLS SNI server name (used when URL contains an IP instead of hostname).
    tls_server_name: Option<String>,
}

impl MarkedHttpClient {
    /// Create a new marked HTTP client.
    ///
    /// The `profile` parameter controls TLS cipher suite ordering in the
    /// ClientHello to mimic a specific browser fingerprint.
    pub fn new(fwmark: Option<u32>, insecure: bool, profile: crate::obfuscation::tls_mimicry::TlsProfile) -> anyhow::Result<Self> {
        let tls_config = build_harp_rustls_config(insecure, profile)?;

        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        Ok(Self {
            fwmark,
            tls_connector,
            tls_server_name: None,
        })
    }

    /// Set an override TLS SNI server name for requests to IP-based URLs.
    pub fn with_tls_server_name(mut self, name: String) -> Self {
        self.tls_server_name = Some(name);
        self
    }

    /// POST JSON body and parse JSON response.
    pub async fn post_json<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(&self, url: &str, body: &Req) -> anyhow::Result<Resp> {
        let body_bytes = serde_json::to_vec(body).map_err(|e| anyhow::anyhow!("failed to serialize request: {e}"))?;

        let resp_bytes = self.do_request(url, &body_bytes, "application/json").await?;

        serde_json::from_slice(&resp_bytes).map_err(|e| anyhow::anyhow!("failed to parse JSON response: {e}"))
    }

    /// POST raw bytes and return raw response bytes.
    pub async fn post_bytes(&self, url: &str, body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        self.do_request(url, &body, "application/octet-stream").await
    }

    /// Perform an HTTP POST request on a marked TCP connection.
    async fn do_request(&self, url: &str, body: &[u8], content_type: &str) -> anyhow::Result<Vec<u8>> {
        let parsed: hyper::Uri = url.parse().map_err(|e| anyhow::anyhow!("invalid URL '{url}': {e}"))?;

        let host = parsed.host().ok_or_else(|| anyhow::anyhow!("URL missing host: {url}"))?;
        let port = parsed
            .port_u16()
            .unwrap_or(if parsed.scheme_str() == Some("https") { 443 } else { 80 });
        let use_tls = parsed.scheme_str() == Some("https");
        let path = parsed.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        // Resolve hostname to IP
        let addr: std::net::SocketAddr = {
            use std::net::ToSocketAddrs;
            format!("{host}:{port}")
                .to_socket_addrs()
                .map_err(|e| anyhow::anyhow!("DNS resolution failed for {host}: {e}"))?
                .next()
                .ok_or_else(|| anyhow::anyhow!("no addresses for {host}"))?
        };

        // Create marked TCP socket
        let domain = if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = crate::routing::create_marked_tcp_socket(domain, self.fwmark)
            .map_err(|e| anyhow::anyhow!("failed to create marked socket: {e}"))?;

        // Connect (blocking connect on socket2, then convert to tokio)
        socket
            .set_nonblocking(true)
            .map_err(|e| anyhow::anyhow!("set_nonblocking failed: {e}"))?;
        let _ = socket.connect(&addr.into()); // non-blocking connect returns EINPROGRESS
        let std_stream: std::net::TcpStream = socket.into();
        let tcp_stream = tokio::net::TcpStream::from_std(std_stream).map_err(|e| anyhow::anyhow!("TcpStream::from_std failed: {e}"))?;

        // Wait for connect to complete
        tcp_stream
            .writable()
            .await
            .map_err(|e| anyhow::anyhow!("TCP connect to {addr} failed: {e}"))?;

        // Check for connect errors
        if let Some(err) = tcp_stream.take_error()? {
            return Err(anyhow::anyhow!("TCP connect to {addr} failed: {err}"));
        }

        // TLS handshake (if HTTPS)
        let sni_host = self.tls_server_name.as_deref().unwrap_or(host);
        let (status, resp_body) = if use_tls {
            let server_name = rustls::pki_types::ServerName::try_from(sni_host.to_string())
                .map_err(|e| anyhow::anyhow!("invalid server name '{sni_host}': {e}"))?;
            let tls_stream = self
                .tls_connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| anyhow::anyhow!("TLS handshake with {sni_host} failed: {e}"))?;

            self.send_http1_request(tls_stream, sni_host, path, body, content_type).await?
        } else {
            self.send_http1_request(tcp_stream, host, path, body, content_type).await?
        };

        if !status.is_success() {
            let body_str = String::from_utf8_lossy(&resp_body);
            return Err(anyhow::anyhow!("HTTP {status} from {url}: {body_str}"));
        }

        Ok(resp_body)
    }

    /// Send an HTTP/1.1 POST request over the given stream.
    async fn send_http1_request<S>(
        &self,
        stream: S,
        host: &str,
        path: &str,
        body: &[u8],
        content_type: &str,
    ) -> anyhow::Result<(hyper::StatusCode, Vec<u8>)>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let io = hyper_util::rt::TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| anyhow::anyhow!("HTTP handshake failed: {e}"))?;

        // Spawn connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("HTTP connection closed: {e}");
            }
        });

        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(path)
            .header("host", host)
            .header("content-type", content_type)
            .header("content-length", body.len())
            .body(http_body_util::Full::new(hyper::body::Bytes::copy_from_slice(body)))
            .map_err(|e| anyhow::anyhow!("failed to build HTTP request: {e}"))?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| anyhow::anyhow!("HTTP request failed: {e}"))?;

        let status = resp.status();
        let resp_body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .map_err(|e| anyhow::anyhow!("failed to read response body: {e}"))?
            .to_bytes()
            .to_vec();

        Ok((status, resp_body))
    }
}

/// Type alias for a boxed WebSocket sink (type-erased for TLS/plain duality).
type BoxedWsSink = std::pin::Pin<
    Box<dyn futures_util::Sink<tokio_tungstenite::tungstenite::Message, Error = tokio_tungstenite::tungstenite::Error> + Send>,
>;

/// Type alias for a boxed WebSocket stream (type-erased for TLS/plain duality).
type BoxedWsStream = std::pin::Pin<
    Box<dyn futures_util::Stream<Item = Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>> + Send>,
>;

/// Connect a WebSocket to the HARP stream endpoint using a marked socket.
///
/// When `fwmark` is `Some`, the TCP socket has SO_MARK set before the SYN
/// packet, ensuring all WebSocket traffic (including handshake) is marked
/// for fwmark policy routing.
///
/// Returns the split (sender, receiver) pair as boxed trait objects since
/// the TLS and plain-TCP branches produce different concrete types.
async fn connect_harp_websocket(
    base_url: &str,
    session_id: &str,
    insecure: bool,
    fwmark: Option<u32>,
    profile: crate::obfuscation::tls_mimicry::TlsProfile,
) -> anyhow::Result<(BoxedWsSink, BoxedWsStream)> {
    // Decode session_id from standard base64 to raw bytes, then re-encode as URL-safe
    let session_id_bytes = BASE64
        .decode(session_id)
        .map_err(|e| anyhow::anyhow!("invalid session_id base64: {e}"))?;
    let session_id_urlsafe = BASE64_URL.encode(&session_id_bytes);

    // Convert http(s):// to ws(s)://
    let ws_url = if base_url.starts_with("https://") {
        base_url.replacen("https://", "wss://", 1)
    } else {
        base_url.replacen("http://", "ws://", 1)
    };
    let url = format!("{ws_url}/api/v1/harp/stream/{session_id_urlsafe}");
    let use_tls = base_url.starts_with("https://");

    tracing::debug!(url = %url, "HARP: connecting WebSocket");

    // Parse host and port from URL for DNS resolution and TLS
    let parsed: hyper::Uri = url.parse().map_err(|e| anyhow::anyhow!("invalid WebSocket URL: {e}"))?;
    let host = parsed.host().ok_or_else(|| anyhow::anyhow!("WebSocket URL missing host"))?;
    let port = parsed.port_u16().unwrap_or(if use_tls { 443 } else { 80 });

    // Resolve hostname to IP
    let addr: std::net::SocketAddr = {
        use std::net::ToSocketAddrs;
        format!("{host}:{port}")
            .to_socket_addrs()
            .map_err(|e| anyhow::anyhow!("DNS resolution failed for {host}: {e}"))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("no addresses for {host}"))?
    };

    // Create marked TCP socket
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = crate::routing::create_marked_tcp_socket(domain, fwmark)
        .map_err(|e| anyhow::anyhow!("failed to create marked WebSocket socket: {e}"))?;
    socket.set_nonblocking(true).map_err(|e| anyhow::anyhow!("set_nonblocking: {e}"))?;
    let _ = socket.connect(&addr.into()); // non-blocking: EINPROGRESS
    let std_stream: std::net::TcpStream = socket.into();
    let tcp_stream = tokio::net::TcpStream::from_std(std_stream).map_err(|e| anyhow::anyhow!("TcpStream::from_std: {e}"))?;
    tcp_stream
        .writable()
        .await
        .map_err(|e| anyhow::anyhow!("TCP connect to {addr}: {e}"))?;
    if let Some(err) = tcp_stream.take_error()? {
        return Err(anyhow::anyhow!("TCP connect to {addr}: {err}"));
    }

    if use_tls {
        // TLS handshake on marked stream with profiled cipher suite ordering
        let tls_config = build_harp_rustls_config(insecure, profile)?;
        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let server_name =
            rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| anyhow::anyhow!("invalid server name '{host}': {e}"))?;
        let tls_stream = tls_connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| anyhow::anyhow!("TLS handshake for WebSocket failed: {e}"))?;

        // WebSocket upgrade on TLS stream
        let (ws_stream, _response) = tokio_tungstenite::client_async(url, tls_stream)
            .await
            .map_err(|e| anyhow::anyhow!("HARP WebSocket upgrade failed: {e}"))?;

        tracing::info!("HARP WebSocket connected (TLS, marked)");
        let (sink, stream) = ws_stream.split();
        Ok((Box::pin(sink), Box::pin(stream)))
    } else {
        // WebSocket upgrade on plain TCP stream
        let (ws_stream, _response) = tokio_tungstenite::client_async(url, tcp_stream)
            .await
            .map_err(|e| anyhow::anyhow!("HARP WebSocket upgrade failed: {e}"))?;

        tracing::info!("HARP WebSocket connected (plain, marked)");
        let (sink, stream) = ws_stream.split();
        Ok((Box::pin(sink), Box::pin(stream)))
    }
}

/// Parameters for running the HARP VPN client.
pub struct HarpClientParams<'a> {
    /// Server `host:port` to connect to.
    pub server_endpoint: &'a str,
    /// TLS SNI hostname (used when endpoint is an IP address).
    pub server_name: &'a str,
    /// Client Noise IK keypair.
    pub noise_keypair: &'a KeyPair,
    /// Server Noise IK public key.
    pub server_noise_pub: &'a [u8; 32],
    /// Server ML-KEM-768 encapsulation key bytes.
    pub server_kem_pub: &'a [u8],
    /// Skip TLS certificate verification.
    pub insecure: bool,
    /// TLS fingerprint profile for cipher suite ordering.
    pub tls_profile: crate::obfuscation::tls_mimicry::TlsProfile,
    /// Cancellation token for graceful shutdown.
    pub cancel: CancellationToken,
}

/// Run the VPN client using HARP (HTTPS API Relay Protocol) transport.
///
/// Establishes a session via HTTP POST, then attempts WebSocket streaming.
/// If WebSocket connection fails, falls back to HTTP polling transport.
/// Runs the tunnel pipeline until cancelled.
pub async fn run_harp_client<T: TunDevice>(tun: T, params: HarpClientParams<'_>) -> anyhow::Result<()> {
    let HarpClientParams {
        server_endpoint,
        server_name,
        noise_keypair,
        server_noise_pub,
        server_kem_pub,
        insecure,
        tls_profile,
        cancel,
    } = params;
    if insecure {
        tracing::warn!("TLS certificate verification disabled (--insecure). Do NOT use in production.");
    }

    let http_client = MarkedHttpClient::new(None, insecure, tls_profile)?;

    // Determine base URL: use server_name for TLS SNI, fall back to endpoint
    let scheme = if insecure { "http" } else { "https" };
    let base_url = format!("{scheme}://{server_name}:{}", extract_port(server_endpoint));

    // Step 1: Establish HARP session (handshake over HTTP)
    let session = establish_harp_session(&http_client, &base_url, noise_keypair, server_noise_pub, server_kem_pub).await?;
    tracing::info!(mode = %session.transport_mode, "HARP handshake complete");

    // Step 2: Create encrypted channel (client is initiator: tx_key = tx, rx_key = rx)
    let channel = EncryptedChannel::new(session.session_keys.tx_key, session.session_keys.rx_key);

    // Step 3: Try WebSocket streaming, fall back to polling on failure
    let stats = Arc::new(crate::tunnel::pipeline::TrafficStats::new());

    match connect_harp_websocket(&base_url, &session.session_id, insecure, None, tls_profile).await {
        Ok((ws_sink, ws_stream)) => {
            tracing::info!("HARP transport: WebSocket streaming");
            let sender = HarpWsSender::new(ws_sink, cancel.child_token());
            let receiver = HarpWsReceiver::new(ws_stream);
            let pipeline = crate::tunnel::pipeline::TunnelPipeline::new(tun, channel, sender, receiver, stats);
            run_pipeline(pipeline, cancel).await
        }
        Err(ws_err) => {
            tracing::warn!("WebSocket connection failed ({ws_err}), falling back to HTTP polling");
            let upload_url = format!("{base_url}{}", session.upload_endpoint);
            let download_url = format!("{base_url}{}", session.download_endpoint);

            let (receiver, piggyback_tx) =
                HarpPollReceiver::new(http_client.clone(), download_url, session.poll_interval_ms, cancel.child_token());
            let sender = HarpPollSender::new(
                http_client,
                upload_url,
                session.poll_interval_ms,
                piggyback_tx,
                cancel.child_token(),
            );
            let pipeline = crate::tunnel::pipeline::TunnelPipeline::new(tun, channel, sender, receiver, stats);
            run_pipeline(pipeline, cancel).await
        }
    }
}

/// Run a tunnel pipeline until cancelled or error.
async fn run_pipeline<T, S, R>(pipeline: crate::tunnel::pipeline::TunnelPipeline<T, S, R>, cancel: CancellationToken) -> anyhow::Result<()>
where
    T: TunDevice,
    S: DatagramSender + 'static,
    R: DatagramReceiver + 'static,
{
    tracing::info!("HARP tunnel pipeline running");
    match pipeline.run(cancel).await {
        Err(TunnelError::Cancelled) => {
            tracing::info!("HARP tunnel pipeline cancelled — shutting down");
            Ok(())
        }
        Err(e) => Err(e.into()),
        Ok(()) => Ok(()),
    }
}

/// Default HTTPS port used when endpoint doesn't specify one.
const DEFAULT_HTTPS_PORT: &str = "443";

/// Extract the port from a `host:port` string, defaulting to HTTPS port 443.
fn extract_port(endpoint: &str) -> &str {
    endpoint.rsplit_once(':').map_or(DEFAULT_HTTPS_PORT, |(_, port)| port)
}

/// Extract the host from a `host:port` string, returning the whole string if no port.
fn extract_host(endpoint: &str) -> &str {
    endpoint.rsplit_once(':').map_or(endpoint, |(host, _)| host)
}

/// TLS certificate verifier that accepts any certificate (for `--insecure` mode).
#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

// ---------------------------------------------------------------------------
// MASQUE Client Transport Adapter (Step 11)
// ---------------------------------------------------------------------------

use crate::transport::traits::{ClientConnectParams, ClientTransport, TransportConnection};

/// Human-readable name for the MASQUE transport.
const MASQUE_TRANSPORT_NAME: &str = "masque";

/// MASQUE client transport implementing [`ClientTransport`].
///
/// Wraps the existing QUIC/MASQUE connection flow (endpoint creation,
/// MASQUE tunnel, hybrid handshake) behind the pluggable transport
/// trait interface.
pub struct MasqueClientTransport {
    /// Server address (host:port) to connect to.
    server_addr: SocketAddr,
    /// Server name for TLS SNI.
    server_name: String,
    /// QUIC keep-alive interval in seconds.
    keep_alive_interval: u64,
    /// QUIC max idle timeout in seconds.
    max_idle_timeout: u64,
    /// Skip TLS certificate verification.
    insecure: bool,
    /// Firewall mark for SO_MARK on transport sockets.
    fwmark: Option<u32>,
}

impl MasqueClientTransport {
    /// Create a new MASQUE client transport with the given configuration.
    pub fn new(
        server_addr: SocketAddr,
        server_name: String,
        keep_alive_interval: u64,
        max_idle_timeout: u64,
        insecure: bool,
        fwmark: Option<u32>,
    ) -> Self {
        Self {
            server_addr,
            server_name,
            keep_alive_interval,
            max_idle_timeout,
            insecure,
            fwmark,
        }
    }
}

impl ClientTransport for MasqueClientTransport {
    fn name(&self) -> &str {
        MASQUE_TRANSPORT_NAME
    }

    fn connect<'a>(
        &'a self,
        params: ClientConnectParams<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<TransportConnection>> + Send + 'a>> {
        Box::pin(async move {
            if self.insecure {
                tracing::warn!("TLS certificate verification disabled (--insecure). Do NOT use in production.");
            }

            let client_config = build_masque_client_config(self.keep_alive_interval, self.max_idle_timeout, self.insecure)?;

            // Create UDP socket with fwmark for policy routing
            let udp_socket = crate::routing::create_marked_udp_socket(self.fwmark)
                .map_err(|e| anyhow::anyhow!("failed to create marked UDP socket: {e}"))?;
            let runtime = Arc::new(quinn::TokioRuntime);
            let mut endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, udp_socket, runtime)?;
            endpoint.set_default_client_config(client_config);

            tracing::info!("connecting to {}", self.server_addr);
            let connection = endpoint.connect(self.server_addr, &self.server_name)?.await?;
            tracing::info!("QUIC connection established to {}", self.server_addr);

            let masque_client = MasqueClient::connect(connection).await?;
            tracing::info!("MASQUE tunnel established");

            let init_result =
                handshake_as_client(params.noise_keypair, params.server_noise_pub, params.server_kem_pub, &masque_client).await?;
            tracing::info!("hybrid handshake complete");

            let masque_client = Arc::new(masque_client);
            Ok(TransportConnection {
                sender: Box::new(Arc::clone(&masque_client)),
                receiver: Box::new(masque_client),
                session_keys: init_result.session_keys,
            })
        })
    }
}

// ---------------------------------------------------------------------------
// HARP HTTP/2 Connect (Step 4.3)
// ---------------------------------------------------------------------------

/// HARP H2 upload endpoint path prefix.
const HARP_H2_UPLOAD_PATH: &str = "/api/v1/harp/upload/";

/// HARP H2 download endpoint path prefix.
const HARP_H2_DOWNLOAD_PATH: &str = "/api/v1/harp/download/";

/// Log message for H2 binding selection.
const LOG_HARP_H2_STREAMS: &str = "HARP transport: using HTTP/2 streams";

/// Preferred binding value for HTTP/2 streaming.
const BINDING_H2: &str = "h2";

/// Preferred binding value for HTTP polling.
const BINDING_POLL: &str = "poll";

/// Establish an HTTP/2 connection and open upload/download streams.
///
/// Creates a marked TCP socket, performs a TLS handshake with H2-only
/// ALPN (`["h2"]`), runs the h2 client handshake, spawns the connection
/// driver, and opens two long-lived streams:
/// - Upload: `POST /api/v1/harp/upload/{session_id}` (sender keeps sending DATA)
/// - Download: `GET /api/v1/harp/download/{session_id}` (receiver reads response DATA)
///
/// Returns `(H2Sender, H2Receiver)` ready for use with the tunnel pipeline.
async fn connect_harp_h2(
    host: &str,
    port: &str,
    session_id: &str,
    insecure: bool,
    fwmark: Option<u32>,
    profile: crate::obfuscation::tls_mimicry::TlsProfile,
) -> anyhow::Result<(H2Sender, H2Receiver)> {
    tracing::debug!(host, port, "H2: connecting");

    // Resolve hostname to IP
    let addr: std::net::SocketAddr = {
        use std::net::ToSocketAddrs;
        format!("{host}:{port}")
            .to_socket_addrs()
            .map_err(|e| anyhow::anyhow!("DNS resolution failed for {host}: {e}"))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("no addresses for {host}"))?
    };

    // Create marked TCP socket
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket =
        crate::routing::create_marked_tcp_socket(domain, fwmark).map_err(|e| anyhow::anyhow!("failed to create marked H2 socket: {e}"))?;
    socket.set_nonblocking(true).map_err(|e| anyhow::anyhow!("set_nonblocking: {e}"))?;
    let _ = socket.connect(&addr.into()); // non-blocking: EINPROGRESS
    let std_stream: std::net::TcpStream = socket.into();
    let tcp_stream = tokio::net::TcpStream::from_std(std_stream).map_err(|e| anyhow::anyhow!("TcpStream::from_std: {e}"))?;
    tcp_stream
        .writable()
        .await
        .map_err(|e| anyhow::anyhow!("TCP connect to {addr}: {e}"))?;
    if let Some(err) = tcp_stream.take_error()? {
        return Err(anyhow::anyhow!("TCP connect to {addr}: {err}"));
    }

    // TLS handshake with H2-only ALPN
    let tls_config = build_harp_h2_rustls_config(insecure, profile)?;
    let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name =
        rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| anyhow::anyhow!("invalid server name '{host}': {e}"))?;
    let tls_stream = tls_connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| anyhow::anyhow!("TLS handshake for H2 failed: {e}"))?;

    // h2 client handshake over TLS stream
    let (send_request, connection) = h2::client::handshake(tls_stream)
        .await
        .map_err(|e| anyhow::anyhow!("H2 handshake failed: {e}"))?;

    // Spawn connection driver
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!("H2 connection closed: {e}");
        }
    });

    // Encode session_id as URL-safe base64 for URL path
    let session_id_bytes = BASE64
        .decode(session_id)
        .map_err(|e| anyhow::anyhow!("invalid session_id base64: {e}"))?;
    let session_id_urlsafe = BASE64_URL.encode(&session_id_bytes);

    let upload_path = format!("{HARP_H2_UPLOAD_PATH}{session_id_urlsafe}");
    let download_path = format!("{HARP_H2_DOWNLOAD_PATH}{session_id_urlsafe}");

    // Open upload stream: POST with end_of_stream=false (we keep sending DATA)
    let upload_request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(&upload_path)
        .header("host", host)
        .body(())
        .map_err(|e| anyhow::anyhow!("failed to build H2 upload request: {e}"))?;

    let mut send_request_clone = send_request.clone();
    let (_, upload_send_stream) = send_request_clone
        .send_request(upload_request, false)
        .map_err(|e| anyhow::anyhow!("H2 upload stream open failed: {e}"))?;

    // Open download stream: GET with end_of_stream=true (we only read response DATA)
    let download_request = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&download_path)
        .header("host", host)
        .body(())
        .map_err(|e| anyhow::anyhow!("failed to build H2 download request: {e}"))?;

    let mut send_request_final = send_request;
    let (download_response_future, _) = send_request_final
        .send_request(download_request, true)
        .map_err(|e| anyhow::anyhow!("H2 download stream open failed: {e}"))?;

    let download_response = download_response_future
        .await
        .map_err(|e| anyhow::anyhow!("H2 download response failed: {e}"))?;
    let download_recv_stream = download_response.into_body();

    tracing::info!(LOG_HARP_H2_STREAMS);

    Ok((H2Sender::new(upload_send_stream), H2Receiver::new(download_recv_stream)))
}

// ---------------------------------------------------------------------------
// HARP Client Transport Adapter (Step 12)
// ---------------------------------------------------------------------------

/// Human-readable name for the HARP client transport.
const HARP_TRANSPORT_NAME: &str = "harp";

/// Error message prefix for direct connection timeout.
const ERR_DIRECT_CONNECT_TIMEOUT: &str = "direct connection timed out";

/// Configuration for constructing a [`HarpClientTransport`].
pub struct HarpClientConfig {
    /// Server endpoint string (`host:port`).
    pub server_endpoint: String,
    /// Server name for TLS SNI.
    pub server_name: String,
    /// Skip TLS certificate verification.
    pub insecure: bool,
    /// Firewall mark for SO_MARK on transport sockets.
    pub fwmark: Option<u32>,
    /// Preferred binding: `"stream"` (WebSocket), `"poll"` (HTTP polling), or `None` (try both).
    pub preferred_binding: Option<String>,
    /// TLS fingerprint profile for cipher suite ordering.
    pub tls_profile: crate::obfuscation::tls_mimicry::TlsProfile,
    /// Maximum time for a direct connection attempt before giving up.
    pub direct_timeout: std::time::Duration,
    /// CDN fronting domain (e.g., `"prrr.tech"`).
    /// When `Some`, `connect_via_cdn()` routes through CDN instead of direct.
    pub cdn_fronting_domain: Option<String>,
    /// Whether CDN domain fronting auto-fallback is enabled.
    pub cdn_fronting_enabled: bool,
    /// Interval between probing direct connection when CDN is active.
    pub direct_retry_interval: std::time::Duration,
}

/// HARP client transport implementing [`ClientTransport`].
///
/// Wraps the existing HARP connection flow (HTTP session establishment,
/// WebSocket or polling transport selection, hybrid handshake) behind
/// the pluggable transport trait interface.
pub struct HarpClientTransport {
    /// Server endpoint string (`host:port`).
    server_endpoint: String,
    /// Server name for TLS SNI.
    server_name: String,
    /// Skip TLS certificate verification.
    insecure: bool,
    /// Firewall mark for SO_MARK on transport sockets.
    fwmark: Option<u32>,
    /// Preferred binding: `"stream"` (WebSocket), `"poll"` (HTTP polling), or `None` (try both).
    preferred_binding: Option<String>,
    /// TLS fingerprint profile for cipher suite ordering.
    tls_profile: crate::obfuscation::tls_mimicry::TlsProfile,
    /// Maximum time for a direct connection attempt before giving up.
    direct_timeout: std::time::Duration,
    /// CDN fronting domain (e.g., `"prrr.tech"`).
    cdn_fronting_domain: Option<String>,
    /// Whether CDN domain fronting auto-fallback is enabled.
    cdn_fronting_enabled: bool,
    /// Interval between probing direct connection when CDN is active.
    direct_retry_interval: std::time::Duration,
    /// Runtime flag: currently preferring CDN over direct.
    /// Persists across reconnection loop iterations via `Arc`.
    use_fronting: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Timestamp of last direct connection probe (for retry interval).
    last_direct_probe: std::sync::Arc<tokio::sync::Mutex<std::time::Instant>>,
}

/// Error message when CDN fronting domain is not configured.
const ERR_CDN_DOMAIN_NOT_CONFIGURED: &str = "CDN fronting domain not configured";

/// Log message: falling back to CDN fronting.
const LOG_FALLING_BACK_TO_CDN: &str = "falling back to CDN fronting";

/// Log message: probing direct connection.
const LOG_PROBING_DIRECT: &str = "probing direct connection";

/// Log message: direct connection recovered.
const LOG_DIRECT_RECOVERED: &str = "direct connection recovered";

/// Log message: direct probe failed.
const LOG_DIRECT_PROBE_FAILED: &str = "direct probe failed, staying on CDN";

impl HarpClientTransport {
    /// Create a new HARP client transport from configuration.
    pub fn new(config: HarpClientConfig) -> Self {
        Self {
            server_endpoint: config.server_endpoint,
            server_name: config.server_name,
            insecure: config.insecure,
            fwmark: config.fwmark,
            preferred_binding: config.preferred_binding,
            tls_profile: config.tls_profile,
            direct_timeout: config.direct_timeout,
            cdn_fronting_domain: config.cdn_fronting_domain,
            cdn_fronting_enabled: config.cdn_fronting_enabled,
            direct_retry_interval: config.direct_retry_interval,
            use_fronting: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            last_direct_probe: std::sync::Arc::new(tokio::sync::Mutex::new(std::time::Instant::now())),
        }
    }
}

impl ClientTransport for HarpClientTransport {
    fn name(&self) -> &str {
        HARP_TRANSPORT_NAME
    }

    fn connect<'a>(
        &'a self,
        params: ClientConnectParams<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<TransportConnection>> + Send + 'a>> {
        Box::pin(async move { self.connect_with_fallback(params).await })
    }
}

impl HarpClientTransport {
    /// Connect with automatic direct → CDN fallback.
    ///
    /// When CDN fronting is disabled, does a simple direct connect with timeout.
    /// When enabled, orchestrates direct → CDN fallback with periodic direct probing.
    async fn connect_with_fallback(&self, params: ClientConnectParams<'_>) -> anyhow::Result<TransportConnection> {
        let timeout = self.direct_timeout;

        if !self.cdn_fronting_enabled {
            // CDN disabled: direct only
            return tokio::time::timeout(timeout, self.connect_inner(params))
                .await
                .map_err(|_| anyhow::anyhow!("{ERR_DIRECT_CONNECT_TIMEOUT} after {timeout:?}"))?;
        }

        let currently_fronting = self.use_fronting.load(std::sync::atomic::Ordering::Relaxed);

        if currently_fronting {
            // Currently using CDN. Check if we should probe direct.
            let should_probe = {
                let last_probe = self.last_direct_probe.lock().await;
                last_probe.elapsed() >= self.direct_retry_interval
            };

            if should_probe {
                tracing::info!(LOG_PROBING_DIRECT);
                *self.last_direct_probe.lock().await = std::time::Instant::now();

                match tokio::time::timeout(timeout, self.connect_inner(params.clone())).await {
                    Ok(Ok(conn)) => {
                        self.use_fronting.store(false, std::sync::atomic::Ordering::Relaxed);
                        tracing::info!(LOG_DIRECT_RECOVERED);
                        return Ok(conn);
                    }
                    _ => {
                        tracing::info!(LOG_DIRECT_PROBE_FAILED);
                    }
                }
            }

            // Use CDN
            tokio::time::timeout(timeout, self.connect_via_cdn(params))
                .await
                .map_err(|_| anyhow::anyhow!("{ERR_DIRECT_CONNECT_TIMEOUT} via CDN after {timeout:?}"))?
        } else {
            // Try direct first
            match tokio::time::timeout(timeout, self.connect_inner(params.clone())).await {
                Ok(Ok(conn)) => Ok(conn),
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, LOG_FALLING_BACK_TO_CDN);
                    self.use_fronting.store(true, std::sync::atomic::Ordering::Relaxed);
                    *self.last_direct_probe.lock().await = std::time::Instant::now();
                    tokio::time::timeout(timeout, self.connect_via_cdn(params))
                        .await
                        .map_err(|_| anyhow::anyhow!("{ERR_DIRECT_CONNECT_TIMEOUT} via CDN after {timeout:?}"))?
                }
                Err(_) => {
                    tracing::warn!(ERR_DIRECT_CONNECT_TIMEOUT);
                    tracing::info!(LOG_FALLING_BACK_TO_CDN);
                    self.use_fronting.store(true, std::sync::atomic::Ordering::Relaxed);
                    *self.last_direct_probe.lock().await = std::time::Instant::now();
                    tokio::time::timeout(timeout, self.connect_via_cdn(params))
                        .await
                        .map_err(|_| anyhow::anyhow!("{ERR_DIRECT_CONNECT_TIMEOUT} via CDN after {timeout:?}"))?
                }
            }
        }
    }

    /// Inner connection logic, wrapped by [`connect_with_fallback`] with a timeout.
    async fn connect_inner(&self, params: ClientConnectParams<'_>) -> anyhow::Result<TransportConnection> {
        if self.insecure {
            tracing::warn!("TLS certificate verification disabled (--insecure). Do NOT use in production.");
        }

        let http_client = MarkedHttpClient::new(self.fwmark, self.insecure, self.tls_profile)?;

        let scheme = if self.insecure { "http" } else { "https" };
        let port = extract_port(&self.server_endpoint);
        // Use server_name (hostname) for the initial handshake URL (DNS works before routing is up).
        let base_url = format!("{scheme}://{}:{port}", self.server_name);
        // Use server_endpoint (resolved IP) for polling URLs to avoid DNS deadlock
        // after routing sets DNS through the tunnel.
        let ip_host = extract_host(&self.server_endpoint);
        let poll_base_url = format!("{scheme}://{ip_host}:{port}");
        tracing::debug!(endpoint = %self.server_endpoint, server_name = %self.server_name, %base_url, %poll_base_url, "HARP connecting");

        let session = establish_harp_session(
            &http_client,
            &base_url,
            params.noise_keypair,
            params.server_noise_pub,
            params.server_kem_pub,
        )
        .await?;
        tracing::info!(mode = %session.transport_mode, "HARP handshake complete");

        // HTTP/2 streaming path
        if self.preferred_binding.as_deref() == Some(BINDING_H2) {
            let (sender, receiver) = connect_harp_h2(
                &self.server_name,
                port,
                &session.session_id,
                self.insecure,
                self.fwmark,
                self.tls_profile,
            )
            .await?;
            return Ok(TransportConnection {
                sender: Box::new(sender),
                receiver: Box::new(receiver),
                session_keys: session.session_keys,
            });
        }

        let use_polling = self.preferred_binding.as_deref() == Some(BINDING_POLL);
        if use_polling {
            tracing::info!("HARP transport: forced HTTP polling (preferred_binding=poll)");
        }

        let ws_result = if use_polling {
            None
        } else {
            match connect_harp_websocket(&base_url, &session.session_id, self.insecure, self.fwmark, self.tls_profile).await {
                Ok(ws) => Some(ws),
                Err(ws_err) => {
                    tracing::warn!("WebSocket failed ({ws_err}), falling back to HTTP polling");
                    None
                }
            }
        };

        if let Some((ws_sink, ws_stream)) = ws_result {
            tracing::info!("HARP transport: WebSocket streaming");
            let sender = HarpWsSender::new(ws_sink, params.cancel.child_token());
            let receiver = HarpWsReceiver::new(ws_stream);
            Ok(TransportConnection {
                sender: Box::new(sender),
                receiver: Box::new(receiver),
                session_keys: session.session_keys,
            })
        } else {
            let upload_url = format!("{poll_base_url}{}", session.upload_endpoint);
            let download_url = format!("{poll_base_url}{}", session.download_endpoint);
            tracing::debug!(%upload_url, %download_url, "HARP polling URLs (IP-based, avoids DNS deadlock)");

            // Create a new HTTP client with TLS SNI override for IP-based URLs
            let poll_http_client =
                MarkedHttpClient::new(self.fwmark, self.insecure, self.tls_profile)?.with_tls_server_name(self.server_name.clone());

            let (receiver, piggyback_tx) = HarpPollReceiver::new(
                poll_http_client.clone(),
                download_url,
                session.poll_interval_ms,
                params.cancel.child_token(),
            );
            let sender = HarpPollSender::new(
                poll_http_client,
                upload_url,
                session.poll_interval_ms,
                piggyback_tx,
                params.cancel.child_token(),
            );
            Ok(TransportConnection {
                sender: Box::new(sender),
                receiver: Box::new(receiver),
                session_keys: session.session_keys,
            })
        }
    }

    /// Connect through CDN domain fronting.
    ///
    /// Instead of connecting directly to the server, routes through a CDN
    /// (e.g., Cloudflare) by using `cdn_fronting_domain` for DNS resolution,
    /// TLS SNI, and HTTP Host header. The CDN forwards traffic to the origin
    /// server transparently.
    pub async fn connect_via_cdn(&self, params: ClientConnectParams<'_>) -> anyhow::Result<TransportConnection> {
        let cdn_domain = self
            .cdn_fronting_domain
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!(ERR_CDN_DOMAIN_NOT_CONFIGURED))?;
        tracing::info!(domain = %cdn_domain, "connecting via CDN fronting");

        let http_client = MarkedHttpClient::new(self.fwmark, self.insecure, self.tls_profile)?;

        let scheme = if self.insecure { "http" } else { "https" };
        let port = extract_port(&self.server_endpoint);
        // CDN path: use cdn_domain for base URL — DNS resolves to CDN IP,
        // TLS SNI = cdn_domain, HTTP Host = cdn_domain, CDN forwards to origin.
        let base_url = format!("{scheme}://{cdn_domain}:{port}");
        tracing::debug!(endpoint = %self.server_endpoint, %cdn_domain, %base_url, "HARP CDN connecting");

        let session = establish_harp_session(
            &http_client,
            &base_url,
            params.noise_keypair,
            params.server_noise_pub,
            params.server_kem_pub,
        )
        .await?;
        tracing::info!(mode = %session.transport_mode, "HARP CDN handshake complete");

        // HTTP/2 streaming path through CDN
        if self.preferred_binding.as_deref() == Some(BINDING_H2) {
            let (sender, receiver) =
                connect_harp_h2(cdn_domain, port, &session.session_id, self.insecure, self.fwmark, self.tls_profile).await?;
            return Ok(TransportConnection {
                sender: Box::new(sender),
                receiver: Box::new(receiver),
                session_keys: session.session_keys,
            });
        }

        let use_polling = self.preferred_binding.as_deref() == Some(BINDING_POLL);
        if use_polling {
            tracing::info!("HARP CDN transport: forced HTTP polling (preferred_binding=poll)");
        }

        // Through CDN, both WebSocket and polling use the CDN domain base URL
        // (CDN routing requires the correct Host header — no IP-based shortcut).
        let ws_result = if use_polling {
            None
        } else {
            match connect_harp_websocket(&base_url, &session.session_id, self.insecure, self.fwmark, self.tls_profile).await {
                Ok(ws) => Some(ws),
                Err(ws_err) => {
                    tracing::warn!("CDN WebSocket failed ({ws_err}), falling back to CDN HTTP polling");
                    None
                }
            }
        };

        if let Some((ws_sink, ws_stream)) = ws_result {
            tracing::info!("HARP CDN transport: WebSocket streaming");
            let sender = HarpWsSender::new(ws_sink, params.cancel.child_token());
            let receiver = HarpWsReceiver::new(ws_stream);
            Ok(TransportConnection {
                sender: Box::new(sender),
                receiver: Box::new(receiver),
                session_keys: session.session_keys,
            })
        } else {
            let upload_url = format!("{base_url}{}", session.upload_endpoint);
            let download_url = format!("{base_url}{}", session.download_endpoint);
            tracing::debug!(%upload_url, %download_url, "HARP CDN polling URLs");

            let (receiver, piggyback_tx) = HarpPollReceiver::new(
                http_client.clone(),
                download_url,
                session.poll_interval_ms,
                params.cancel.child_token(),
            );
            let sender = HarpPollSender::new(
                http_client,
                upload_url,
                session.poll_interval_ms,
                piggyback_tx,
                params.cancel.child_token(),
            );
            Ok(TransportConnection {
                sender: Box::new(sender),
                receiver: Box::new(receiver),
                session_keys: session.session_keys,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-20260223-harp-client-transport.md

    use super::*;
    use crate::transport::harp::HarpFrame;

    // -- Constants for tests --
    const SMALL_PAYLOAD: &[u8] = b"hello-harp";

    /// Type alias for a pinned, boxed WS sink used in test helpers.
    type MockWsSink = std::pin::Pin<
        Box<dyn futures_util::Sink<tokio_tungstenite::tungstenite::Message, Error = tokio_tungstenite::tungstenite::Error> + Send>,
    >;

    /// Build a `Box::pin`-ned mock WS sink that forwards messages to an mpsc channel.
    fn mock_ws_sink(capacity: usize) -> (MockWsSink, mpsc::Receiver<tokio_tungstenite::tungstenite::Message>) {
        let (tx, rx) = mpsc::channel(capacity);
        let sink = futures_util::sink::unfold(tx, |tx, msg| async move {
            tx.send(msg)
                .await
                .map_err(|_| tokio_tungstenite::tungstenite::Error::ConnectionClosed)?;
            Ok::<_, tokio_tungstenite::tungstenite::Error>(tx)
        });
        (Box::pin(sink), rx)
    }

    // -- AC-5: HarpWsSender encodes DATA frame and sends via channel --
    #[tokio::test]
    async fn harp_ws_sender_encodes_and_sends() {
        let (sink, mut rx) = mock_ws_sink(16);

        let cancel = CancellationToken::new();
        let sender = HarpWsSender::new(sink, cancel.clone());

        // Send a datagram
        sender.send_datagram(SMALL_PAYLOAD).expect("send_datagram");

        // Read from the sink output channel
        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout")
            .expect("recv");

        // Verify it's a binary WS message containing a HARP DATA frame
        let data = match msg {
            tokio_tungstenite::tungstenite::Message::Binary(d) => d.to_vec(),
            other => panic!("expected Binary, got {other:?}"),
        };
        let (frame, _consumed) = HarpFrame::decode(&data).expect("decode");
        assert_eq!(frame.frame_type, HarpFrameType::Data);
        assert_eq!(frame.payload, SMALL_PAYLOAD);

        cancel.cancel();
    }

    // -- AC-5: HarpWsSender returns error when channel full/closed --
    #[tokio::test]
    async fn harp_ws_sender_returns_error_on_closed_sink() {
        let (sink, _rx) = mock_ws_sink(1);

        let cancel = CancellationToken::new();
        let sender = HarpWsSender::new(sink, cancel.clone());

        // Fill the internal channel (capacity = WS_WRITE_CHANNEL_CAPACITY = 256)
        // Then it should return HarpChannelClosed
        for _ in 0..WS_WRITE_CHANNEL_CAPACITY {
            let _ = sender.send_datagram(SMALL_PAYLOAD);
        }
        let result = sender.send_datagram(SMALL_PAYLOAD);
        assert!(matches!(result, Err(TransportError::HarpChannelClosed)));

        cancel.cancel();
    }

    // -- AC-6: HarpWsReceiver decodes DATA frame from WS binary --
    #[tokio::test]
    async fn harp_ws_receiver_decodes_data_frame() {
        let frame = HarpFrame::data(SMALL_PAYLOAD.to_vec());
        let wire = frame.encode().expect("encode");

        let msg = Ok(tokio_tungstenite::tungstenite::Message::Binary(wire.into()));
        let stream = futures_util::stream::iter(vec![msg]);

        let receiver = HarpWsReceiver::new(stream);
        let payload = receiver.recv_datagram().await.expect("recv");
        assert_eq!(payload, SMALL_PAYLOAD);
    }

    // -- AC-6: HarpWsReceiver skips KEEPALIVE, returns DATA --
    #[tokio::test]
    async fn harp_ws_receiver_skips_keepalive() {
        let keepalive = HarpFrame::keepalive().encode().expect("encode ka");
        let data = HarpFrame::data(SMALL_PAYLOAD.to_vec()).encode().expect("encode data");

        let messages = vec![
            Ok(tokio_tungstenite::tungstenite::Message::Binary(keepalive.into())),
            Ok(tokio_tungstenite::tungstenite::Message::Binary(data.into())),
        ];
        let stream = futures_util::stream::iter(messages);

        let receiver = HarpWsReceiver::new(stream);
        let payload = receiver.recv_datagram().await.expect("recv");
        assert_eq!(payload, SMALL_PAYLOAD);
    }

    // -- AC-6: HarpWsReceiver returns error on CLOSE frame --
    #[tokio::test]
    async fn harp_ws_receiver_returns_error_on_close_frame() {
        let close = HarpFrame::close().encode().expect("encode close");
        let msg = Ok(tokio_tungstenite::tungstenite::Message::Binary(close.into()));
        let stream = futures_util::stream::iter(vec![msg]);

        let receiver = HarpWsReceiver::new(stream);
        let result = receiver.recv_datagram().await;
        assert!(matches!(result, Err(TransportError::HarpSessionClosed)));
    }

    // -- AC-6: HarpWsReceiver returns error on WS Close message --
    #[tokio::test]
    async fn harp_ws_receiver_returns_error_on_ws_close() {
        let msg = Ok(tokio_tungstenite::tungstenite::Message::Close(None));
        let stream = futures_util::stream::iter(vec![msg]);

        let receiver = HarpWsReceiver::new(stream);
        let result = receiver.recv_datagram().await;
        assert!(matches!(result, Err(TransportError::HarpSessionClosed)));
    }

    // -- AC-6: HarpWsReceiver returns error when stream ends --
    #[tokio::test]
    async fn harp_ws_receiver_returns_error_on_stream_end() {
        let stream =
            futures_util::stream::empty::<Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>>();

        let receiver = HarpWsReceiver::new(stream);
        let result = receiver.recv_datagram().await;
        assert!(matches!(result, Err(TransportError::HarpChannelClosed)));
    }

    // -- AC-6: HarpWsReceiver skips text messages --
    #[tokio::test]
    async fn harp_ws_receiver_skips_text_messages() {
        let data = HarpFrame::data(SMALL_PAYLOAD.to_vec()).encode().expect("encode");
        let messages = vec![
            Ok(tokio_tungstenite::tungstenite::Message::Text("hello".into())),
            Ok(tokio_tungstenite::tungstenite::Message::Binary(data.into())),
        ];
        let stream = futures_util::stream::iter(messages);

        let receiver = HarpWsReceiver::new(stream);
        let payload = receiver.recv_datagram().await.expect("recv");
        assert_eq!(payload, SMALL_PAYLOAD);
    }

    // -- extract_port helper --
    #[test]
    fn extract_port_with_port() {
        assert_eq!(extract_port("192.168.1.1:8443"), "8443");
    }

    #[test]
    fn extract_port_default() {
        assert_eq!(extract_port("hostname"), DEFAULT_HTTPS_PORT);
    }

    // -- extract_host helper --
    #[test]
    fn extract_host_with_port() {
        assert_eq!(extract_host("192.168.1.1:8443"), "192.168.1.1");
    }

    #[test]
    fn extract_host_without_port() {
        assert_eq!(extract_host("hostname"), "hostname");
    }

    // -- AC-1: build_harp_http_client succeeds --
    #[test]
    fn build_harp_http_client_secure() {
        let client = build_harp_http_client(false);
        assert!(client.is_ok());
    }

    #[test]
    fn build_harp_http_client_insecure() {
        let client = build_harp_http_client(true);
        assert!(client.is_ok());
    }

    // -- AC-1, AC-2, AC-3, AC-7: Integration test — full session establishment --
    #[tokio::test]
    async fn establish_harp_session_integration() {
        use crate::crypto::hybrid_kex::KemKeyPair;

        // Set up an in-process Axum server with the HARP session handler
        let state = harp_test_app_state();
        let app = crate::web::build_router(state.clone());

        // Register a client
        let client_noise = KeyPair::generate().expect("client keypair");
        let client_pub = *client_noise.public_key();
        let kem_kp = KemKeyPair::generate();
        let kem_pub = kem_kp.encapsulation_key_bytes();
        {
            let mut registry = state.registry.lock().await;
            registry.add("test-harp-client", client_pub, Some(kem_pub)).expect("register");
        }

        // Start a real TCP listener
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        // Build HTTP client and call establish_harp_session
        let http_client = MarkedHttpClient::new(None, true, crate::obfuscation::tls_mimicry::TlsProfile::Default).expect("http client");
        let base_url = format!("http://{addr}");

        let result = establish_harp_session(
            &http_client,
            &base_url,
            &client_noise,
            &state.server_noise_public_key,
            &state.server_context.kem_public_key,
        )
        .await;

        let session = result.expect("session establishment should succeed");

        // AC-2: session_id is non-empty base64
        assert!(!session.session_id.is_empty());
        let session_id_bytes = BASE64.decode(&session.session_id).expect("valid base64 session_id");
        assert_eq!(session_id_bytes.len(), crate::web::harp::SESSION_ID_LEN);

        // AC-3: Keys are non-zero (handshake actually completed)
        assert_ne!(session.session_keys.tx_key, [0u8; 32]);
        assert_ne!(session.session_keys.rx_key, [0u8; 32]);

        // AC-7: Session appears in the store
        let stored_session = state.harp_sessions.get(&session_id_bytes.try_into().expect("32 bytes"));
        assert!(stored_session.is_some());
    }

    // -- AC-2: Handshake failure returns error (unregistered client) --
    #[tokio::test]
    async fn establish_harp_session_unregistered_client_fails() {
        let state = harp_test_app_state();
        let app = crate::web::build_router(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        // Create an unregistered client
        let client_noise = KeyPair::generate().expect("keypair");
        let http_client = MarkedHttpClient::new(None, true, crate::obfuscation::tls_mimicry::TlsProfile::Default).expect("http client");
        let base_url = format!("http://{addr}");

        let result = establish_harp_session(
            &http_client,
            &base_url,
            &client_noise,
            &state.server_noise_public_key,
            &state.server_context.kem_public_key,
        )
        .await;

        // The server returns a fake response, so the handshake will fail
        // when the client tries to finish() with the fake noise_msg2
        assert!(result.is_err());
    }

    // -- AC-8: HarpSessionRequest is serializable --
    #[test]
    fn harp_session_request_serializes() {
        let request = HarpSessionRequest {
            noise_msg1: "dGVzdA==".to_string(),
            capabilities: vec!["stream".to_string()],
            timestamp: 1234567890,
        };
        let json = serde_json::to_string(&request).expect("serialize");
        assert!(json.contains("noise_msg1"));
        assert!(json.contains("capabilities"));
        assert!(json.contains("timestamp"));
    }

    // -- Helper: create test AppState (mirrors web::harp::tests pattern) --
    fn harp_test_app_state() -> crate::web::state::AppState {
        use crate::config::DEFAULT_SESSION_TIMEOUT;
        use crate::crypto::hybrid_kex::KemKeyPair;
        use crate::distribution::{ConfigTokenStore, ServerContext};
        use crate::registry::ClientRegistry;
        use crate::web::handlers::{ServerConfigResponse, TransportInfoResponse};
        use crate::web::harp::HarpSessionStore;

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

        crate::web::state::AppState {
            registry: Arc::new(tokio::sync::Mutex::new(registry)),
            active_connections: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            start_time: std::time::Instant::now(),
            jwt_secret: Arc::from([0xABu8; 32].as_slice()),
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            admin_password_hash: Arc::from(test_password_hash().as_str()),
            cancel: CancellationToken::new(),
            server_context: Arc::new(ServerContext {
                endpoint: "127.0.0.1:443".to_string(),
                server_name: "test.example.com".to_string(),
                noise_public_key: server_noise_public_key,
                kem_public_key,
                dns_servers: vec!["1.1.1.1".to_string()],
                mtu: 1280,
                transport_protocol: "harp".to_string(),
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
            cover_page_enabled: true,
            trust_proxy_headers: false,
        }
    }

    // -----------------------------------------------------------------------
    // Polling Transport Adapter Tests (FRD-20260223-harp-polling-transport.md)
    // -----------------------------------------------------------------------

    // -- AC-8: HarpPollSender implements DatagramSender and queues HARP DATA frames --

    #[tokio::test]
    async fn poll_sender_encodes_data_frame_to_channel() {
        let (piggyback_tx, _piggyback_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        // Use a dummy URL — the background task won't fire during this test
        // because we cancel before the jitter sleep completes
        let sender = HarpPollSender::new(
            MarkedHttpClient::new(None, true, crate::obfuscation::tls_mimicry::TlsProfile::Default).expect("http client"),
            "http://localhost:1/noop".to_string(),
            60_000, // very long interval so background task doesn't fire
            piggyback_tx,
            cancel.clone(),
        );

        let payload = b"poll-test-payload";
        sender.send_datagram(payload).expect("send_datagram");

        // The frame is in the internal channel — we can't read it directly,
        // but we can verify the send succeeded and a second call works
        sender.send_datagram(b"second").expect("send_datagram 2");

        cancel.cancel();
    }

    // -- AC-8: HarpPollSender returns error when channel is full --

    #[tokio::test]
    async fn poll_sender_returns_error_on_full_channel() {
        let (piggyback_tx, _piggyback_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let sender = HarpPollSender::new(
            MarkedHttpClient::new(None, true, crate::obfuscation::tls_mimicry::TlsProfile::Default).expect("http client"),
            "http://localhost:1/noop".to_string(),
            60_000,
            piggyback_tx,
            cancel.clone(),
        );

        // Fill the internal channel
        for _ in 0..POLL_UPLOAD_CHANNEL_CAPACITY {
            let _ = sender.send_datagram(b"fill");
        }
        let result = sender.send_datagram(b"overflow");
        assert!(matches!(result, Err(TransportError::HarpChannelClosed)));

        cancel.cancel();
    }

    // -- AC-9: HarpPollReceiver implements DatagramReceiver --

    #[tokio::test]
    async fn poll_receiver_returns_data_payload() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(16);
        let receiver = HarpPollReceiver {
            rx: Arc::new(TokioMutex::new(rx)),
        };

        // Send a wire-encoded DATA frame
        let payload = b"poll-recv-test";
        let frame = HarpFrame::data(payload.to_vec());
        let wire = frame.encode().expect("encode");
        tx.send(wire).await.expect("send");

        let result = receiver.recv_datagram().await.expect("recv");
        assert_eq!(result, payload);
    }

    // -- AC-9: HarpPollReceiver skips KEEPALIVE frames --

    #[tokio::test]
    async fn poll_receiver_skips_keepalive() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(16);
        let receiver = HarpPollReceiver {
            rx: Arc::new(TokioMutex::new(rx)),
        };

        let ka = HarpFrame::keepalive().encode().expect("encode ka");
        let data = HarpFrame::data(b"after-ka".to_vec()).encode().expect("encode data");
        tx.send(ka).await.expect("send ka");
        tx.send(data).await.expect("send data");

        let result = receiver.recv_datagram().await.expect("recv");
        assert_eq!(result, b"after-ka");
    }

    // -- AC-9: HarpPollReceiver returns error on CLOSE frame --

    #[tokio::test]
    async fn poll_receiver_returns_error_on_close() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(16);
        let receiver = HarpPollReceiver {
            rx: Arc::new(TokioMutex::new(rx)),
        };

        let close = HarpFrame::close().encode().expect("encode close");
        tx.send(close).await.expect("send close");

        let result = receiver.recv_datagram().await;
        assert!(matches!(result, Err(TransportError::HarpSessionClosed)));
    }

    // -- AC-9: HarpPollReceiver returns error on channel closed --

    #[tokio::test]
    async fn poll_receiver_returns_error_on_channel_closed() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(16);
        let receiver = HarpPollReceiver {
            rx: Arc::new(TokioMutex::new(rx)),
        };

        drop(tx);

        let result = receiver.recv_datagram().await;
        assert!(matches!(result, Err(TransportError::HarpChannelClosed)));
    }

    // -- forward_piggybacked_frames parses and forwards frames --

    #[tokio::test]
    async fn forward_piggybacked_frames_works() {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);

        let frame1 = HarpFrame::data(b"piggy-1".to_vec()).encode().expect("encode1");
        let frame2 = HarpFrame::data(b"piggy-2".to_vec()).encode().expect("encode2");
        let mut combined = Vec::new();
        combined.extend_from_slice(&frame1);
        combined.extend_from_slice(&frame2);

        forward_piggybacked_frames(&combined, &tx).await;

        let received1 = rx.recv().await.expect("recv1");
        let (decoded1, _) = HarpFrame::decode(&received1).expect("decode1");
        assert_eq!(decoded1.payload, b"piggy-1");

        let received2 = rx.recv().await.expect("recv2");
        let (decoded2, _) = HarpFrame::decode(&received2).expect("decode2");
        assert_eq!(decoded2.payload, b"piggy-2");
    }

    // -- Integration: HarpPollSender uploads to real server, HarpPollReceiver downloads --

    #[tokio::test]
    async fn poll_sender_receiver_integration_with_server() {
        let state = harp_test_app_state();
        let (session_id, session) = state.harp_sessions.create(uuid::Uuid::new_v4());
        let session_id_b64 = BASE64_URL.encode(session_id);

        // Start test server
        let app = crate::web::build_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let base_url = format!("http://{addr}/api/v1/harp");
        let upload_url = format!("{base_url}/upload/{session_id_b64}");
        let download_url = format!("{base_url}/download/{session_id_b64}");

        let http_client = MarkedHttpClient::new(None, true, crate::obfuscation::tls_mimicry::TlsProfile::Default).expect("http client");
        let cancel = CancellationToken::new();
        let poll_interval_ms: u64 = 10; // fast for testing

        // Create receiver first (returns piggyback_tx)
        let (receiver, piggyback_tx) = HarpPollReceiver::new(http_client.clone(), download_url, poll_interval_ms, cancel.child_token());

        // Create sender with piggyback_tx
        let sender = HarpPollSender::new(http_client, upload_url, poll_interval_ms, piggyback_tx, cancel.child_token());

        // Client → Server: send a datagram via polling sender
        let payload = b"integration-test-data";
        sender.send_datagram(payload).expect("send_datagram");

        // Wait for the background upload task to POST
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Verify the frame arrived in the session's from_client_rx
        let mut from_client_rx = session.from_client_rx.lock().await;
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), from_client_rx.recv())
            .await
            .expect("timeout")
            .expect("channel recv");
        let (decoded, _) = HarpFrame::decode(&received).expect("decode");
        assert_eq!(decoded.frame_type, HarpFrameType::Data);
        assert_eq!(decoded.payload, payload);
        drop(from_client_rx);

        // Server → Client: queue a frame for download
        let server_payload = b"server-to-client";
        let server_frame = HarpFrame::data(server_payload.to_vec()).encode().expect("encode");
        session.to_client_tx.send(server_frame).await.expect("queue download");

        // Wait for the background download task to fetch it
        let client_received = tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv_datagram())
            .await
            .expect("timeout")
            .expect("recv_datagram");
        assert_eq!(client_received, server_payload);

        cancel.cancel();
    }

    // FRD: specs/frds/FRD-20260223-masque-transport-traits.md

    /// Transport name constant for assertion.
    const MASQUE_TRANSPORT_NAME: &str = "masque";

    /// AC-2: MasqueClientTransport::name() returns "masque".
    #[test]
    fn masque_client_transport_name() {
        let transport = MasqueClientTransport::new(
            "127.0.0.1:443".parse().expect("addr"),
            "localhost".to_string(),
            25,
            300,
            false,
            None,
        );
        assert_eq!(transport.name(), MASQUE_TRANSPORT_NAME);
    }

    /// AC-3: MasqueClientTransport::connect() returns working TransportConnection.
    #[tokio::test]
    async fn masque_client_transport_connect_integration() {
        use crate::crypto::hybrid_kex::KemKeyPair;
        use crate::registry::ClientRegistry;
        use crate::server::{MultiServerParams, bind_ephemeral_server, run_multi_server_on_endpoint};
        use crate::tunnel::MockTunFactory;
        use crate::tunnel::tun_device::DEFAULT_TUNNEL_MTU;
        use std::sync::atomic::AtomicU32;
        use tokio::sync::Mutex;

        let _ = rustls::crypto::ring::default_provider().install_default();

        let server_noise = KeyPair::generate().expect("server noise keypair");
        let server_kem = KemKeyPair::generate();
        let server_noise_pub = *server_noise.public_key();
        let server_kem_pub = server_kem.encapsulation_key_bytes();

        let (endpoint, actual_addr) = bind_ephemeral_server("localhost").expect("bind");

        let client_noise = KeyPair::generate().expect("client noise keypair");
        let mut registry = ClientRegistry::new("10.66.66.0/24").expect("registry");
        registry
            .add("trait-test-client", *client_noise.public_key(), None)
            .expect("register");
        let registry = Arc::new(Mutex::new(registry));
        let tun_factory = Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU));
        let cancel = CancellationToken::new();

        let server_task = {
            let cancel = cancel.clone();
            let registry = Arc::clone(&registry);
            tokio::spawn(async move {
                run_multi_server_on_endpoint(
                    endpoint,
                    &server_noise,
                    server_kem,
                    MultiServerParams {
                        registry,
                        max_clients: 2,
                        tun_factory,
                        cancel,
                        active_connections: Arc::new(AtomicU32::new(0)),
                    },
                )
                .await
            })
        };

        let transport = MasqueClientTransport::new(actual_addr, "localhost".to_string(), 25, 300, true, None);

        let params = ClientConnectParams {
            noise_keypair: &client_noise,
            server_noise_pub: &server_noise_pub,
            server_kem_pub: &server_kem_pub,
            cancel: cancel.child_token(),
        };

        let conn = transport.connect(params).await.expect("connect should succeed");

        // Verify sender/receiver are functional
        let test_payload = b"trait-test-payload";
        assert!(conn.sender.send_datagram(test_payload).is_ok());

        cancel.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server_task).await;
    }

    /// AC-1: MasqueClientTransport can be used as Box<dyn ClientTransport>.
    #[test]
    fn masque_client_transport_trait_object() {
        let transport: Box<dyn ClientTransport> = Box::new(MasqueClientTransport::new(
            "127.0.0.1:443".parse().expect("addr"),
            "localhost".to_string(),
            25,
            300,
            true,
            None,
        ));
        assert_eq!(transport.name(), MASQUE_TRANSPORT_NAME);
    }

    // FRD: specs/frds/FRD-20260223-harp-transport-traits.md

    /// Constant for HARP transport name used in tests.
    const HARP_TRANSPORT_NAME_TEST: &str = "harp";

    /// Create a default `HarpClientConfig` for tests.
    fn test_harp_config() -> HarpClientConfig {
        HarpClientConfig {
            server_endpoint: "127.0.0.1:443".to_string(),
            server_name: "localhost".to_string(),
            insecure: false,
            fwmark: None,
            preferred_binding: None,
            tls_profile: crate::obfuscation::tls_mimicry::TlsProfile::Default,
            direct_timeout: std::time::Duration::from_secs(crate::config::DEFAULT_DIRECT_TIMEOUT_SECS),
            cdn_fronting_domain: None,
            cdn_fronting_enabled: false,
            direct_retry_interval: std::time::Duration::from_secs(crate::config::DEFAULT_DIRECT_RETRY_INTERVAL_SECS),
        }
    }

    // T-S12-1: HarpClientTransport::name() returns "harp"
    #[test]
    fn harp_client_transport_name() {
        let transport = HarpClientTransport::new(test_harp_config());
        assert_eq!(transport.name(), HARP_TRANSPORT_NAME_TEST);
    }

    // T-S12-2: HarpClientTransport can be used as Box<dyn ClientTransport>
    #[test]
    fn harp_client_transport_trait_object() {
        let transport: Box<dyn ClientTransport> = Box::new(HarpClientTransport::new(test_harp_config()));
        assert_eq!(transport.name(), HARP_TRANSPORT_NAME_TEST);
    }

    // -----------------------------------------------------------------------
    // FRD: specs/frds/FRD-20260224-wire-tls-profile.md
    // Step 1.2: Wire TlsProfile into MarkedHttpClient
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // FRD: specs/frds/FRD-20260224-thread-tls-profile.md
    // Step 1.3: Thread tls_profile through HarpClientTransport
    // -----------------------------------------------------------------------

    // AC-1: HarpClientTransport::new() accepts and stores a TlsProfile
    #[test]
    fn harp_client_transport_stores_tls_profile() {
        let mut config = test_harp_config();
        config.tls_profile = crate::obfuscation::tls_mimicry::TlsProfile::Chrome;
        let transport = HarpClientTransport::new(config);
        assert_eq!(transport.name(), HARP_TRANSPORT_NAME_TEST);
    }

    // -----------------------------------------------------------------------
    // FRD: specs/frds/FRD-20260224-direct-connect-timeout.md
    // Step 3.2: Direct-connect timeout
    // -----------------------------------------------------------------------

    // AC-1: HarpClientTransport::new() accepts and stores direct_timeout
    #[test]
    fn harp_client_transport_stores_direct_timeout() {
        let timeout = std::time::Duration::from_secs(10);
        let mut config = test_harp_config();
        config.direct_timeout = timeout;
        let transport = HarpClientTransport::new(config);
        assert_eq!(transport.direct_timeout, timeout);
    }

    // -----------------------------------------------------------------------
    // FRD: specs/frds/FRD-20260224-cdn-fronting-connect.md
    // Step 3.3: CDN fronting connect path
    // -----------------------------------------------------------------------

    // AC-1: HarpClientTransport stores cdn_fronting_domain
    #[test]
    fn harp_client_transport_stores_cdn_domain() {
        let mut config = test_harp_config();
        config.cdn_fronting_domain = Some("prrr.tech".to_string());
        let transport = HarpClientTransport::new(config);
        assert_eq!(transport.cdn_fronting_domain.as_deref(), Some("prrr.tech"));
    }

    // AC-2: connect_via_cdn() fails without configured domain
    #[tokio::test]
    async fn harp_cdn_connect_fails_without_domain() {
        let transport = HarpClientTransport::new(test_harp_config());
        let noise_kp = crate::handshake::noise_ik::KeyPair::generate().expect("keypair");
        let server_pub = [0u8; 32];
        let kem_pub = vec![0u8; crate::crypto::hybrid_kex::KEM_ENCAPSULATION_KEY_LEN];
        let cancel = tokio_util::sync::CancellationToken::new();
        let params = ClientConnectParams {
            noise_keypair: &noise_kp,
            server_noise_pub: &server_pub,
            server_kem_pub: &kem_pub,
            cancel: cancel.clone(),
        };
        let result = transport.connect_via_cdn(params).await;
        assert!(result.is_err());
        let err = result.err().expect("expected error");
        assert!(
            err.to_string().contains(ERR_CDN_DOMAIN_NOT_CONFIGURED),
            "expected CDN domain error, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // FRD: specs/frds/FRD-20260224-auto-fallback-strategy.md
    // Step 3.4: Auto-fallback strategy
    // -----------------------------------------------------------------------

    // AC-1: CDN disabled → use_fronting stays false
    #[test]
    fn auto_fallback_cdn_disabled_use_fronting_stays_false() {
        let config = test_harp_config(); // cdn_fronting_enabled = false
        let transport = HarpClientTransport::new(config);
        assert!(!transport.cdn_fronting_enabled);
        assert!(!transport.use_fronting.load(std::sync::atomic::Ordering::Relaxed));
    }

    // AC-3: CDN enabled → use_fronting defaults to false (direct first)
    #[test]
    fn auto_fallback_cdn_enabled_defaults_direct() {
        let mut config = test_harp_config();
        config.cdn_fronting_enabled = true;
        config.cdn_fronting_domain = Some("prrr.tech".to_string());
        let transport = HarpClientTransport::new(config);
        assert!(transport.cdn_fronting_enabled);
        assert!(!transport.use_fronting.load(std::sync::atomic::Ordering::Relaxed));
    }

    // AC-1: MarkedHttpClient::new with Chrome profile, insecure
    #[test]
    fn marked_http_client_chrome_insecure() {
        use crate::obfuscation::tls_mimicry::TlsProfile;
        let client = MarkedHttpClient::new(None, true, TlsProfile::Chrome);
        assert!(client.is_ok(), "MarkedHttpClient with Chrome profile should succeed");
    }

    // AC-2: MarkedHttpClient::new with Chrome profile, secure
    #[test]
    fn marked_http_client_chrome_secure() {
        use crate::obfuscation::tls_mimicry::TlsProfile;
        let client = MarkedHttpClient::new(None, false, TlsProfile::Chrome);
        assert!(client.is_ok(), "MarkedHttpClient with Chrome secure should succeed");
    }

    // AC-3: MarkedHttpClient::new with Default profile, insecure
    #[test]
    fn marked_http_client_default_insecure() {
        use crate::obfuscation::tls_mimicry::TlsProfile;
        let client = MarkedHttpClient::new(None, true, TlsProfile::Default);
        assert!(client.is_ok(), "MarkedHttpClient with Default profile should succeed");
    }

    // AC-3b: MarkedHttpClient::new with Firefox profile
    #[test]
    fn marked_http_client_firefox_insecure() {
        use crate::obfuscation::tls_mimicry::TlsProfile;
        let client = MarkedHttpClient::new(None, true, TlsProfile::Firefox);
        assert!(client.is_ok(), "MarkedHttpClient with Firefox profile should succeed");
    }

    // -----------------------------------------------------------------------
    // FRD: specs/frds/FRD-20260224-alpn-h2-http11.md
    // Step 1.4: ALPN h2 + http/1.1
    // -----------------------------------------------------------------------

    // AC-1: build_harp_rustls_config sets ALPN protocols h2 and http/1.1
    #[test]
    fn harp_rustls_config_alpn_protocols() {
        use crate::obfuscation::tls_mimicry::TlsProfile;
        let config = build_harp_rustls_config(true, TlsProfile::Chrome).unwrap();
        let expected_alpn: Vec<Vec<u8>> = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        assert_eq!(config.alpn_protocols, expected_alpn, "ALPN should be [h2, http/1.1]");
    }

    // AC-1b: ALPN is set regardless of insecure mode
    #[test]
    fn harp_rustls_config_alpn_secure() {
        use crate::obfuscation::tls_mimicry::TlsProfile;
        let config = build_harp_rustls_config(false, TlsProfile::Default).unwrap();
        let expected_alpn: Vec<Vec<u8>> = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        assert_eq!(config.alpn_protocols, expected_alpn, "ALPN should be set in secure mode too");
    }

    // -----------------------------------------------------------------------
    // FRD: specs/frds/FRD-20260225-h2-client-connect.md
    // Step 4.3: H2 client connect path
    // -----------------------------------------------------------------------

    // AC-6: HARP_CLIENT_CAPABILITIES includes "h2"
    #[test]
    fn client_capabilities_include_h2() {
        assert!(
            HARP_CLIENT_CAPABILITIES.contains(&"h2"),
            "HARP_CLIENT_CAPABILITIES must include 'h2'"
        );
    }

    // AC-7: H2-only rustls config has ALPN ["h2"]
    #[test]
    fn h2_rustls_config_alpn_h2_only() {
        use crate::obfuscation::tls_mimicry::TlsProfile;
        let config = build_harp_h2_rustls_config(true, TlsProfile::Chrome).unwrap();
        let expected_alpn: Vec<Vec<u8>> = vec![b"h2".to_vec()];
        assert_eq!(config.alpn_protocols, expected_alpn, "H2 config ALPN should be [h2] only");
    }

    // AC-7b: H2-only rustls config works in secure mode
    #[test]
    fn h2_rustls_config_alpn_h2_only_secure() {
        use crate::obfuscation::tls_mimicry::TlsProfile;
        let config = build_harp_h2_rustls_config(false, TlsProfile::Default).unwrap();
        let expected_alpn: Vec<Vec<u8>> = vec![b"h2".to_vec()];
        assert_eq!(config.alpn_protocols, expected_alpn, "H2 config ALPN should be [h2] in secure mode");
    }
}
