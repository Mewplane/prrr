// FRD: specs/frds/FRD-006.md

//! QUIC client and server transport using quinn over TLS 1.3.
//!
//! Provides thin wrappers around `quinn::Endpoint` for establishing
//! QUIC connections with bidirectional stream support. At this layer
//! streams carry raw bytes — MASQUE framing is added in F-007.
//!
//! # Certificate Generation
//!
//! For dev/test, use [`generate_self_signed_cert`] to create a
//! self-signed certificate with the required SANs.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::crypto::rustls::QuicServerConfig;

use super::TransportError;

/// Default idle timeout for QUIC connections in milliseconds.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Default maximum read size for stream reads (1 MiB).
pub const DEFAULT_MAX_READ_SIZE: usize = 1_048_576;

/// Generate a self-signed TLS certificate for dev/test use.
///
/// Returns DER-encoded certificate and private key bytes.
/// `subject_alt_names` should include at least `"localhost"` for local testing.
pub fn generate_self_signed_cert(
    subject_alt_names: Vec<String>,
) -> Result<
    (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    TransportError,
> {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(subject_alt_names).map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der()).map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    Ok((cert_der, key_der))
}

/// Build a quinn `ServerConfig` from a DER-encoded certificate and private key.
fn build_server_config(
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, TransportError> {
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    tls_config.alpn_protocols = vec![b"prrr".to_vec()];

    let quic_server_config = QuicServerConfig::try_from(tls_config).map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_server_config)))
}

/// Build a quinn `ClientConfig` with configurable certificate verification.
///
/// When `insecure` is `true`, skips certificate verification (dev/test).
/// When `insecure` is `false`, verifies against the Mozilla CA root store.
fn build_client_config(insecure: bool) -> Result<quinn::ClientConfig, TransportError> {
    let verifier = super::tls::build_cert_verifier(insecure);
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"prrr".to_vec()];

    let quic_client_config = QuicClientConfig::try_from(tls_config).map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    Ok(quinn::ClientConfig::new(Arc::new(quic_client_config)))
}

/// QUIC server that listens for incoming connections.
pub struct QuicServer {
    endpoint: quinn::Endpoint,
}

impl QuicServer {
    /// Bind a QUIC server to the given address.
    ///
    /// Uses the provided DER-encoded certificate and private key for TLS.
    /// Pass `"0.0.0.0:0"` or `"[::1]:0"` for an OS-assigned port.
    pub fn bind(
        addr: SocketAddr,
        cert_der: rustls::pki_types::CertificateDer<'static>,
        key_der: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<Self, TransportError> {
        let server_config = build_server_config(cert_der, key_der)?;
        let endpoint = quinn::Endpoint::server(server_config, addr).map_err(|e| TransportError::BindFailed(e.to_string()))?;

        Ok(Self { endpoint })
    }

    /// Return the local address the server is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr().map_err(|e| TransportError::BindFailed(e.to_string()))
    }

    /// Accept the next incoming QUIC connection.
    ///
    /// Blocks (async) until a client connects or the endpoint is closed.
    pub async fn accept(&self) -> Result<QuicConnection, TransportError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| TransportError::QuicConnection("endpoint closed".to_string()))?;

        let connection = incoming.await.map_err(|e| TransportError::QuicConnection(e.to_string()))?;

        Ok(QuicConnection { connection })
    }

    /// Gracefully close the server endpoint.
    ///
    /// All active connections will be notified.
    pub fn close(&self) {
        self.endpoint.close(quinn::VarInt::from_u32(0), b"server shutdown");
    }
}

/// QUIC client endpoint for initiating connections.
pub struct QuicClient {
    endpoint: quinn::Endpoint,
}

impl QuicClient {
    /// Create a new QUIC client endpoint.
    ///
    /// Uses an insecure TLS config that skips server certificate verification
    /// (suitable for dev/test with self-signed certs).
    pub fn new_insecure() -> Result<Self, TransportError> {
        let client_config = build_client_config(true)?;

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("valid socket addr"))
            .map_err(|e| TransportError::BindFailed(e.to_string()))?;

        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    /// Connect to a QUIC server at the given address.
    ///
    /// `server_name` is the SNI hostname (must match the server's certificate SANs).
    pub async fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<QuicConnection, TransportError> {
        let connection = self
            .endpoint
            .connect(addr, server_name)
            .map_err(|e| TransportError::QuicConnection(e.to_string()))?
            .await
            .map_err(|e| TransportError::QuicConnection(e.to_string()))?;

        Ok(QuicConnection { connection })
    }

    /// Close the client endpoint.
    pub fn close(&self) {
        self.endpoint.close(quinn::VarInt::from_u32(0), b"client shutdown");
    }
}

/// A QUIC connection with bidirectional stream support.
pub struct QuicConnection {
    connection: quinn::Connection,
}

impl QuicConnection {
    /// Open a new bidirectional stream on this connection.
    pub async fn open_bi(&self) -> Result<(QuicSendStream, QuicRecvStream), TransportError> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| TransportError::QuicConnection(e.to_string()))?;

        Ok((QuicSendStream { inner: send }, QuicRecvStream { inner: recv }))
    }

    /// Accept an incoming bidirectional stream from the remote peer.
    pub async fn accept_bi(&self) -> Result<(QuicSendStream, QuicRecvStream), TransportError> {
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|e| TransportError::QuicConnection(e.to_string()))?;

        Ok((QuicSendStream { inner: send }, QuicRecvStream { inner: recv }))
    }

    /// Return the remote address of the peer.
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Gracefully close the connection.
    pub fn close(&self) {
        self.connection.close(quinn::VarInt::from_u32(0), b"done");
    }
}

/// A QUIC send stream for writing bytes.
pub struct QuicSendStream {
    inner: quinn::SendStream,
}

impl QuicSendStream {
    /// Write all bytes to the stream.
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.inner
            .write_all(data)
            .await
            .map_err(|e| TransportError::QuicWrite(e.to_string()))
    }

    /// Signal that no more data will be written to this stream.
    pub async fn finish(&mut self) -> Result<(), TransportError> {
        self.inner.finish().map_err(|e| TransportError::QuicWrite(e.to_string()))
    }
}

/// A QUIC receive stream for reading bytes.
pub struct QuicRecvStream {
    inner: quinn::RecvStream,
}

impl QuicRecvStream {
    /// Read all bytes from the stream up to `max_size`.
    ///
    /// Returns the received data when the sender finishes or closes the stream.
    pub async fn read_to_end(&mut self, max_size: usize) -> Result<Vec<u8>, TransportError> {
        self.inner
            .read_to_end(max_size)
            .await
            .map_err(|e| TransportError::QuicRead(e.to_string()))
    }

    /// Read exactly enough bytes to fill `buf`.
    ///
    /// Returns an error if the stream ends before `buf` is full.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), TransportError> {
        self.inner
            .read_exact(buf)
            .await
            .map_err(|e| TransportError::QuicRead(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SERVER_NAME: &str = "localhost";
    const TEST_PAYLOAD_PING: &[u8] = b"ping";
    const TEST_PAYLOAD_PONG: &[u8] = b"pong";
    const TEST_BIND_ADDR: &str = "127.0.0.1:0";
    const LARGE_PAYLOAD_SIZE: usize = 65_536;
    const CONCURRENT_STREAM_COUNT: usize = 5;

    /// Install the rustls ring crypto provider (idempotent — safe to call multiple times).
    fn init_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// Generate a self-signed cert for localhost and start a server.
    fn setup_server_config() -> (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        init_crypto_provider();
        generate_self_signed_cert(vec![TEST_SERVER_NAME.to_string()]).expect("cert generation")
    }

    // T-1: Self-signed cert generation produces cert and key
    #[test]
    fn self_signed_cert_generation() {
        let (cert_der, key_der) = setup_server_config();
        // Certificate should be non-empty DER bytes
        assert!(!cert_der.is_empty(), "certificate DER should not be empty");
        // Private key should be non-empty
        let key_bytes: &[u8] = match &key_der {
            rustls::pki_types::PrivateKeyDer::Pkcs1(k) => k.secret_pkcs1_der(),
            rustls::pki_types::PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der(),
            rustls::pki_types::PrivateKeyDer::Sec1(k) => k.secret_sec1_der(),
            _ => &[],
        };
        assert!(!key_bytes.is_empty(), "private key should not be empty");
    }

    // T-2: Server binds to port 0 and reports bound address
    #[tokio::test]
    async fn server_binds_and_reports_address() {
        let (cert, key) = setup_server_config();
        let bind_addr: SocketAddr = TEST_BIND_ADDR.parse().expect("valid addr");
        let server = QuicServer::bind(bind_addr, cert, key).expect("server bind");
        let local_addr = server.local_addr().expect("local addr");

        // OS should assign a non-zero port
        assert_ne!(local_addr.port(), 0, "OS should assign a real port");
        assert_eq!(local_addr.ip(), bind_addr.ip());

        server.close();
    }

    // T-3: Client connects to server, ping-pong over bidirectional stream
    #[tokio::test]
    async fn ping_pong_over_stream() {
        let (cert, key) = setup_server_config();
        let bind_addr: SocketAddr = TEST_BIND_ADDR.parse().expect("valid addr");
        let server = QuicServer::bind(bind_addr, cert, key).expect("server bind");
        let server_addr = server.local_addr().expect("local addr");

        let client = QuicClient::new_insecure().expect("client");

        // Server accept task — returns conn and server to keep them alive
        let server_handle = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept");
            let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");

            // Read ping
            let data = recv.read_to_end(DEFAULT_MAX_READ_SIZE).await.expect("read");
            assert_eq!(data, TEST_PAYLOAD_PING);

            // Send pong
            send.write_all(TEST_PAYLOAD_PONG).await.expect("write");
            send.finish().await.expect("finish");

            // Keep connection alive until client is done reading
            (server, conn)
        });

        // Client sends ping, receives pong
        let conn = client.connect(server_addr, TEST_SERVER_NAME).await.expect("connect");
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");

        send.write_all(TEST_PAYLOAD_PING).await.expect("write ping");
        send.finish().await.expect("finish");

        let data = recv.read_to_end(DEFAULT_MAX_READ_SIZE).await.expect("read pong");
        assert_eq!(data, TEST_PAYLOAD_PONG);

        let (_server, _conn) = server_handle.await.expect("server task");
    }

    // T-4: Multiple concurrent bidirectional streams on one connection
    #[tokio::test]
    async fn multiple_concurrent_streams() {
        let (cert, key) = setup_server_config();
        let bind_addr: SocketAddr = TEST_BIND_ADDR.parse().expect("valid addr");
        let server = QuicServer::bind(bind_addr, cert, key).expect("server bind");
        let server_addr = server.local_addr().expect("local addr");

        let client = QuicClient::new_insecure().expect("client");

        let server_handle = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept");

            // Accept and echo on multiple streams
            let mut handles = Vec::new();
            for _ in 0..CONCURRENT_STREAM_COUNT {
                let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
                handles.push(tokio::spawn(async move {
                    let data = recv.read_to_end(DEFAULT_MAX_READ_SIZE).await.expect("read");
                    send.write_all(&data).await.expect("write");
                    send.finish().await.expect("finish");
                }));
            }

            for handle in handles {
                handle.await.expect("stream task");
            }

            // Keep connection alive until client is done reading
            (server, conn)
        });

        let conn = client.connect(server_addr, TEST_SERVER_NAME).await.expect("connect");

        // Open multiple streams concurrently
        let mut handles = Vec::new();
        for i in 0..CONCURRENT_STREAM_COUNT {
            let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
            handles.push(tokio::spawn(async move {
                let msg = format!("stream-{i}");
                send.write_all(msg.as_bytes()).await.expect("write");
                send.finish().await.expect("finish");

                let data = recv.read_to_end(DEFAULT_MAX_READ_SIZE).await.expect("read");
                assert_eq!(data, msg.as_bytes(), "echo mismatch on stream {i}");
            }));
        }

        for handle in handles {
            handle.await.expect("client stream task");
        }

        let (_server, _conn) = server_handle.await.expect("server task");
    }

    // T-5: Client connection to non-existent server fails with error
    #[tokio::test]
    async fn connect_to_nonexistent_server_fails() {
        init_crypto_provider();
        let client = QuicClient::new_insecure().expect("client");

        // Connect to a port that (almost certainly) has no QUIC server
        let bad_addr: SocketAddr = "127.0.0.1:1".parse().expect("valid addr");
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), client.connect(bad_addr, TEST_SERVER_NAME)).await;

        // Either times out or returns a connection error
        match result {
            Ok(Err(TransportError::QuicConnection(_))) => {}
            Err(_timeout) => {}
            Ok(Err(other)) => panic!("expected QuicConnection error, got: {other}"),
            Ok(Ok(_)) => panic!("expected connection error or timeout, got Ok"),
        }
    }

    // T-6: Server graceful shutdown
    #[tokio::test]
    async fn server_graceful_shutdown() {
        let (cert, key) = setup_server_config();
        let bind_addr: SocketAddr = TEST_BIND_ADDR.parse().expect("valid addr");
        let server = QuicServer::bind(bind_addr, cert, key).expect("server bind");

        // Close the server
        server.close();

        // Accept should now fail (endpoint closed)
        let result = server.accept().await;
        assert!(result.is_err(), "accept after close should fail");
    }

    // T-7: Large payload (64KB) transfer over stream
    #[tokio::test]
    async fn large_payload_transfer() {
        let (cert, key) = setup_server_config();
        let bind_addr: SocketAddr = TEST_BIND_ADDR.parse().expect("valid addr");
        let server = QuicServer::bind(bind_addr, cert, key).expect("server bind");
        let server_addr = server.local_addr().expect("local addr");

        let client = QuicClient::new_insecure().expect("client");

        let large_data: Vec<u8> = (0..LARGE_PAYLOAD_SIZE).map(|i| (i % 256) as u8).collect();
        let expected = large_data.clone();

        let server_handle = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept");
            let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");

            let data = recv.read_to_end(DEFAULT_MAX_READ_SIZE).await.expect("read");
            send.write_all(&data).await.expect("write");
            send.finish().await.expect("finish");

            // Keep connection alive until client is done reading
            (server, conn)
        });

        let conn = client.connect(server_addr, TEST_SERVER_NAME).await.expect("connect");
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");

        send.write_all(&large_data).await.expect("write large");
        send.finish().await.expect("finish");

        let data = recv.read_to_end(DEFAULT_MAX_READ_SIZE).await.expect("read large");
        assert_eq!(data.len(), LARGE_PAYLOAD_SIZE);
        assert_eq!(data, expected);

        let (_server, _conn) = server_handle.await.expect("server task");
    }

    // T-8: Stream finish signals end of data
    #[tokio::test]
    async fn stream_finish_signals_end() {
        let (cert, key) = setup_server_config();
        let bind_addr: SocketAddr = TEST_BIND_ADDR.parse().expect("valid addr");
        let server = QuicServer::bind(bind_addr, cert, key).expect("server bind");
        let server_addr = server.local_addr().expect("local addr");

        let client = QuicClient::new_insecure().expect("client");

        let server_handle = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept");
            let (_send, mut recv) = conn.accept_bi().await.expect("accept_bi");

            // read_to_end returns when client finishes the stream
            let data = recv.read_to_end(DEFAULT_MAX_READ_SIZE).await.expect("read");
            assert_eq!(data, b"before-finish");

            // Keep connection alive
            (server, conn)
        });

        let conn = client.connect(server_addr, TEST_SERVER_NAME).await.expect("connect");
        let (mut send, _recv) = conn.open_bi().await.expect("open_bi");

        send.write_all(b"before-finish").await.expect("write");
        send.finish().await.expect("finish");

        let (_server, _conn) = server_handle.await.expect("server task");
    }
}
