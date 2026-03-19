// FRD: specs/frds/FRD-P001.md

//! CLI argument parsing and TOML configuration for the `prrr` binary.
//!
//! Provides [`Cli`] (clap top-level), [`ServerArgs`], [`ClientArgs`],
//! [`ServerConfig`] for server TOML configuration, and [`ClientConfigFile`]
//! for client TOML configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use clap::{Parser, Subcommand};
use serde::Deserialize;

use crate::crypto::hybrid_kex::KEM_ENCAPSULATION_KEY_LEN;
use crate::handshake::noise_ik::PUBLIC_KEY_LEN;

// ---------------------------------------------------------------------------
// Default constants — server
// ---------------------------------------------------------------------------

/// Default listen address for the server.
pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:443";

/// Default log level when none is specified.
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// Default TLS server name for the server (used for self-signed cert generation in dev/test).
pub const DEFAULT_SERVER_SERVER_NAME: &str = "localhost";

/// Error message when client `server_name` is not configured.
pub const ERR_MISSING_SERVER_NAME: &str =
    "server_name is required. Set --server-name on the CLI or [server].server_name in the config file.";

/// Default maximum number of concurrent VPN clients.
pub const DEFAULT_MAX_CLIENTS: u32 = 100;

/// Default server data directory.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/prrr";

/// Default VPN client subnet (CIDR).
pub const DEFAULT_SUBNET: &str = "10.66.66.0/24";

/// Default DNS servers for VPN clients.
pub const DEFAULT_DNS_SERVERS: &[&str] = &["1.1.1.1", "8.8.8.8"];

/// Default tunnel MTU (must fit in QUIC datagrams after encryption + MASQUE overhead).
pub const DEFAULT_MTU: u16 = 1100;

/// Default path for server X25519 identity key.
pub const DEFAULT_IDENTITY_KEY_PATH: &str = "/etc/prrr/keys/server_identity.key";

/// Default path for server ML-KEM-768 post-quantum key.
pub const DEFAULT_PQ_KEY_PATH: &str = "/etc/prrr/keys/server_pq.key";

/// Default rekey interval in seconds.
pub const DEFAULT_REKEY_INTERVAL: u64 = 3600;

/// Default transport protocol.
pub const DEFAULT_TRANSPORT_PROTOCOL: &str = "masque";

/// Default QUIC max idle timeout in seconds.
pub const DEFAULT_MAX_IDLE_TIMEOUT: u64 = 300;

/// Default QUIC keep-alive interval in seconds.
pub const DEFAULT_KEEP_ALIVE: u64 = 25;

/// Default HARP session idle timeout in seconds.
pub const DEFAULT_HARP_SESSION_IDLE_TIMEOUT: u64 = 300;

/// Default padding strategy for traffic obfuscation.
pub const DEFAULT_PADDING_STRATEGY: &str = "power-of-two";

/// Default max timing jitter in milliseconds.
pub const DEFAULT_TIMING_JITTER_MS: u64 = 50;

/// Default TLS fingerprint mimicry profile.
pub const DEFAULT_TLS_PROFILE: &str = "chrome";

/// Default probe resistance tokens per second.
pub const DEFAULT_PROBE_RESIST_TOKENS_PER_SEC: u64 = 20;

/// Default probe resistance burst capacity.
pub const DEFAULT_PROBE_RESIST_BURST: u64 = 5;

/// Default direct connection timeout before CDN fallback (seconds).
pub const DEFAULT_DIRECT_TIMEOUT_SECS: u64 = 5;

/// Default interval for probing direct connection when using CDN (seconds).
pub const DEFAULT_DIRECT_RETRY_INTERVAL_SECS: u64 = 600;

/// Default web admin listen address.
pub const DEFAULT_WEB_ADMIN_ADDR: &str = "0.0.0.0:8443";

/// Default web admin session timeout in seconds.
pub const DEFAULT_SESSION_TIMEOUT: u64 = 3600;

/// Default messaging relay mode.
pub const DEFAULT_RELAY_MODE: &str = "server";

/// Default maximum message size in bytes (10 MiB).
pub const DEFAULT_MAX_MESSAGE_SIZE: u64 = 10_485_760;

/// Default message retention in days.
pub const DEFAULT_RETENTION_DAYS: u32 = 30;

/// Default Prometheus metrics port.
pub const DEFAULT_PROMETHEUS_PORT: u16 = 9090;

/// Default log rotation strategy.
pub const DEFAULT_LOG_ROTATION: &str = "daily";

/// Default log retention in days.
pub const DEFAULT_LOG_RETENTION_DAYS: u32 = 7;

// ---------------------------------------------------------------------------
// CLI (P-009B: nested subcommands for client management)
// ---------------------------------------------------------------------------

/// PRRR — censorship-resistant VPN protocol.
#[derive(Parser, Debug)]
#[command(name = "prrr", version, about = "Censorship-resistant VPN protocol")]
pub struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start VPN server or manage clients.
    Server(ServerArgs),
    /// Connect to VPN server or import configuration.
    Client(ClientArgs),
}

/// Arguments for the `prrr server` subcommand.
///
/// When no subcommand is provided, starts the VPN server.
/// Use `prrr server client <action>` to manage clients.
#[derive(clap::Args, Debug)]
pub struct ServerArgs {
    /// Address to listen on.
    #[arg(long, default_value = DEFAULT_LISTEN_ADDR, env = "PRRR_LISTEN")]
    pub listen: SocketAddr,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = DEFAULT_LOG_LEVEL, env = "PRRR_LOG_LEVEL")]
    pub log_level: String,

    /// Optional TOML configuration file.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// TLS server name (SNI).
    #[arg(long, default_value = DEFAULT_SERVER_SERVER_NAME)]
    pub server_name: String,

    /// Server management subcommand.
    #[command(subcommand)]
    pub subcommand: Option<ServerSubcommand>,
}

/// Server management subcommands.
#[derive(Subcommand, Debug)]
pub enum ServerSubcommand {
    /// Manage VPN clients.
    Client(ServerClientArgs),
    /// Run server diagnostic checks.
    Doctor,
}

/// Arguments for `prrr server client <action>`.
#[derive(clap::Args, Debug)]
pub struct ServerClientArgs {
    /// Client management action.
    #[command(subcommand)]
    pub action: ServerClientAction,
}

/// Client management actions.
#[derive(Subcommand, Debug)]
pub enum ServerClientAction {
    /// Register a new VPN client.
    Add {
        /// Client name (must be unique among active clients).
        name: String,
        /// Also output QR code (SVG) for mobile import.
        #[arg(long)]
        qr: bool,
    },
    /// List all registered clients.
    List,
    /// Revoke a client by name.
    Remove {
        /// Client name to revoke.
        name: String,
    },
    /// Export client configuration.
    Export {
        /// Client name to export.
        name: String,
        /// Output QR code (SVG) instead of TOML config.
        #[arg(long)]
        qr: bool,
        /// Write output to file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

/// Arguments for the `prrr client` subcommand.
///
/// When no subcommand is provided, connects to the VPN server
/// (requires `--server`). Use `prrr client import <source>` to
/// import a configuration file.
#[derive(clap::Args, Debug)]
pub struct ClientArgs {
    /// Server address to connect to (required for connect mode).
    #[arg(long)]
    pub server: Option<SocketAddr>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = DEFAULT_LOG_LEVEL, env = "PRRR_LOG_LEVEL")]
    pub log_level: String,

    /// Optional TOML configuration file.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// TLS server name (SNI) — required for production use.
    #[arg(long)]
    pub server_name: Option<String>,

    /// Server Noise IK public key (base64-encoded, 32 bytes decoded).
    #[arg(long)]
    pub server_public_key: Option<String>,

    /// Server ML-KEM-768 public key (base64-encoded, 1184 bytes decoded).
    #[arg(long)]
    pub server_pq_public_key: Option<String>,

    /// Skip TLS certificate verification (insecure, dev/test only).
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// Client management subcommand.
    #[command(subcommand)]
    pub subcommand: Option<ClientSubcommand>,
}

/// Client subcommands.
#[derive(Subcommand, Debug)]
pub enum ClientSubcommand {
    /// Import client configuration from file or prrr:// URL.
    Import {
        /// File path or prrr://import URL to import configuration from.
        source: String,
    },
    /// Run client diagnostic checks.
    Doctor,
}

/// Error message when --server is required but not provided.
pub const ERR_MISSING_SERVER_ADDR: &str = "server address required: use --server <ADDR> or prrr client import <source>";

// ---------------------------------------------------------------------------
// Server TOML configuration (SPEC.md §1.2)
// ---------------------------------------------------------------------------

/// Full server configuration from TOML file.
///
/// All sections are optional. Missing sections use defaults.
/// Unknown fields are silently ignored for forward compatibility.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct ServerConfig {
    /// Core server settings.
    pub server: Option<ServerSection>,
    /// Virtual network settings.
    pub network: Option<NetworkSection>,
    /// Cryptographic key paths and intervals.
    pub crypto: Option<CryptoSection>,
    /// Transport configurations (replaces legacy `[transport]`).
    pub transports: Option<Vec<TransportEntry>>,
    /// Traffic obfuscation and anti-censorship settings.
    pub obfuscation: Option<ObfuscationSection>,
    /// Web administration interface settings.
    pub web_admin: Option<WebAdminSection>,
    /// Whisper messaging service settings.
    pub messaging: Option<MessagingSection>,
    /// Monitoring and observability settings.
    pub monitoring: Option<MonitoringSection>,
}

/// `[server]` section — core server parameters.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct ServerSection {
    /// Address to listen on (e.g. `"0.0.0.0:443"`).
    pub listen_addr: Option<String>,
    /// Maximum number of concurrent VPN clients.
    pub max_clients: Option<u32>,
    /// Log level directive.
    pub log_level: Option<String>,
    /// Server data directory for persistent state.
    pub data_dir: Option<String>,
    /// TLS server name for SNI.
    pub server_name: Option<String>,
}

/// `[network]` section — virtual network for clients.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct NetworkSection {
    /// Client subnet in CIDR notation (e.g. `"10.66.66.0/24"`).
    pub subnet: Option<String>,
    /// DNS servers pushed to clients.
    pub dns_servers: Option<Vec<String>>,
    /// Tunnel MTU.
    pub mtu: Option<u16>,
}

/// `[crypto]` section — key storage and rotation.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct CryptoSection {
    /// Path to X25519 identity key file.
    pub identity_key_path: Option<String>,
    /// Path to ML-KEM-768 post-quantum key file.
    pub pq_key_path: Option<String>,
    /// Rekey interval in seconds.
    pub rekey_interval: Option<u64>,
}

/// A transport entry in the `[[transports]]` array.
///
/// Uses serde tag dispatch on the `name` field to select the transport type.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(tag = "name")]
pub enum TransportEntry {
    /// QUIC/MASQUE transport.
    #[serde(rename = "masque")]
    Masque(MasqueTransportConfig),
    /// HARP (HTTPS API Relay Protocol) transport.
    #[serde(rename = "harp")]
    Harp(HarpTransportConfig),
}

/// MASQUE transport configuration within `[[transports]]`.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct MasqueTransportConfig {
    /// Whether this transport is enabled (default: true).
    pub enabled: Option<bool>,
    /// Max idle timeout in seconds before connection close.
    pub max_idle_timeout: Option<u64>,
    /// Keep-alive interval in seconds.
    pub keep_alive: Option<u64>,
    /// Path to TLS certificate file (PEM) for CA-signed cert.
    pub tls_cert: Option<String>,
    /// Path to TLS private key file (PEM).
    pub tls_key: Option<String>,
}

/// HARP transport configuration within `[[transports]]`.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct HarpTransportConfig {
    /// Whether this transport is enabled (default: true).
    pub enabled: Option<bool>,
    /// Enable WebSocket streaming mode.
    pub websocket_enabled: Option<bool>,
    /// Enable HTTP polling fallback mode.
    pub polling_enabled: Option<bool>,
    /// Enable HTTP/2 multiplexed streaming mode (default: `true` when resolved).
    pub h2_streaming_enabled: Option<bool>,
    /// Seconds before idle HARP sessions are cleaned up.
    pub session_idle_timeout: Option<u64>,
    /// Path to TLS certificate file (PEM) for HTTPS.
    pub tls_cert: Option<String>,
    /// Path to TLS private key file (PEM).
    pub tls_key: Option<String>,
}

/// `[obfuscation]` section — traffic shaping and anti-censorship.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct ObfuscationSection {
    /// Whether obfuscation is enabled.
    pub enabled: Option<bool>,
    /// Padding strategy: `"power-of-two"`, `"http-sizes"`, `"fixed-mtu:<N>"`, `"none"`.
    pub padding_strategy: Option<String>,
    /// Maximum timing jitter per packet in milliseconds.
    pub timing_jitter_ms: Option<u64>,
    /// TLS fingerprint profile: `"chrome"`, `"firefox"`, `"default"`.
    pub tls_profile: Option<String>,
    /// Active probing resistance sub-section.
    pub probe_resist: Option<ProbeResistSection>,
}

/// `[obfuscation.probe_resist]` section — active probing resistance.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct ProbeResistSection {
    /// Whether probe resistance is enabled.
    pub enabled: Option<bool>,
    /// Pre-shared key for token generation (base64).
    pub psk: Option<String>,
    /// Rate limit tokens per second per IP.
    pub tokens_per_second: Option<u64>,
    /// Token bucket burst capacity.
    pub burst_capacity: Option<u64>,
}

/// `[web_admin]` section — web management interface.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct WebAdminSection {
    /// Whether web admin is enabled.
    pub enabled: Option<bool>,
    /// Listen address (e.g. `"0.0.0.0:8443"`).
    pub listen_addr: Option<String>,
    /// Path to TLS certificate file.
    pub tls_cert: Option<String>,
    /// Path to TLS private key file.
    pub tls_key: Option<String>,
    /// Argon2id hash of admin password.
    pub admin_password_hash: Option<String>,
    /// Session timeout in seconds.
    pub session_timeout: Option<u64>,
    /// Whether to serve the cover landing page at `/` (default: `true`).
    /// When `false`, `/` serves the admin SPA directly.
    pub cover_page_enabled: Option<bool>,
    /// Whether to trust proxy headers (`CF-Connecting-IP`, `X-Forwarded-For`)
    /// for extracting the real client IP (default: `false`).
    /// Enable when behind a trusted CDN (e.g., Cloudflare).
    pub trust_proxy_headers: Option<bool>,
}

/// `[messaging]` section — Whisper messaging service.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct MessagingSection {
    /// Whether messaging is enabled.
    pub enabled: Option<bool>,
    /// Relay mode: `"server"`, `"distributed"`, `"hybrid"`.
    pub relay_mode: Option<String>,
    /// Maximum message size in bytes.
    pub max_message_size: Option<u64>,
    /// Message retention in days.
    pub retention_days: Option<u32>,
}

/// `[monitoring]` section — Prometheus metrics and logging.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct MonitoringSection {
    /// Whether Prometheus metrics are enabled.
    pub metrics_enabled: Option<bool>,
    /// Port for the Prometheus metrics endpoint.
    pub prometheus_port: Option<u16>,
    /// Path to log file (structured JSON when set).
    pub log_file: Option<String>,
    /// Log rotation strategy: `"daily"`, `"hourly"`, `"size:<bytes>"`.
    pub log_rotation: Option<String>,
    /// Log retention in days.
    pub log_retention_days: Option<u32>,
}

// ---------------------------------------------------------------------------
// Client TOML configuration (SPEC.md §2.2)
// ---------------------------------------------------------------------------

/// Full client configuration from TOML file.
///
/// All sections are optional. Missing sections use defaults.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct ClientConfigFile {
    /// Client identity settings.
    pub client: Option<ClientSection>,
    /// Server connection settings.
    pub server: Option<ClientServerSection>,
    /// Local interface and key settings.
    pub interface: Option<InterfaceSection>,
    /// Routing rules.
    pub routing: Option<RoutingSection>,
    /// Transport settings.
    pub transport: Option<ClientTransportSection>,
    /// Obfuscation settings.
    pub obfuscation: Option<ClientObfuscationSection>,
    /// Messaging settings.
    pub messaging: Option<ClientMessagingSection>,
}

/// `[client]` section — client identity.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct ClientSection {
    /// Human-readable client name.
    pub name: Option<String>,
    /// Whether to auto-connect on startup.
    pub auto_connect: Option<bool>,
    /// Log level directive.
    pub log_level: Option<String>,
}

/// `[server]` section in client config — server connection details.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct ClientServerSection {
    /// Server endpoint address (e.g. `"vpn.example.com:443"`).
    pub endpoint: Option<String>,
    /// TLS Server Name (SNI)
    pub server_name: Option<String>,
    /// Server X25519 public key (base64).
    pub public_key: Option<String>,
    /// Server ML-KEM-768 public key (base64).
    pub pq_public_key: Option<String>,
}

/// `[interface]` section — local tunnel interface.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct InterfaceSection {
    /// Inline client X25519 private key (base64). Preferred over `private_key_path`.
    pub private_key: Option<String>,
    /// Path to client X25519 private key (fallback when `private_key` is absent).
    pub private_key_path: Option<String>,
    /// Path to client ML-KEM-768 private key.
    pub pq_private_key_path: Option<String>,
    /// Assigned IP address (CIDR, e.g. `"10.66.66.2/32"`).
    pub address: Option<String>,
    /// DNS servers.
    pub dns: Option<Vec<String>>,
    /// Tunnel MTU.
    pub mtu: Option<u16>,
    /// Transport protocol (e.g. `"masque"` or `"harp"`).
    pub transport_protocol: Option<String>,
}

/// `[routing]` section — traffic routing rules.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct RoutingSection {
    /// Route all traffic through VPN.
    pub all_traffic: Option<bool>,
    /// Allowed destination CIDRs.
    pub allowed_ips: Option<Vec<String>>,
    /// Excluded destination CIDRs.
    pub excluded_ips: Option<Vec<String>>,
    /// Firewall mark for VPN transport sockets (default: 51820).
    pub fwmark: Option<u32>,
    /// Path to routing hook script (default: `/usr/local/bin/prrr-route`).
    pub hook_script: Option<String>,
}

/// `[transport]` section in client config.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct ClientTransportSection {
    /// Transport protocol.
    pub protocol: Option<String>,
    /// Keep-alive interval in seconds (MASQUE).
    pub keep_alive: Option<u64>,
    /// Skip TLS certificate verification (insecure, dev/test only).
    pub insecure_skip_verify: Option<bool>,
    /// Preferred HARP binding: `"stream"` (WebSocket) or `"poll"` (HTTP polling).
    pub preferred_binding: Option<String>,
    /// HARP polling interval in milliseconds (with jitter applied by client).
    pub poll_interval_ms: Option<u64>,
    /// Initial reconnection backoff delay in milliseconds.
    pub reconnect_backoff_ms: Option<u64>,
    /// Maximum reconnection backoff delay in milliseconds.
    pub reconnect_max_backoff_ms: Option<u64>,
    /// TLS fingerprint profile: `"chrome"`, `"firefox"`, or `"default"`.
    /// When `None`, the caller defaults to `TlsProfile::Chrome`.
    pub tls_profile: Option<String>,
    /// Enable CDN domain fronting fallback (default: disabled).
    /// When `true`, the client falls back to CDN routing if direct
    /// connection fails within `direct_timeout_secs`.
    pub cdn_fronting_enabled: Option<bool>,
    /// CDN fronting domain (e.g., `"prrr.tech"`).
    /// Used for DNS resolution and TLS SNI when fronting through CDN.
    pub cdn_fronting_domain: Option<String>,
    /// Direct connection timeout in seconds before falling back to CDN (default: 5).
    pub direct_timeout_secs: Option<u64>,
    /// Interval in seconds between probing direct connection when CDN is active (default: 600).
    pub direct_retry_interval_secs: Option<u64>,
}

/// `[obfuscation]` section in client config.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct ClientObfuscationSection {
    /// Whether obfuscation is enabled.
    pub enabled: Option<bool>,
}

/// `[messaging]` section in client config.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct ClientMessagingSection {
    /// Whether Whisper messaging is enabled.
    pub enabled: Option<bool>,
}

// ---------------------------------------------------------------------------
// Key resolution helpers (P-003)
// ---------------------------------------------------------------------------

/// Error message when neither CLI flag nor config provides a server noise key.
const ERR_MISSING_NOISE_KEY: &str = "server Noise public key required: use --server-public-key or set [server].public_key in config";

/// Error message when neither CLI flag nor config provides a server KEM key.
const ERR_MISSING_KEM_KEY: &str = "server KEM public key required: use --server-pq-public-key or set [server].pq_public_key in config";

/// Error message prefix for invalid base64 in a key value.
const ERR_INVALID_BASE64: &str = "invalid base64 in server public key";

/// Error message prefix for wrong key length.
const ERR_WRONG_NOISE_KEY_LEN: &str = "server Noise public key must be exactly";

/// Error message prefix for wrong KEM key length.
const ERR_WRONG_KEM_KEY_LEN: &str = "server KEM public key must be exactly";

/// Resolve the server's Noise IK public key from CLI flag or config file.
///
/// Priority: `cli_flag` > `config_value`. Both are base64-encoded.
/// Returns the decoded 32-byte public key, or an error if missing/invalid.
pub fn resolve_server_noise_key(cli_flag: Option<&str>, config_value: Option<&str>) -> anyhow::Result<[u8; PUBLIC_KEY_LEN]> {
    let b64 = cli_flag.or(config_value).ok_or_else(|| anyhow::anyhow!(ERR_MISSING_NOISE_KEY))?;

    let bytes = BASE64_STANDARD
        .decode(b64)
        .map_err(|e| anyhow::anyhow!("{ERR_INVALID_BASE64}: {e}"))?;

    let key: [u8; PUBLIC_KEY_LEN] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("{ERR_WRONG_NOISE_KEY_LEN} {PUBLIC_KEY_LEN} bytes, got {}", v.len()))?;

    Ok(key)
}

/// Resolve the server's ML-KEM-768 encapsulation key from CLI flag or config file.
///
/// Priority: `cli_flag` > `config_value`. Both are base64-encoded.
/// Returns the decoded 1184-byte encapsulation key, or an error if missing/invalid.
pub fn resolve_server_kem_key(cli_flag: Option<&str>, config_value: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let b64 = cli_flag.or(config_value).ok_or_else(|| anyhow::anyhow!(ERR_MISSING_KEM_KEY))?;

    let bytes = BASE64_STANDARD
        .decode(b64)
        .map_err(|e| anyhow::anyhow!("{ERR_INVALID_BASE64}: {e}"))?;

    if bytes.len() != KEM_ENCAPSULATION_KEY_LEN {
        anyhow::bail!("{ERR_WRONG_KEM_KEY_LEN} {KEM_ENCAPSULATION_KEY_LEN} bytes, got {}", bytes.len());
    }

    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

/// Load and parse a server TOML configuration file.
///
/// Returns `ServerConfig::default()` if the path is `None`.
/// Returns `Err` if the file does not exist or cannot be parsed.
pub fn load_server_config(path: Option<&PathBuf>) -> anyhow::Result<ServerConfig> {
    let Some(path) = path else {
        return Ok(ServerConfig::default());
    };

    if !path.exists() {
        anyhow::bail!("config file not found: {}", path.display());
    }

    let text = std::fs::read_to_string(path)?;
    let config: ServerConfig = toml::from_str(&text)?;
    Ok(config)
}

/// Load and parse a client TOML configuration file.
///
/// Returns `ClientConfigFile::default()` if the path is `None`.
/// Returns `Err` if the file does not exist or cannot be parsed.
pub fn load_client_config(path: Option<&PathBuf>) -> anyhow::Result<ClientConfigFile> {
    let Some(path) = path else {
        return Ok(ClientConfigFile::default());
    };

    if !path.exists() {
        anyhow::bail!("config file not found: {}", path.display());
    }

    let text = std::fs::read_to_string(path)?;
    let config: ClientConfigFile = toml::from_str(&text)?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// Transport resolution
// ---------------------------------------------------------------------------

/// A resolved transport configuration with defaults applied.
///
/// Produced by [`resolve_server_transports`] from raw config entries.
#[derive(Debug, PartialEq)]
pub enum ResolvedTransport {
    /// QUIC/MASQUE transport with resolved settings.
    Masque {
        /// Max idle timeout in seconds.
        max_idle_timeout: u64,
        /// Keep-alive interval in seconds.
        keep_alive: u64,
        /// Optional TLS certificate path.
        tls_cert: Option<String>,
        /// Optional TLS key path.
        tls_key: Option<String>,
    },
    /// HARP transport with resolved settings.
    Harp {
        /// Whether WebSocket streaming is enabled.
        websocket_enabled: bool,
        /// Whether HTTP polling fallback is enabled.
        polling_enabled: bool,
        /// Whether HTTP/2 multiplexed streaming is enabled.
        h2_streaming_enabled: bool,
        /// Session idle timeout in seconds.
        session_idle_timeout: u64,
        /// Optional TLS certificate path.
        tls_cert: Option<String>,
        /// Optional TLS key path.
        tls_key: Option<String>,
    },
}

/// Resolve the effective list of enabled server transports from config.
///
/// If `[[transports]]` is absent, returns a single default MASQUE transport.
/// Disabled entries (`enabled = false`) are filtered out.
pub fn resolve_server_transports(config: &ServerConfig) -> Vec<ResolvedTransport> {
    let entries = match config.transports.as_deref() {
        Some(entries) if !entries.is_empty() => entries,
        _ => {
            return vec![ResolvedTransport::Harp {
                websocket_enabled: true,
                polling_enabled: true,
                h2_streaming_enabled: true,
                session_idle_timeout: DEFAULT_HARP_SESSION_IDLE_TIMEOUT,
                tls_cert: None,
                tls_key: None,
            }];
        }
    };

    entries
        .iter()
        .filter_map(|entry| match entry {
            TransportEntry::Masque(m) => {
                if m.enabled == Some(false) {
                    return None;
                }
                Some(ResolvedTransport::Masque {
                    max_idle_timeout: m.max_idle_timeout.unwrap_or(DEFAULT_MAX_IDLE_TIMEOUT),
                    keep_alive: m.keep_alive.unwrap_or(DEFAULT_KEEP_ALIVE),
                    tls_cert: m.tls_cert.clone(),
                    tls_key: m.tls_key.clone(),
                })
            }
            TransportEntry::Harp(h) => {
                if h.enabled == Some(false) {
                    return None;
                }
                Some(ResolvedTransport::Harp {
                    websocket_enabled: h.websocket_enabled.unwrap_or(true),
                    polling_enabled: h.polling_enabled.unwrap_or(true),
                    h2_streaming_enabled: h.h2_streaming_enabled.unwrap_or(true),
                    session_idle_timeout: h.session_idle_timeout.unwrap_or(DEFAULT_HARP_SESSION_IDLE_TIMEOUT),
                    tls_cert: h.tls_cert.clone(),
                    tls_key: h.tls_key.clone(),
                })
            }
        })
        .collect()
}

/// Initialize the tracing subscriber with the given log level directive.
///
/// Falls back to `RUST_LOG` environment variable if set. Otherwise uses
/// the provided `level` string (e.g. "info", "debug", "trace").
///
/// When `log_file` is `Some`, adds a JSON-formatted file layer for
/// structured logging alongside the compact console layer on stderr.
pub fn init_tracing(level: &str, log_file: Option<&str>) {
    use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    let console_layer = fmt::layer().with_target(true).compact();

    match log_file {
        Some(path) => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap_or_else(|e| panic!("failed to open log file {path}: {e}"));
            let json_layer = fmt::layer().json().with_writer(std::sync::Mutex::new(file));
            tracing_subscriber::registry()
                .with(console_layer)
                .with(json_layer)
                .with(filter)
                .init();
        }
        None => {
            tracing_subscriber::registry().with(console_layer).with(filter).init();
        }
    }
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-P001.md, specs/frds/FRD-P009B.md
    use super::*;
    use clap::Parser;
    use std::path::Path;

    // -----------------------------------------------------------------------
    // CLI tests (P-009B: nested subcommands)
    // -----------------------------------------------------------------------

    // T-1: CLI parses server subcommand with defaults (backward compat)
    #[test]
    fn cli_parses_server_defaults() {
        let cli = Cli::parse_from(["prrr", "server"]);
        match cli.command {
            Command::Server(args) => {
                assert_eq!(args.listen, DEFAULT_LISTEN_ADDR.parse::<SocketAddr>().expect("valid addr"));
                assert_eq!(args.log_level, DEFAULT_LOG_LEVEL);
                assert_eq!(args.server_name, DEFAULT_SERVER_SERVER_NAME);
                assert!(args.config.is_none());
                assert!(args.subcommand.is_none(), "no subcommand = start server");
            }
            Command::Client(_) => panic!("expected Server command"),
        }
    }

    // T-2: CLI parses client subcommand with --server (backward compat)
    #[test]
    fn cli_parses_client_with_server() {
        let cli = Cli::parse_from(["prrr", "client", "--server", "10.0.0.1:443"]);
        match cli.command {
            Command::Client(args) => {
                let expected_addr: SocketAddr = "10.0.0.1:443".parse().expect("valid addr");
                assert_eq!(args.server, Some(expected_addr));
                assert_eq!(args.log_level, DEFAULT_LOG_LEVEL);
                assert!(args.server_name.is_none());
                assert!(args.config.is_none());
                assert!(args.server_public_key.is_none());
                assert!(args.server_pq_public_key.is_none());
                assert!(args.subcommand.is_none(), "no subcommand = connect mode");
            }
            Command::Server(_) => panic!("expected Client command"),
        }
    }

    // T-P003-1: Client CLI parses server public key flags
    #[test]
    fn cli_client_public_key_flags() {
        let noise_b64 = "dGVzdC1ub2lzZS1wdWJsaWMta2V5LTMyYnl0ZXM=";
        let kem_b64 = "dGVzdC1rZW0tcHVibGljLWtleQ==";
        let cli = Cli::parse_from([
            "prrr",
            "client",
            "--server",
            "10.0.0.1:443",
            "--server-public-key",
            noise_b64,
            "--server-pq-public-key",
            kem_b64,
        ]);
        match cli.command {
            Command::Client(args) => {
                assert_eq!(args.server_public_key.as_deref(), Some(noise_b64));
                assert_eq!(args.server_pq_public_key.as_deref(), Some(kem_b64));
            }
            Command::Server(_) => panic!("expected Client command"),
        }
    }

    // T-2b: Client subcommand without --server parses (validation at runtime)
    #[test]
    fn cli_client_without_server_parses() {
        let cli = Cli::parse_from(["prrr", "client"]);
        match cli.command {
            Command::Client(args) => {
                assert!(args.server.is_none(), "--server is optional at parse time");
                assert!(args.subcommand.is_none());
            }
            Command::Server(_) => panic!("expected Client command"),
        }
    }

    // T-DPI003-1: Client --insecure flag defaults to false
    #[test]
    fn cli_client_insecure_defaults_false() {
        let cli = Cli::parse_from(["prrr", "client"]);
        match cli.command {
            Command::Client(args) => {
                assert!(!args.insecure, "--insecure should default to false");
            }
            Command::Server(_) => panic!("expected Client command"),
        }
    }

    // T-DPI003-2: Client --insecure flag parses when present
    #[test]
    fn cli_client_insecure_flag() {
        let cli = Cli::parse_from(["prrr", "client", "--insecure"]);
        match cli.command {
            Command::Client(args) => {
                assert!(args.insecure, "--insecure should be true when passed");
            }
            Command::Server(_) => panic!("expected Client command"),
        }
    }

    // FRD: specs/frds/FRD-20260223-pluggable-transport-config.md
    // T-STEP13-1: Client transport preferred_binding parses from TOML
    #[test]
    fn client_transport_preferred_binding() {
        let toml_str = r#"
[transport]
protocol = "harp"
preferred_binding = "poll"
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert_eq!(transport.preferred_binding.as_deref(), Some("poll"));
    }

    // T-STEP13-2: Client transport poll_interval_ms parses from TOML
    #[test]
    fn client_transport_poll_interval() {
        let toml_str = r#"
[transport]
protocol = "harp"
poll_interval_ms = 200
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert_eq!(transport.poll_interval_ms, Some(200));
    }

    // T-DPI003-3: Client transport config parses insecure_skip_verify
    #[test]
    fn client_transport_insecure_skip_verify() {
        let toml_str = r#"
[transport]
protocol = "masque"
insecure_skip_verify = true
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert_eq!(transport.insecure_skip_verify, Some(true));
    }

    // T-DPI003-4: Client transport config without insecure_skip_verify defaults to None
    #[test]
    fn client_transport_insecure_skip_verify_absent() {
        let toml_str = r#"
[transport]
protocol = "masque"
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert!(transport.insecure_skip_verify.is_none());
    }

    // T-STEP15-1: Client transport reconnect_backoff_ms parses from TOML
    #[test]
    fn client_transport_reconnect_backoff() {
        let toml_str = r#"
[transport]
protocol = "harp"
reconnect_backoff_ms = 2000
reconnect_max_backoff_ms = 60000
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert_eq!(transport.reconnect_backoff_ms, Some(2000));
        assert_eq!(transport.reconnect_max_backoff_ms, Some(60000));
    }

    // T-STEP15-2: Client transport reconnect fields default to None when absent
    #[test]
    fn client_transport_reconnect_defaults() {
        let toml_str = r#"
[transport]
protocol = "masque"
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert!(transport.reconnect_backoff_ms.is_none());
        assert!(transport.reconnect_max_backoff_ms.is_none());
    }

    // T-DPI005-1: Client --server-name is None when not provided
    #[test]
    fn cli_client_server_name_defaults_none() {
        let cli = Cli::parse_from(["prrr", "client"]);
        match cli.command {
            Command::Client(args) => {
                assert!(args.server_name.is_none(), "server_name should be None when not provided");
            }
            Command::Server(_) => panic!("expected Client command"),
        }
    }

    // T-DPI005-2: Client --server-name parses when provided
    #[test]
    fn cli_client_server_name_provided() {
        let cli = Cli::parse_from(["prrr", "client", "--server-name", "vpn.example.com"]);
        match cli.command {
            Command::Client(args) => {
                assert_eq!(args.server_name.as_deref(), Some("vpn.example.com"));
            }
            Command::Server(_) => panic!("expected Client command"),
        }
    }

    // T-DPI005-3: Server --server-name defaults to localhost
    #[test]
    fn cli_server_name_defaults_localhost() {
        let cli = Cli::parse_from(["prrr", "server"]);
        match cli.command {
            Command::Server(args) => {
                assert_eq!(args.server_name, "localhost");
            }
            Command::Client(_) => panic!("expected Server command"),
        }
    }

    // T-1b: Server subcommand with custom flags
    #[test]
    fn cli_server_custom_flags() {
        let cli = Cli::parse_from([
            "prrr",
            "server",
            "--listen",
            "127.0.0.1:8443",
            "--log-level",
            "debug",
            "--server-name",
            "vpn.example.com",
            "--config",
            "/etc/prrr.toml",
        ]);
        match cli.command {
            Command::Server(args) => {
                let expected_addr: SocketAddr = "127.0.0.1:8443".parse().expect("valid addr");
                assert_eq!(args.listen, expected_addr);
                assert_eq!(args.log_level, "debug");
                assert_eq!(args.server_name, "vpn.example.com");
                assert_eq!(args.config, Some(PathBuf::from("/etc/prrr.toml")));
            }
            Command::Client(_) => panic!("expected Server command"),
        }
    }

    // -----------------------------------------------------------------------
    // P-009B: Nested subcommand parsing tests
    // -----------------------------------------------------------------------

    // AC-B5: prrr server client add alice
    #[test]
    fn cli_server_client_add_parses() {
        let cli = Cli::parse_from(["prrr", "server", "client", "add", "alice"]);
        match cli.command {
            Command::Server(args) => match args.subcommand {
                Some(ServerSubcommand::Client(sc)) => match sc.action {
                    ServerClientAction::Add { ref name, qr } => {
                        assert_eq!(name, "alice");
                        assert!(!qr);
                    }
                    _ => panic!("expected Add action"),
                },
                _ => panic!("expected Client subcommand"),
            },
            _ => panic!("expected Server command"),
        }
    }

    // AC-B6: prrr server client list
    #[test]
    fn cli_server_client_list_parses() {
        let cli = Cli::parse_from(["prrr", "server", "client", "list"]);
        match cli.command {
            Command::Server(args) => match args.subcommand {
                Some(ServerSubcommand::Client(sc)) => {
                    assert!(matches!(sc.action, ServerClientAction::List));
                }
                _ => panic!("expected Client subcommand"),
            },
            _ => panic!("expected Server command"),
        }
    }

    // AC-B7: prrr server client remove alice
    #[test]
    fn cli_server_client_remove_parses() {
        let cli = Cli::parse_from(["prrr", "server", "client", "remove", "alice"]);
        match cli.command {
            Command::Server(args) => match args.subcommand {
                Some(ServerSubcommand::Client(sc)) => match sc.action {
                    ServerClientAction::Remove { ref name } => assert_eq!(name, "alice"),
                    _ => panic!("expected Remove action"),
                },
                _ => panic!("expected Client subcommand"),
            },
            _ => panic!("expected Server command"),
        }
    }

    // AC-B8: prrr server client export alice --qr
    #[test]
    fn cli_server_client_export_parses() {
        let cli = Cli::parse_from(["prrr", "server", "client", "export", "alice", "--qr"]);
        match cli.command {
            Command::Server(args) => match args.subcommand {
                Some(ServerSubcommand::Client(sc)) => match sc.action {
                    ServerClientAction::Export { ref name, qr, ref output } => {
                        assert_eq!(name, "alice");
                        assert!(qr);
                        assert!(output.is_none());
                    }
                    _ => panic!("expected Export action"),
                },
                _ => panic!("expected Client subcommand"),
            },
            _ => panic!("expected Server command"),
        }
    }

    // AC-B8b: prrr server client export alice --output /tmp/client.toml
    #[test]
    fn cli_server_client_export_output_parses() {
        let cli = Cli::parse_from(["prrr", "server", "client", "export", "alice", "--output", "/tmp/client.toml"]);
        match cli.command {
            Command::Server(args) => match args.subcommand {
                Some(ServerSubcommand::Client(sc)) => match sc.action {
                    ServerClientAction::Export { ref name, qr, ref output } => {
                        assert_eq!(name, "alice");
                        assert!(!qr);
                        assert_eq!(output.as_deref(), Some(Path::new("/tmp/client.toml")));
                    }
                    _ => panic!("expected Export action"),
                },
                _ => panic!("expected Client subcommand"),
            },
            _ => panic!("expected Server command"),
        }
    }

    // AC-B9: prrr client import /path/to/config.toml
    #[test]
    fn cli_client_import_parses() {
        let cli = Cli::parse_from(["prrr", "client", "import", "/tmp/client.toml"]);
        match cli.command {
            Command::Client(args) => match args.subcommand {
                Some(ClientSubcommand::Import { ref source }) => {
                    assert_eq!(source, "/tmp/client.toml");
                }
                _ => panic!("expected Import subcommand"),
            },
            _ => panic!("expected Client command"),
        }
    }

    // AC-B9b: prrr client import with prrr:// URL
    #[test]
    fn cli_client_import_url_parses() {
        let url = "prrr://import?z=dGVzdA";
        let cli = Cli::parse_from(["prrr", "client", "import", url]);
        match cli.command {
            Command::Client(args) => match args.subcommand {
                Some(ClientSubcommand::Import { ref source }) => {
                    assert_eq!(source, url);
                }
                _ => panic!("expected Import subcommand"),
            },
            _ => panic!("expected Client command"),
        }
    }

    // AC-B4: prrr server (no subcommand) = start server (backward compat)
    #[test]
    fn cli_server_no_subcommand_starts_server() {
        let cli = Cli::parse_from(["prrr", "server", "--listen", "0.0.0.0:443"]);
        match cli.command {
            Command::Server(args) => {
                assert!(args.subcommand.is_none());
                assert_eq!(args.listen.to_string(), "0.0.0.0:443");
            }
            _ => panic!("expected Server command"),
        }
    }

    // AC-B10: prrr client --server <ADDR> (no subcommand) = connect (backward compat)
    #[test]
    fn cli_client_connect_backward_compat() {
        let cli = Cli::parse_from(["prrr", "client", "--server", "10.0.0.1:443"]);
        match cli.command {
            Command::Client(args) => {
                assert!(args.subcommand.is_none());
                assert_eq!(args.server, Some("10.0.0.1:443".parse().expect("valid addr")));
            }
            _ => panic!("expected Client command"),
        }
    }

    // -----------------------------------------------------------------------
    // ServerConfig tests (FRD-P001)
    // -----------------------------------------------------------------------

    // AC-1: Empty TOML parses to ServerConfig::default()
    #[test]
    fn server_config_empty_toml() {
        let config: ServerConfig = toml::from_str("").expect("parse empty toml");
        assert_eq!(config, ServerConfig::default());
    }

    // AC-2: Full TOML with all sections parses correctly
    #[test]
    fn server_config_full_toml() {
        let toml_str = r#"
[server]
listen_addr = "0.0.0.0:443"
max_clients = 100
log_level = "info"
data_dir = "/var/lib/prrr"
server_name = "www.google.com"

[network]
subnet = "10.66.66.0/24"
dns_servers = ["1.1.1.1", "8.8.8.8"]
mtu = 1100

[crypto]
identity_key_path = "/etc/prrr/keys/server_identity.key"
pq_key_path = "/etc/prrr/keys/server_pq.key"
rekey_interval = 3600

[[transports]]
name = "masque"
enabled = true
max_idle_timeout = 300
keep_alive = 25
tls_cert = "/etc/prrr/tls/fullchain.pem"
tls_key = "/etc/prrr/tls/privkey.pem"

[[transports]]
name = "harp"
enabled = true

[obfuscation]
enabled = true
padding_strategy = "power-of-two"
timing_jitter_ms = 50
tls_profile = "chrome"

[obfuscation.probe_resist]
enabled = true
psk = ""
tokens_per_second = 20
burst_capacity = 5

[web_admin]
enabled = true
listen_addr = "0.0.0.0:8443"
tls_cert = "/etc/prrr/tls/server.crt"
tls_key = "/etc/prrr/tls/server.key"
admin_password_hash = "$argon2id$..."
session_timeout = 3600

[messaging]
enabled = true
relay_mode = "server"
max_message_size = 10485760
retention_days = 30

[monitoring]
metrics_enabled = true
prometheus_port = 9090
log_file = "/var/log/prrr/server.log"
log_rotation = "daily"
log_retention_days = 7
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse full toml");

        let srv = config.server.expect("server section");
        assert_eq!(srv.listen_addr.as_deref(), Some(DEFAULT_LISTEN_ADDR));
        assert_eq!(srv.max_clients, Some(DEFAULT_MAX_CLIENTS));
        assert_eq!(srv.log_level.as_deref(), Some(DEFAULT_LOG_LEVEL));
        assert_eq!(srv.data_dir.as_deref(), Some(DEFAULT_DATA_DIR));
        assert_eq!(srv.server_name.as_deref(), Some("www.google.com"));

        let net = config.network.expect("network section");
        assert_eq!(net.subnet.as_deref(), Some(DEFAULT_SUBNET));
        assert_eq!(
            net.dns_servers.as_deref(),
            Some(&["1.1.1.1".to_string(), "8.8.8.8".to_string()][..])
        );
        assert_eq!(net.mtu, Some(DEFAULT_MTU));

        let crypto = config.crypto.expect("crypto section");
        assert_eq!(crypto.identity_key_path.as_deref(), Some(DEFAULT_IDENTITY_KEY_PATH));
        assert_eq!(crypto.pq_key_path.as_deref(), Some(DEFAULT_PQ_KEY_PATH));
        assert_eq!(crypto.rekey_interval, Some(DEFAULT_REKEY_INTERVAL));

        let transports = config.transports.expect("transports section");
        assert_eq!(transports.len(), 2);
        match &transports[0] {
            TransportEntry::Masque(m) => {
                assert_eq!(m.enabled, Some(true));
                assert_eq!(m.max_idle_timeout, Some(DEFAULT_MAX_IDLE_TIMEOUT));
                assert_eq!(m.keep_alive, Some(DEFAULT_KEEP_ALIVE));
                assert_eq!(m.tls_cert.as_deref(), Some("/etc/prrr/tls/fullchain.pem"));
                assert_eq!(m.tls_key.as_deref(), Some("/etc/prrr/tls/privkey.pem"));
            }
            _ => panic!("expected Masque entry at index 0"),
        }
        assert!(matches!(&transports[1], TransportEntry::Harp(_)));

        let obfs = config.obfuscation.expect("obfuscation section");
        assert_eq!(obfs.enabled, Some(true));
        assert_eq!(obfs.padding_strategy.as_deref(), Some(DEFAULT_PADDING_STRATEGY));
        assert_eq!(obfs.timing_jitter_ms, Some(DEFAULT_TIMING_JITTER_MS));
        assert_eq!(obfs.tls_profile.as_deref(), Some(DEFAULT_TLS_PROFILE));

        let pr = obfs.probe_resist.expect("probe_resist sub-section");
        assert_eq!(pr.enabled, Some(true));
        assert_eq!(pr.psk.as_deref(), Some(""));
        assert_eq!(pr.tokens_per_second, Some(DEFAULT_PROBE_RESIST_TOKENS_PER_SEC));
        assert_eq!(pr.burst_capacity, Some(DEFAULT_PROBE_RESIST_BURST));

        let web = config.web_admin.expect("web_admin section");
        assert_eq!(web.enabled, Some(true));
        assert_eq!(web.listen_addr.as_deref(), Some(DEFAULT_WEB_ADMIN_ADDR));
        assert_eq!(web.tls_cert.as_deref(), Some("/etc/prrr/tls/server.crt"));
        assert_eq!(web.tls_key.as_deref(), Some("/etc/prrr/tls/server.key"));
        assert_eq!(web.admin_password_hash.as_deref(), Some("$argon2id$..."));
        assert_eq!(web.session_timeout, Some(DEFAULT_SESSION_TIMEOUT));

        let msg = config.messaging.expect("messaging section");
        assert_eq!(msg.enabled, Some(true));
        assert_eq!(msg.relay_mode.as_deref(), Some(DEFAULT_RELAY_MODE));
        assert_eq!(msg.max_message_size, Some(DEFAULT_MAX_MESSAGE_SIZE));
        assert_eq!(msg.retention_days, Some(DEFAULT_RETENTION_DAYS));

        let mon = config.monitoring.expect("monitoring section");
        assert_eq!(mon.metrics_enabled, Some(true));
        assert_eq!(mon.prometheus_port, Some(DEFAULT_PROMETHEUS_PORT));
        assert_eq!(mon.log_file.as_deref(), Some("/var/log/prrr/server.log"));
        assert_eq!(mon.log_rotation.as_deref(), Some(DEFAULT_LOG_ROTATION));
        assert_eq!(mon.log_retention_days, Some(DEFAULT_LOG_RETENTION_DAYS));
    }

    // AC-3: Partial TOML (only [server] section) — other sections are None
    #[test]
    fn server_config_partial() {
        let toml_str = r#"
[server]
max_clients = 50
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse partial toml");
        let srv = config.server.expect("server section present");
        assert_eq!(srv.max_clients, Some(50));
        assert!(srv.listen_addr.is_none());
        assert!(config.network.is_none());
        assert!(config.crypto.is_none());
        assert!(config.transports.is_none());
        assert!(config.obfuscation.is_none());
        assert!(config.web_admin.is_none());
        assert!(config.messaging.is_none());
        assert!(config.monitoring.is_none());
    }

    // AC-DPI002: MASQUE transport without TLS fields parses to None
    #[test]
    fn masque_transport_without_tls_fields_parses_to_none() {
        let toml_str = r#"
[[transports]]
name = "masque"
max_idle_timeout = 300
keep_alive = 25
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse masque without tls");
        let transports = config.transports.expect("transports present");
        match &transports[0] {
            TransportEntry::Masque(m) => {
                assert!(m.tls_cert.is_none());
                assert!(m.tls_key.is_none());
            }
            _ => panic!("expected Masque entry"),
        }
    }

    // AC-DPI002b: MASQUE transport with only tls_cert parses correctly
    #[test]
    fn masque_transport_with_tls_cert_only() {
        let toml_str = r#"
[[transports]]
name = "masque"
tls_cert = "/etc/prrr/tls/fullchain.pem"
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse masque with cert only");
        let transports = config.transports.expect("transports present");
        match &transports[0] {
            TransportEntry::Masque(m) => {
                assert_eq!(m.tls_cert.as_deref(), Some("/etc/prrr/tls/fullchain.pem"));
                assert!(m.tls_key.is_none());
            }
            _ => panic!("expected Masque entry"),
        }
    }

    // AC-4: Unknown fields in TOML are silently ignored
    #[test]
    fn server_config_unknown_fields() {
        let toml_str = r#"
[server]
listen_addr = "0.0.0.0:443"
some_future_field = true

[future_section]
foo = "bar"
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("unknown fields ignored");
        let srv = config.server.expect("server section");
        assert_eq!(srv.listen_addr.as_deref(), Some(DEFAULT_LISTEN_ADDR));
    }

    // AC-5: Old minimal flat TOML no longer maps to ServerConfig.server section
    // (the old flat format is intentionally not backward-compatible at the
    //  struct level — callers that used TomlConfig must migrate to ServerConfig)
    #[test]
    fn server_config_flat_fields_ignored() {
        let toml_str = r#"
listen = "0.0.0.0:8443"
log_level = "debug"
"#;
        // Flat fields are unknown at the top level and silently ignored
        let config: ServerConfig = toml::from_str(toml_str).expect("flat fields ignored");
        assert_eq!(config, ServerConfig::default());
    }

    // -----------------------------------------------------------------------
    // ClientConfigFile tests (FRD-P001)
    // -----------------------------------------------------------------------

    // AC-6: Empty TOML parses to ClientConfigFile::default()
    #[test]
    fn client_config_empty_toml() {
        let config: ClientConfigFile = toml::from_str("").expect("parse empty toml");
        assert_eq!(config, ClientConfigFile::default());
    }

    // AC-7: Full client TOML parses correctly
    #[test]
    fn client_config_full_toml() {
        let toml_str = r#"
[client]
name = "laptop-fedora"
auto_connect = false
log_level = "info"

[server]
endpoint = "vpn.example.com:443"
public_key = "wG5kaFGLAHzkdKr/8LLXu0K1NhVYYQ3dqp7A3Qwxj3k="
pq_public_key = "AQIDBA=="

[interface]
private_key_path = "/home/user/.local/share/prrr/keys/client.key"
pq_private_key_path = "/home/user/.local/share/prrr/keys/client_pq.key"
address = "10.66.66.2/32"
dns = ["1.1.1.1", "8.8.8.8"]
mtu = 1100

[routing]
all_traffic = true
allowed_ips = ["0.0.0.0/0", "::/0"]
excluded_ips = ["192.168.0.0/16", "10.0.0.0/8"]

[transport]
protocol = "masque"
keep_alive = 25

[obfuscation]
enabled = true

[messaging]
enabled = true
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse full client toml");

        let client = config.client.expect("client section");
        assert_eq!(client.name.as_deref(), Some("laptop-fedora"));
        assert_eq!(client.auto_connect, Some(false));
        assert_eq!(client.log_level.as_deref(), Some(DEFAULT_LOG_LEVEL));

        let srv = config.server.expect("server section");
        assert_eq!(srv.endpoint.as_deref(), Some("vpn.example.com:443"));
        assert!(srv.public_key.is_some());
        assert!(srv.pq_public_key.is_some());

        let iface = config.interface.expect("interface section");
        assert!(iface.private_key_path.is_some());
        assert!(iface.pq_private_key_path.is_some());
        assert_eq!(iface.address.as_deref(), Some("10.66.66.2/32"));
        assert_eq!(iface.mtu, Some(DEFAULT_MTU));

        let routing = config.routing.expect("routing section");
        assert_eq!(routing.all_traffic, Some(true));
        assert!(routing.allowed_ips.is_some());
        assert!(routing.excluded_ips.is_some());

        let transport = config.transport.expect("transport section");
        assert_eq!(transport.protocol.as_deref(), Some(DEFAULT_TRANSPORT_PROTOCOL));
        assert_eq!(transport.keep_alive, Some(DEFAULT_KEEP_ALIVE));

        let obfs = config.obfuscation.expect("obfuscation section");
        assert_eq!(obfs.enabled, Some(true));

        let msg = config.messaging.expect("messaging section");
        assert_eq!(msg.enabled, Some(true));
    }

    // AC-7b: Partial client TOML
    #[test]
    fn client_config_partial() {
        let toml_str = r#"
[server]
endpoint = "10.0.0.1:443"
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse partial");
        assert!(config.client.is_none());
        let srv = config.server.expect("server section");
        assert_eq!(srv.endpoint.as_deref(), Some("10.0.0.1:443"));
        assert!(config.interface.is_none());
    }

    // AC-7c: Client config with unknown fields
    #[test]
    fn client_config_unknown_fields() {
        let toml_str = r#"
[client]
name = "test"
future_flag = true

[unknown_section]
x = 1
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("unknown fields ignored");
        let client = config.client.expect("client section");
        assert_eq!(client.name.as_deref(), Some("test"));
    }

    // -----------------------------------------------------------------------
    // Config loading tests (FRD-P001)
    // -----------------------------------------------------------------------

    // AC-8: load_server_config(None) returns default
    #[test]
    fn load_server_config_none() {
        let config = load_server_config(None).expect("should succeed");
        assert_eq!(config, ServerConfig::default());
    }

    // AC-9: load_server_config with nonexistent path returns error
    #[test]
    fn load_server_config_missing_file() {
        let path = PathBuf::from("/nonexistent/server.toml");
        let result = load_server_config(Some(&path));
        assert!(result.is_err());
    }

    // AC-10: load_server_config with valid file
    #[test]
    fn load_server_config_valid() {
        let dir = std::env::temp_dir().join("prrr-test-server-config");
        std::fs::create_dir_all(&dir).expect("create dir");
        let path = dir.join("server.toml");
        std::fs::write(&path, "[server]\nmax_clients = 200\n").expect("write file");

        let config = load_server_config(Some(&path)).expect("should succeed");
        let srv = config.server.expect("server section");
        assert_eq!(srv.max_clients, Some(200));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    // AC-12: load_client_config with valid file
    #[test]
    fn load_client_config_valid() {
        let dir = std::env::temp_dir().join("prrr-test-client-config");
        std::fs::create_dir_all(&dir).expect("create dir");
        let path = dir.join("client.toml");
        std::fs::write(&path, "[client]\nname = \"test-client\"\n").expect("write file");

        let config = load_client_config(Some(&path)).expect("should succeed");
        let client = config.client.expect("client section");
        assert_eq!(client.name.as_deref(), Some("test-client"));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    // AC-12b: load_client_config(None) returns default
    #[test]
    fn load_client_config_none() {
        let config = load_client_config(None).expect("should succeed");
        assert_eq!(config, ClientConfigFile::default());
    }

    // AC-12c: load_client_config with nonexistent path returns error
    #[test]
    fn load_client_config_missing_file() {
        let path = PathBuf::from("/nonexistent/client.toml");
        let result = load_client_config(Some(&path));
        assert!(result.is_err());
    }

    // FRD: specs/frds/FRD-20260223-pluggable-transport-config.md
    // T-STEP13-3: Server config parses [[transports]] with both MASQUE and HARP
    #[test]
    fn server_config_transports_array() {
        let toml_str = r#"
[[transports]]
name = "masque"
enabled = true
max_idle_timeout = 300
keep_alive = 25
tls_cert = "/etc/prrr/tls/fullchain.pem"
tls_key = "/etc/prrr/tls/privkey.pem"

[[transports]]
name = "harp"
enabled = true
websocket_enabled = true
polling_enabled = false
session_idle_timeout = 600
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse transports array");
        let transports = config.transports.expect("transports present");
        assert_eq!(transports.len(), 2);
        match &transports[0] {
            TransportEntry::Masque(m) => {
                assert_eq!(m.enabled, Some(true));
                assert_eq!(m.max_idle_timeout, Some(DEFAULT_MAX_IDLE_TIMEOUT));
                assert_eq!(m.keep_alive, Some(DEFAULT_KEEP_ALIVE));
                assert_eq!(m.tls_cert.as_deref(), Some("/etc/prrr/tls/fullchain.pem"));
                assert_eq!(m.tls_key.as_deref(), Some("/etc/prrr/tls/privkey.pem"));
            }
            _ => panic!("expected Masque entry at index 0"),
        }
        match &transports[1] {
            TransportEntry::Harp(h) => {
                assert_eq!(h.enabled, Some(true));
                assert_eq!(h.websocket_enabled, Some(true));
                assert_eq!(h.polling_enabled, Some(false));
                assert_eq!(h.session_idle_timeout, Some(600));
            }
            _ => panic!("expected Harp entry at index 1"),
        }
    }

    // T-STEP13-4: Server config parses [[transports]] with only MASQUE
    #[test]
    fn server_config_transports_masque_only() {
        let toml_str = r#"
[[transports]]
name = "masque"
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse masque-only");
        let transports = config.transports.expect("transports present");
        assert_eq!(transports.len(), 1);
        assert!(matches!(&transports[0], TransportEntry::Masque(_)));
    }

    // T-STEP13-5: Server config parses [[transports]] with only HARP
    #[test]
    fn server_config_transports_harp_only() {
        let toml_str = r#"
[[transports]]
name = "harp"
session_idle_timeout = 300
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse harp-only");
        let transports = config.transports.expect("transports present");
        assert_eq!(transports.len(), 1);
        match &transports[0] {
            TransportEntry::Harp(h) => {
                assert_eq!(h.session_idle_timeout, Some(300));
            }
            _ => panic!("expected Harp entry"),
        }
    }

    // T-STEP13-6: Empty server config has no transports (None)
    #[test]
    fn server_config_no_transports_defaults() {
        let config: ServerConfig = toml::from_str("").expect("parse empty");
        assert!(config.transports.is_none());
    }

    // T-STEP13-7: resolve_server_transports with both entries returns both
    #[test]
    fn resolve_transports_from_array() {
        let toml_str = r#"
[[transports]]
name = "masque"
max_idle_timeout = 200
keep_alive = 10

[[transports]]
name = "harp"
session_idle_timeout = 400
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse");
        let resolved = resolve_server_transports(&config);
        assert_eq!(resolved.len(), 2);
        match &resolved[0] {
            ResolvedTransport::Masque {
                max_idle_timeout,
                keep_alive,
                ..
            } => {
                assert_eq!(*max_idle_timeout, 200);
                assert_eq!(*keep_alive, 10);
            }
            _ => panic!("expected Masque"),
        }
        match &resolved[1] {
            ResolvedTransport::Harp { session_idle_timeout, .. } => {
                assert_eq!(*session_idle_timeout, 400);
            }
            _ => panic!("expected Harp"),
        }
    }

    // T-STEP13-8: resolve_server_transports with no transports defaults to HARP
    #[test]
    fn resolve_transports_default() {
        let config: ServerConfig = toml::from_str("").expect("parse empty");
        let resolved = resolve_server_transports(&config);
        assert_eq!(resolved.len(), 1);
        match &resolved[0] {
            ResolvedTransport::Harp {
                websocket_enabled,
                polling_enabled,
                session_idle_timeout,
                ..
            } => {
                assert!(*websocket_enabled);
                assert!(*polling_enabled);
                assert_eq!(*session_idle_timeout, DEFAULT_HARP_SESSION_IDLE_TIMEOUT);
            }
            _ => panic!("expected default Harp"),
        }
    }

    // T-STEP13-9: resolve_server_transports filters out disabled entries
    #[test]
    fn resolve_transports_disabled_filtered() {
        let toml_str = r#"
[[transports]]
name = "masque"
enabled = false

[[transports]]
name = "harp"
enabled = true
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse");
        let resolved = resolve_server_transports(&config);
        assert_eq!(resolved.len(), 1);
        assert!(matches!(&resolved[0], ResolvedTransport::Harp { .. }));
    }

    // T-STEP13-10: HARP defaults: websocket=true, polling=true, timeout=300
    #[test]
    fn resolve_transports_harp_defaults() {
        let toml_str = r#"
[[transports]]
name = "harp"
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse");
        let resolved = resolve_server_transports(&config);
        assert_eq!(resolved.len(), 1);
        match &resolved[0] {
            ResolvedTransport::Harp {
                websocket_enabled,
                polling_enabled,
                session_idle_timeout,
                ..
            } => {
                assert!(*websocket_enabled);
                assert!(*polling_enabled);
                assert_eq!(*session_idle_timeout, DEFAULT_HARP_SESSION_IDLE_TIMEOUT);
            }
            _ => panic!("expected Harp"),
        }
    }

    // AC-11: All default constants match SPEC.md values
    #[test]
    fn defaults_match_spec() {
        assert_eq!(DEFAULT_LISTEN_ADDR, "0.0.0.0:443");
        assert_eq!(DEFAULT_LOG_LEVEL, "info");
        assert_eq!(DEFAULT_SERVER_SERVER_NAME, "localhost");
        assert_eq!(DEFAULT_MAX_CLIENTS, 100);
        assert_eq!(DEFAULT_DATA_DIR, "/var/lib/prrr");
        assert_eq!(DEFAULT_SUBNET, "10.66.66.0/24");
        assert_eq!(DEFAULT_DNS_SERVERS, &["1.1.1.1", "8.8.8.8"]);
        assert_eq!(DEFAULT_MTU, 1100);
        assert_eq!(DEFAULT_IDENTITY_KEY_PATH, "/etc/prrr/keys/server_identity.key");
        assert_eq!(DEFAULT_PQ_KEY_PATH, "/etc/prrr/keys/server_pq.key");
        assert_eq!(DEFAULT_REKEY_INTERVAL, 3600);
        assert_eq!(DEFAULT_TRANSPORT_PROTOCOL, "masque");
        assert_eq!(DEFAULT_MAX_IDLE_TIMEOUT, 300);
        assert_eq!(DEFAULT_KEEP_ALIVE, 25);
        assert_eq!(DEFAULT_PADDING_STRATEGY, "power-of-two");
        assert_eq!(DEFAULT_TIMING_JITTER_MS, 50);
        assert_eq!(DEFAULT_TLS_PROFILE, "chrome");
        assert_eq!(DEFAULT_PROBE_RESIST_TOKENS_PER_SEC, 20);
        assert_eq!(DEFAULT_PROBE_RESIST_BURST, 5);
        assert_eq!(DEFAULT_WEB_ADMIN_ADDR, "0.0.0.0:8443");
        assert_eq!(DEFAULT_SESSION_TIMEOUT, 3600);
        assert_eq!(DEFAULT_RELAY_MODE, "server");
        assert_eq!(DEFAULT_MAX_MESSAGE_SIZE, 10_485_760);
        assert_eq!(DEFAULT_RETENTION_DAYS, 30);
        assert_eq!(DEFAULT_PROMETHEUS_PORT, 9090);
        assert_eq!(DEFAULT_LOG_ROTATION, "daily");
        assert_eq!(DEFAULT_LOG_RETENTION_DAYS, 7);
    }

    /// MTU constants must be consistent across config and tunnel layers.
    /// If these drift, clients get a different MTU than the server expects,
    /// causing silent QUIC datagram drops.
    #[test]
    fn config_and_tun_device_default_mtu_match() {
        assert_eq!(
            DEFAULT_MTU,
            crate::tunnel::tun_device::DEFAULT_TUNNEL_MTU,
            "config::DEFAULT_MTU and tunnel::DEFAULT_TUNNEL_MTU must be identical"
        );
    }

    // -----------------------------------------------------------------------
    // Key resolution tests (FRD-P003)
    // -----------------------------------------------------------------------

    // T-P003-2: Resolve noise key from CLI flag
    #[test]
    fn client_resolve_noise_key_from_flag() {
        let key_bytes = [0xABu8; PUBLIC_KEY_LEN];
        let b64 = BASE64_STANDARD.encode(key_bytes);
        let result = resolve_server_noise_key(Some(&b64), None).expect("should decode");
        assert_eq!(result, key_bytes);
    }

    // T-P003-3: Resolve noise key from config (fallback)
    #[test]
    fn client_resolve_noise_key_from_config() {
        let key_bytes = [0xCDu8; PUBLIC_KEY_LEN];
        let b64 = BASE64_STANDARD.encode(key_bytes);
        let result = resolve_server_noise_key(None, Some(&b64)).expect("should decode");
        assert_eq!(result, key_bytes);
    }

    // T-P003-4: CLI flag takes priority over config for noise key
    #[test]
    fn client_resolve_noise_key_flag_priority() {
        let flag_bytes = [0x01u8; PUBLIC_KEY_LEN];
        let config_bytes = [0x02u8; PUBLIC_KEY_LEN];
        let flag_b64 = BASE64_STANDARD.encode(flag_bytes);
        let config_b64 = BASE64_STANDARD.encode(config_bytes);
        let result = resolve_server_noise_key(Some(&flag_b64), Some(&config_b64)).expect("should decode");
        assert_eq!(result, flag_bytes);
    }

    // T-P003-5: Missing noise key returns error
    #[test]
    fn client_missing_noise_key_error() {
        let err = resolve_server_noise_key(None, None).unwrap_err();
        assert!(
            err.to_string().contains(ERR_MISSING_NOISE_KEY),
            "error should mention missing key: {err}"
        );
    }

    // T-P003-6: Invalid base64 noise key returns error
    #[test]
    fn client_invalid_base64_noise_error() {
        let err = resolve_server_noise_key(Some("not-valid-base64!!!"), None).unwrap_err();
        assert!(
            err.to_string().contains(ERR_INVALID_BASE64),
            "error should mention invalid base64: {err}"
        );
    }

    // T-P003-7: Wrong-length noise key returns error
    #[test]
    fn client_wrong_noise_key_length_error() {
        let short_bytes = [0xAAu8; 16]; // 16 bytes, not 32
        let b64 = BASE64_STANDARD.encode(short_bytes);
        let err = resolve_server_noise_key(Some(&b64), None).unwrap_err();
        assert!(
            err.to_string().contains(ERR_WRONG_NOISE_KEY_LEN),
            "error should mention wrong length: {err}"
        );
    }

    // T-P003-8: Resolve KEM key from CLI flag
    #[test]
    fn client_resolve_kem_key_from_flag() {
        let key_bytes = vec![0xBBu8; KEM_ENCAPSULATION_KEY_LEN];
        let b64 = BASE64_STANDARD.encode(&key_bytes);
        let result = resolve_server_kem_key(Some(&b64), None).expect("should decode");
        assert_eq!(result, key_bytes);
    }

    // T-P003-9: Resolve KEM key from config (fallback)
    #[test]
    fn client_resolve_kem_key_from_config() {
        let key_bytes = vec![0xDDu8; KEM_ENCAPSULATION_KEY_LEN];
        let b64 = BASE64_STANDARD.encode(&key_bytes);
        let result = resolve_server_kem_key(None, Some(&b64)).expect("should decode");
        assert_eq!(result, key_bytes);
    }

    // T-P003-10: CLI flag takes priority over config for KEM key
    #[test]
    fn client_resolve_kem_key_flag_priority() {
        let flag_bytes = vec![0x01u8; KEM_ENCAPSULATION_KEY_LEN];
        let config_bytes = vec![0x02u8; KEM_ENCAPSULATION_KEY_LEN];
        let flag_b64 = BASE64_STANDARD.encode(&flag_bytes);
        let config_b64 = BASE64_STANDARD.encode(&config_bytes);
        let result = resolve_server_kem_key(Some(&flag_b64), Some(&config_b64)).expect("should decode");
        assert_eq!(result, flag_bytes);
    }

    // T-P003-11: Missing KEM key returns error
    #[test]
    fn client_missing_kem_key_error() {
        let err = resolve_server_kem_key(None, None).unwrap_err();
        assert!(
            err.to_string().contains(ERR_MISSING_KEM_KEY),
            "error should mention missing key: {err}"
        );
    }

    // T-P003-12: Invalid base64 KEM key returns error
    #[test]
    fn client_invalid_base64_kem_error() {
        let err = resolve_server_kem_key(Some("not-valid-base64!!!"), None).unwrap_err();
        assert!(
            err.to_string().contains(ERR_INVALID_BASE64),
            "error should mention invalid base64: {err}"
        );
    }

    // T-P003-13: Wrong-length KEM key returns error
    #[test]
    fn client_wrong_kem_key_length_error() {
        let short_bytes = [0xAAu8; 64]; // 64 bytes, not 1184
        let b64 = BASE64_STANDARD.encode(short_bytes);
        let err = resolve_server_kem_key(Some(&b64), None).unwrap_err();
        assert!(
            err.to_string().contains(ERR_WRONG_KEM_KEY_LEN),
            "error should mention wrong length: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // P-010: Doctor subcommand parsing tests
    // -----------------------------------------------------------------------

    // AC-21: prrr server doctor
    #[test]
    fn cli_server_doctor_parses() {
        let cli = Cli::parse_from(["prrr", "server", "doctor"]);
        match cli.command {
            Command::Server(args) => {
                assert!(matches!(args.subcommand, Some(ServerSubcommand::Doctor)));
            }
            _ => panic!("expected Server command"),
        }
    }

    // AC-22: prrr client doctor
    #[test]
    fn cli_client_doctor_parses() {
        let cli = Cli::parse_from(["prrr", "client", "doctor"]);
        match cli.command {
            Command::Client(args) => {
                assert!(matches!(args.subcommand, Some(ClientSubcommand::Doctor)));
            }
            _ => panic!("expected Client command"),
        }
    }

    // -----------------------------------------------------------------------
    // FRD: specs/frds/FRD-20260224-tls-profile-config.md
    // Step 1.1: tls_profile config field
    // -----------------------------------------------------------------------

    // AC-1: TOML with tls_profile = "chrome" parses to Some("chrome")
    #[test]
    fn client_transport_tls_profile_chrome() {
        let toml_str = r#"
[transport]
protocol = "harp"
tls_profile = "chrome"
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert_eq!(
            transport.tls_profile.as_deref(),
            Some("chrome"),
            "tls_profile should parse as Some(\"chrome\")"
        );
    }

    // AC-2: TOML with tls_profile = "firefox" parses to Some("firefox")
    #[test]
    fn client_transport_tls_profile_firefox() {
        let toml_str = r#"
[transport]
protocol = "harp"
tls_profile = "firefox"
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert_eq!(
            transport.tls_profile.as_deref(),
            Some("firefox"),
            "tls_profile should parse as Some(\"firefox\")"
        );
    }

    // AC-3: TOML with tls_profile = "default" parses to Some("default")
    #[test]
    fn client_transport_tls_profile_default_value() {
        let toml_str = r#"
[transport]
protocol = "harp"
tls_profile = "default"
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert_eq!(
            transport.tls_profile.as_deref(),
            Some("default"),
            "tls_profile should parse as Some(\"default\")"
        );
    }

    // AC-4: TOML without tls_profile defaults to None
    #[test]
    fn client_transport_tls_profile_absent() {
        let toml_str = r#"
[transport]
protocol = "harp"
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert!(transport.tls_profile.is_none(), "tls_profile should be None when absent");
    }

    // AC-5: TOML with unknown tls_profile = "safari" preserves the raw string
    #[test]
    fn client_transport_tls_profile_unknown_preserved() {
        let toml_str = r#"
[transport]
protocol = "harp"
tls_profile = "safari"
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert_eq!(
            transport.tls_profile.as_deref(),
            Some("safari"),
            "unknown tls_profile should be preserved as raw string"
        );
    }

    // -----------------------------------------------------------------------
    // FRD: specs/frds/FRD-20260224-cover-page-config.md
    // Step 2.3: cover_page_enabled config field
    // -----------------------------------------------------------------------

    // AC-1: web_admin with cover_page_enabled = false parses correctly
    #[test]
    fn web_admin_cover_page_disabled() {
        let toml_str = r#"
[server]
name = "test"

[web_admin]
enabled = true
cover_page_enabled = false
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse server config");
        let web = config.web_admin.expect("web_admin section present");
        assert_eq!(web.cover_page_enabled, Some(false));
    }

    // -----------------------------------------------------------------------
    // FRD: specs/frds/FRD-20260224-cdn-fronting-config.md
    // Step 3.1: CDN fronting config fields
    // -----------------------------------------------------------------------

    // AC-1: TOML with all CDN fronting fields parses correctly
    #[test]
    fn client_transport_cdn_fronting_full() {
        let toml_str = r#"
[transport]
protocol = "harp"
cdn_fronting_enabled = true
cdn_fronting_domain = "prrr.tech"
direct_timeout_secs = 10
direct_retry_interval_secs = 300
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert_eq!(transport.cdn_fronting_enabled, Some(true));
        assert_eq!(transport.cdn_fronting_domain.as_deref(), Some("prrr.tech"));
        assert_eq!(transport.direct_timeout_secs, Some(10));
        assert_eq!(transport.direct_retry_interval_secs, Some(300));
    }

    // AC-2: TOML without CDN fields defaults all to None
    #[test]
    fn client_transport_cdn_fronting_absent() {
        let toml_str = r#"
[transport]
protocol = "harp"
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert!(transport.cdn_fronting_enabled.is_none());
        assert!(transport.cdn_fronting_domain.is_none());
        assert!(transport.direct_timeout_secs.is_none());
        assert!(transport.direct_retry_interval_secs.is_none());
    }

    // AC-3: Partial CDN config (enabled=true, no domain) is representable
    #[test]
    fn client_transport_cdn_fronting_partial() {
        let toml_str = r#"
[transport]
protocol = "harp"
cdn_fronting_enabled = true
direct_timeout_secs = 5
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client transport");
        let transport = config.transport.expect("transport section present");
        assert_eq!(transport.cdn_fronting_enabled, Some(true));
        assert!(transport.cdn_fronting_domain.is_none(), "domain should be None when absent");
        assert_eq!(transport.direct_timeout_secs, Some(DEFAULT_DIRECT_TIMEOUT_SECS));
        assert!(transport.direct_retry_interval_secs.is_none());
    }

    // AC-2: web_admin without cover_page_enabled defaults to None (caller defaults true)
    #[test]
    fn web_admin_cover_page_default() {
        let toml_str = r#"
[server]
name = "test"

[web_admin]
enabled = true
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse server config");
        let web = config.web_admin.expect("web_admin section present");
        assert!(web.cover_page_enabled.is_none(), "cover_page_enabled should be None when absent");
    }

    // -----------------------------------------------------------------------
    // FRD: specs/frds/FRD-20260224-cdn-header-parsing.md
    // Step 3.5: trust_proxy_headers config field
    // -----------------------------------------------------------------------

    // AC-1: web_admin with trust_proxy_headers = true parses correctly
    #[test]
    fn server_config_trust_proxy_headers_enabled() {
        let toml_str = r#"
[web_admin]
enabled = true
trust_proxy_headers = true
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse server config");
        let web = config.web_admin.expect("web_admin section present");
        assert_eq!(web.trust_proxy_headers, Some(true));
    }

    // AC-2: web_admin with trust_proxy_headers = false parses correctly
    #[test]
    fn server_config_trust_proxy_headers_disabled() {
        let toml_str = r#"
[web_admin]
enabled = true
trust_proxy_headers = false
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse server config");
        let web = config.web_admin.expect("web_admin section present");
        assert_eq!(web.trust_proxy_headers, Some(false));
    }

    // AC-3: web_admin without trust_proxy_headers defaults to None
    #[test]
    fn server_config_trust_proxy_headers_absent() {
        let toml_str = r#"
[web_admin]
enabled = true
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse server config");
        let web = config.web_admin.expect("web_admin section present");
        assert!(web.trust_proxy_headers.is_none(), "trust_proxy_headers should be None when absent");
    }

    // -----------------------------------------------------------------------
    // FRD: specs/frds/FRD-20260224-h2-dependency-config.md
    // Step 4.1: h2 dependency and config fields
    // -----------------------------------------------------------------------

    // AC-1: h2 crate is accessible (compile-time check)
    #[test]
    fn h2_crate_accessible() {
        // Verify h2 types are usable — confirms the dependency compiles
        let _reason = h2::Reason::NO_ERROR;
    }

    // AC-2: hyper http2 feature is active (compile-time check)
    #[test]
    fn hyper_http2_feature_active() {
        // http2::Builder is only available when hyper's "http2" feature is enabled
        let _builder = hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
    }

    // AC-3: Server HARP config with h2_streaming_enabled = true parses
    #[test]
    fn harp_config_h2_enabled() {
        let toml_str = r#"
[[transports]]
name = "harp"
h2_streaming_enabled = true
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse harp h2 enabled");
        let transports = config.transports.expect("transports present");
        match &transports[0] {
            TransportEntry::Harp(h) => {
                assert_eq!(h.h2_streaming_enabled, Some(true));
            }
            _ => panic!("expected Harp entry"),
        }
    }

    // AC-4: Server HARP config with h2_streaming_enabled = false parses
    #[test]
    fn harp_config_h2_disabled() {
        let toml_str = r#"
[[transports]]
name = "harp"
h2_streaming_enabled = false
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse harp h2 disabled");
        let transports = config.transports.expect("transports present");
        match &transports[0] {
            TransportEntry::Harp(h) => {
                assert_eq!(h.h2_streaming_enabled, Some(false));
            }
            _ => panic!("expected Harp entry"),
        }
    }

    // AC-5: Server HARP config without h2_streaming_enabled defaults to None
    #[test]
    fn harp_config_h2_absent() {
        let toml_str = r#"
[[transports]]
name = "harp"
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse harp without h2");
        let transports = config.transports.expect("transports present");
        match &transports[0] {
            TransportEntry::Harp(h) => {
                assert!(h.h2_streaming_enabled.is_none(), "h2_streaming_enabled should be None when absent");
            }
            _ => panic!("expected Harp entry"),
        }
    }

    // AC-6: resolve_server_transports resolves h2_streaming_enabled default to true
    #[test]
    fn resolve_harp_h2_default_true() {
        let toml_str = r#"
[[transports]]
name = "harp"
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse");
        let resolved = resolve_server_transports(&config);
        match &resolved[0] {
            ResolvedTransport::Harp { h2_streaming_enabled, .. } => {
                assert!(*h2_streaming_enabled, "h2_streaming_enabled should default to true");
            }
            _ => panic!("expected Harp"),
        }
    }

    // AC-7: resolve_server_transports preserves explicit h2_streaming_enabled = false
    #[test]
    fn resolve_harp_h2_explicit_false() {
        let toml_str = r#"
[[transports]]
name = "harp"
h2_streaming_enabled = false
"#;
        let config: ServerConfig = toml::from_str(toml_str).expect("parse");
        let resolved = resolve_server_transports(&config);
        match &resolved[0] {
            ResolvedTransport::Harp { h2_streaming_enabled, .. } => {
                assert!(!*h2_streaming_enabled, "h2_streaming_enabled should be false when explicitly set");
            }
            _ => panic!("expected Harp"),
        }
    }

    // AC-8: Client config preferred_binding = "h2" parses correctly
    #[test]
    fn client_preferred_binding_h2() {
        let toml_str = r#"
[transport]
protocol = "harp"
preferred_binding = "h2"
"#;
        let config: ClientConfigFile = toml::from_str(toml_str).expect("parse client h2 binding");
        let transport = config.transport.expect("transport section present");
        assert_eq!(transport.preferred_binding.as_deref(), Some("h2"));
    }
}
