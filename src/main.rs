// FRD: specs/frds/FRD-009.md

use std::path::Path;

use base64::Engine as _;
use clap::Parser;
use prrr::{
    config::{Cli, Command, init_tracing},
    transport::ServerTransport as _,
};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the rustls crypto provider before any TLS/QUIC operations.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    let cancel = CancellationToken::new();
    let cancel_signal = cancel.clone();

    // Spawn signal handler
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutdown signal received");
        cancel_signal.cancel();
    });

    match cli.command {
        Command::Server(args) => {
            // Load optional TOML config early so we can extract log_file for tracing init
            let config = prrr::config::load_server_config(args.config.as_ref())?;
            let log_file = config.monitoring.as_ref().and_then(|m| m.log_file.as_deref());
            init_tracing(&args.log_level, log_file);

            // Handle server client management subcommands (P-009B)
            if let Some(prrr::config::ServerSubcommand::Client(ref client_args)) = args.subcommand {
                let subnet = config
                    .network
                    .as_ref()
                    .and_then(|n| n.subnet.as_deref())
                    .unwrap_or(prrr::config::DEFAULT_SUBNET);
                let data_dir = config
                    .server
                    .as_ref()
                    .and_then(|s| s.data_dir.as_deref())
                    .unwrap_or(prrr::config::DEFAULT_DATA_DIR);
                let db_path = Path::new(data_dir).join(prrr::registry::DATABASE_FILENAME);
                let mut registry = prrr::registry::ClientRegistry::open(subnet, &db_path)?;

                return prrr::cli::handle_server_client_action(&mut registry, &client_args.action, &config, &args);
            }

            // Handle server doctor subcommand (P-010)
            if let Some(prrr::config::ServerSubcommand::Doctor) = args.subcommand {
                let report = prrr::diagnostics::run_server_doctor(&config, args.listen);
                report.print_colored();
                std::process::exit(report.exit_code());
            }

            tracing::info!("starting prrr server");
            tracing::debug!(?config, "server config loaded");

            // Resolve key paths from config or defaults
            let identity_key_path = config
                .crypto
                .as_ref()
                .and_then(|c| c.identity_key_path.as_deref())
                .unwrap_or(prrr::config::DEFAULT_IDENTITY_KEY_PATH);
            let pq_key_path = config
                .crypto
                .as_ref()
                .and_then(|c| c.pq_key_path.as_deref())
                .unwrap_or(prrr::config::DEFAULT_PQ_KEY_PATH);

            // Load or generate persistent server keys
            let key_store = prrr::keys::KeyStore::load_or_generate(Path::new(identity_key_path), Path::new(pq_key_path))?;
            tracing::info!(
                noise_pub = %key_store.noise_public_key_base64(),
                kem_pub_len = key_store.kem_keypair().encapsulation_key_bytes().len(),
                "server keys ready"
            );

            // Capture public keys for client config distribution before consuming the key store.
            let server_noise_pub = *key_store.noise_keypair().public_key();
            let server_kem_pub = key_store.kem_keypair().encapsulation_key_bytes();

            let server_noise_private_key: std::sync::Arc<[u8]> = std::sync::Arc::from(key_store.noise_keypair().private_key_bytes());
            let server_kem_dk_bytes: std::sync::Arc<[u8]> = std::sync::Arc::from(key_store.kem_keypair().dk_bytes().as_slice());

            let (noise_keypair, kem_keypair) = key_store.into_parts();

            let subnet = config
                .network
                .as_ref()
                .and_then(|n| n.subnet.as_deref())
                .unwrap_or(prrr::config::DEFAULT_SUBNET);
            let data_dir = config
                .server
                .as_ref()
                .and_then(|s| s.data_dir.as_deref())
                .unwrap_or(prrr::config::DEFAULT_DATA_DIR);
            let db_path = Path::new(data_dir).join(prrr::registry::DATABASE_FILENAME);
            let registry = prrr::registry::ClientRegistry::open(subnet, &db_path)?;
            tracing::info!(?db_path, "client registry opened");
            let registry = std::sync::Arc::new(tokio::sync::Mutex::new(registry));

            let max_clients = config
                .server
                .as_ref()
                .and_then(|s| s.max_clients)
                .unwrap_or(prrr::config::DEFAULT_MAX_CLIENTS);

            // Real TUN factory — creates system TUN interfaces per client (requires root/CAP_NET_ADMIN).
            let tun_factory = std::sync::Arc::new(prrr::tunnel::SystemTunFactory::new());

            let active_connections = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));

            // Build server context for client config distribution (P-009)
            // Resolve server_name from config, falling back to CLI arg.
            // Use the resolved name (not the bind address) for the client endpoint.
            let dist_server_name = config
                .server
                .as_ref()
                .and_then(|s| s.server_name.as_deref())
                .unwrap_or(&args.server_name);
            let server_endpoint = format!("{dist_server_name}:{}", args.listen.port());
            let dist_dns_servers = config
                .network
                .as_ref()
                .and_then(|n| n.dns_servers.as_ref())
                .cloned()
                .unwrap_or_else(|| prrr::config::DEFAULT_DNS_SERVERS.iter().map(|s| (*s).to_string()).collect());
            let dist_mtu = config.network.as_ref().and_then(|n| n.mtu).unwrap_or(prrr::config::DEFAULT_MTU);
            let dist_transport_protocol = {
                let names: Vec<&str> = config
                    .transports
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|e| match e {
                        prrr::config::TransportEntry::Harp(h) if h.enabled != Some(false) => Some("harp"),
                        prrr::config::TransportEntry::Masque(m) if m.enabled != Some(false) => Some("masque"),
                        _ => None,
                    })
                    .collect();
                if names.is_empty() {
                    prrr::config::DEFAULT_TRANSPORT_PROTOCOL.to_string()
                } else {
                    // Prefer first enabled transport as default for clients
                    names[0].to_string()
                }
            };
            let server_context = std::sync::Arc::new(prrr::distribution::ServerContext {
                endpoint: server_endpoint,
                server_name: dist_server_name.to_string(),
                noise_public_key: server_noise_pub,
                kem_public_key: server_kem_pub,
                dns_servers: dist_dns_servers,
                mtu: dist_mtu,
                transport_protocol: dist_transport_protocol,
            });
            let config_tokens = std::sync::Arc::new(prrr::distribution::ConfigTokenStore::new());

            // Cross-transport session eviction map shared between HARP and MASQUE.
            let active_clients: std::sync::Arc<
                tokio::sync::Mutex<std::collections::HashMap<uuid::Uuid, tokio_util::sync::CancellationToken>>,
            > = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

            // Start web admin if enabled
            let web_task = if config.web_admin.as_ref().and_then(|w| w.enabled).unwrap_or(false) {
                let web_config = config.web_admin.as_ref().expect("web_admin present when enabled");
                let listen_addr: std::net::SocketAddr = web_config
                    .listen_addr
                    .as_deref()
                    .unwrap_or(prrr::config::DEFAULT_WEB_ADMIN_ADDR)
                    .parse()?;
                let password_hash = web_config
                    .admin_password_hash
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("web_admin.admin_password_hash is required when web admin is enabled"))?;
                let session_timeout = web_config.session_timeout.unwrap_or(prrr::config::DEFAULT_SESSION_TIMEOUT);

                let mut jwt_secret_bytes = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut jwt_secret_bytes);

                let dns_servers = config
                    .network
                    .as_ref()
                    .and_then(|n| n.dns_servers.as_ref())
                    .map(|d| d.iter().map(String::clone).collect())
                    .unwrap_or_else(|| prrr::config::DEFAULT_DNS_SERVERS.iter().map(|s| (*s).to_string()).collect());
                let mtu = config.network.as_ref().and_then(|n| n.mtu).unwrap_or(prrr::config::DEFAULT_MTU);
                let transport_protocol = {
                    let names: Vec<&str> = config
                        .transports
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .map(|e| match e {
                            prrr::config::TransportEntry::Masque(_) => "masque",
                            prrr::config::TransportEntry::Harp(_) => "harp",
                        })
                        .collect();
                    if names.is_empty() {
                        prrr::config::DEFAULT_TRANSPORT_PROTOCOL.to_string()
                    } else {
                        names.join(",")
                    }
                };
                let obfuscation_enabled = config.obfuscation.as_ref().and_then(|o| o.enabled).unwrap_or(false);
                let metrics_enabled = config.monitoring.as_ref().and_then(|m| m.metrics_enabled).unwrap_or(false);

                let server_config = std::sync::Arc::new(prrr::web::handlers::ServerConfigResponse {
                    listen_addr: format!("{}", args.listen),
                    server_name: args.server_name.clone(),
                    subnet: subnet.to_string(),
                    dns_servers,
                    mtu,
                    max_clients,
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    transport_protocol,
                    obfuscation_enabled,
                    web_admin_enabled: true,
                    metrics_enabled,
                });

                let resolved_server_transports = prrr::config::resolve_server_transports(&config);

                let app_state = prrr::web::AppState {
                    registry: std::sync::Arc::clone(&registry),
                    active_connections: std::sync::Arc::clone(&active_connections),
                    start_time: std::time::Instant::now(),
                    jwt_secret: std::sync::Arc::from(jwt_secret_bytes.as_slice()),
                    session_timeout,
                    admin_password_hash: std::sync::Arc::from(password_hash),
                    cancel: cancel.clone(),
                    server_context: std::sync::Arc::clone(&server_context),
                    config_tokens: std::sync::Arc::clone(&config_tokens),
                    server_config,
                    resolved_transports: std::sync::Arc::new(
                        resolved_server_transports
                            .iter()
                            .map(|rt| match rt {
                                prrr::config::ResolvedTransport::Harp {
                                    websocket_enabled,
                                    polling_enabled,
                                    session_idle_timeout,
                                    ..
                                } => prrr::web::handlers::TransportInfoResponse::from_harp(
                                    *websocket_enabled,
                                    *polling_enabled,
                                    *session_idle_timeout,
                                ),
                                prrr::config::ResolvedTransport::Masque {
                                    max_idle_timeout,
                                    keep_alive,
                                    ..
                                } => prrr::web::handlers::TransportInfoResponse::from_masque(*max_idle_timeout, *keep_alive),
                            })
                            .collect(),
                    ),
                    harp_sessions: std::sync::Arc::new(prrr::web::harp::HarpSessionStore::new()),
                    server_noise_private_key: std::sync::Arc::clone(&server_noise_private_key),
                    server_noise_public_key: server_noise_pub,
                    server_kem_dk_bytes: std::sync::Arc::clone(&server_kem_dk_bytes),
                    tunnel_spawner: None,
                    cover_page_enabled: web_config.cover_page_enabled.unwrap_or(true),
                    trust_proxy_headers: web_config.trust_proxy_headers.unwrap_or(false),
                    h2_streaming_enabled: resolved_server_transports.iter().any(|rt| {
                        matches!(
                            rt,
                            prrr::config::ResolvedTransport::Harp {
                                h2_streaming_enabled: true,
                                ..
                            }
                        )
                    }),
                    active_clients: std::sync::Arc::clone(&active_clients),
                };
                tracing::info!(%listen_addr, "starting web admin server");
                Some(tokio::spawn(prrr::web::run_web_server(listen_addr, app_state)))
            } else {
                None
            };

            // Start metrics server if enabled
            let metrics_task = if config.monitoring.as_ref().and_then(|m| m.metrics_enabled).unwrap_or(false) {
                let prometheus_port = config
                    .monitoring
                    .as_ref()
                    .and_then(|m| m.prometheus_port)
                    .unwrap_or(prrr::config::DEFAULT_PROMETHEUS_PORT);
                let prometheus_handle = prrr::metrics::install_metrics_recorder();
                let metrics_addr: std::net::SocketAddr = ([0, 0, 0, 0], prometheus_port).into();
                let metrics_state = prrr::metrics::MetricsState {
                    start_time: std::time::Instant::now(),
                    cancel: cancel.clone(),
                    prometheus_handle: std::sync::Arc::new(prometheus_handle),
                };
                tracing::info!(%metrics_addr, "starting metrics server");
                Some(tokio::spawn(prrr::metrics::run_metrics_server(metrics_addr, metrics_state)))
            } else {
                None
            };

            // Resolve enabled transports from config
            let resolved_transports = prrr::config::resolve_server_transports(&config);
            if resolved_transports.is_empty() {
                anyhow::bail!("no transports enabled in configuration");
            }

            // Get subnet gateway before spawning transports
            let subnet_gateway = {
                let reg = registry.lock().await;
                reg.gateway_addr()
            };

            // Build shared server state for all transports
            let shared = std::sync::Arc::new(prrr::transport::SharedServerState {
                registry,
                noise_keypair: std::sync::Arc::new(noise_keypair),
                kem_keypair: std::sync::Arc::new(kem_keypair),
                active_connections,
                max_clients,
                subnet_gateway,
                cancel: cancel.clone(),
                active_clients: std::sync::Arc::clone(&active_clients),
            });

            // Spawn each enabled transport
            let mut transport_tasks = tokio::task::JoinSet::new();
            for resolved in &resolved_transports {
                match resolved {
                    prrr::config::ResolvedTransport::Masque { tls_cert, tls_key, .. } => {
                        let transport = prrr::server::MasqueServerTransport::new(
                            args.listen,
                            args.server_name.clone(),
                            tls_cert.clone(),
                            tls_key.clone(),
                            std::sync::Arc::clone(&tun_factory),
                        );
                        let shared = std::sync::Arc::clone(&shared);
                        let cancel = cancel.clone();
                        tracing::info!("starting MASQUE transport on {}", args.listen);
                        transport_tasks.spawn(async move { transport.run(shared, cancel).await });
                    }
                    prrr::config::ResolvedTransport::Harp {
                        tls_cert,
                        tls_key,
                        session_idle_timeout,
                        ..
                    } => {
                        let transport = prrr::web::harp::HarpServerTransport::new(
                            args.listen,
                            std::sync::Arc::clone(&tun_factory),
                            tls_cert.clone(),
                            tls_key.clone(),
                            *session_idle_timeout,
                        );
                        let shared = std::sync::Arc::clone(&shared);
                        let cancel = cancel.clone();
                        tracing::info!("starting HARP transport on {}", args.listen);
                        transport_tasks.spawn(async move { transport.run(shared, cancel).await });
                    }
                }
            }

            // Wait for first transport to finish (error or cancellation)
            let vpn_result = if let Some(result) = transport_tasks.join_next().await {
                match result {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(e),
                    Err(e) => Err(anyhow::anyhow!("transport task panicked: {e}")),
                }
            } else {
                Ok(())
            };

            // Cancel remaining transports
            cancel.cancel();
            while transport_tasks.join_next().await.is_some() {}

            if let Some(task) = web_task {
                let _ = task.await;
            }
            if let Some(task) = metrics_task {
                let _ = task.await;
            }

            vpn_result
        }
        Command::Client(args) => {
            init_tracing(&args.log_level, None);

            // Handle client subcommands (P-009B, P-010)
            match args.subcommand {
                Some(prrr::config::ClientSubcommand::Import { source }) => {
                    tracing::info!("importing client configuration");
                    return prrr::cli::handle_client_import(&source);
                }
                Some(prrr::config::ClientSubcommand::Doctor) => {
                    let config = prrr::config::load_client_config(args.config.as_ref())?;
                    let report = prrr::diagnostics::run_client_doctor(&config);
                    report.print_colored();
                    std::process::exit(report.exit_code());
                }
                Some(prrr::config::ClientSubcommand::Route(route_args)) => {
                    let mut stdout = std::io::stdout();
                    return prrr::cli::handle_client_route_action(args.config.as_deref(), &route_args.action, &mut stdout);
                }
                None => {}
            }

            // Load optional client config file
            let config = prrr::config::load_client_config(args.config.as_ref())?;

            // Resolve server address: CLI flag > config endpoint
            // Supports both IP:port and hostname:port (with DNS resolution).
            let server_addr: std::net::SocketAddr = match args.server {
                Some(addr) => addr,
                None => {
                    let endpoint = config
                        .server
                        .as_ref()
                        .and_then(|s| s.endpoint.as_deref())
                        .ok_or_else(|| anyhow::anyhow!(prrr::config::ERR_MISSING_SERVER_ADDR))?;
                    use std::net::ToSocketAddrs;
                    endpoint
                        .to_socket_addrs()
                        .map_err(|e| anyhow::anyhow!("failed to resolve server endpoint '{endpoint}': {e}"))?
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("server endpoint '{endpoint}' resolved to no addresses"))?
                }
            };

            // Resolve server_name: CLI flag > config > error
            let server_name = args
                .server_name
                .as_deref()
                .or_else(|| config.server.as_ref().and_then(|s| s.server_name.as_deref()))
                .ok_or_else(|| anyhow::anyhow!(prrr::config::ERR_MISSING_SERVER_NAME))?;

            // Resolve insecure flag: CLI flag > config > false
            let insecure = if args.insecure {
                true
            } else {
                config.transport.as_ref().and_then(|t| t.insecure_skip_verify).unwrap_or(false)
            };

            tracing::info!("starting prrr client");
            tracing::debug!(?config, "client config loaded");

            // Resolve server Noise IK public key: CLI flag > config
            let config_noise_key = config.server.as_ref().and_then(|s| s.public_key.as_deref());
            let server_noise_pub = prrr::config::resolve_server_noise_key(args.server_public_key.as_deref(), config_noise_key)?;

            // Resolve server ML-KEM-768 encapsulation key: CLI flag > config
            let config_kem_key = config.server.as_ref().and_then(|s| s.pq_public_key.as_deref());
            let server_kem_pub = prrr::config::resolve_server_kem_key(args.server_pq_public_key.as_deref(), config_kem_key)?;

            // Resolve client Noise IK keypair: inline key > key file > ephemeral
            let noise_keypair = if let Some(key_b64) = config.interface.as_ref().and_then(|i| i.private_key.as_deref()) {
                let key_bytes = base64::engine::general_purpose::STANDARD
                    .decode(key_b64)
                    .map_err(|e| anyhow::anyhow!("invalid inline private_key base64: {e}"))?;
                tracing::info!("using inline private_key from config");
                prrr::handshake::noise_ik::KeyPair::from_private_key(&key_bytes)?
            } else if let Some(key_path) = config.interface.as_ref().and_then(|i| i.private_key_path.as_deref()) {
                let key_bytes = std::fs::read(key_path).map_err(|e| anyhow::anyhow!("failed to read client key {key_path}: {e}"))?;
                prrr::handshake::noise_ik::KeyPair::from_private_key(&key_bytes)?
            } else {
                tracing::info!("no client key configured, generating ephemeral keypair");
                prrr::handshake::noise_ik::KeyPair::generate()?
            };

            // Create real system TUN device from client config
            let tun_address: std::net::Ipv4Addr = config
                .interface
                .as_ref()
                .and_then(|i| i.address.as_deref())
                .ok_or_else(|| anyhow::anyhow!("interface.address is required in client config (e.g. \"10.66.66.3\")"))?
                .split('/')
                .next()
                .expect("split always yields at least one element")
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid interface.address: {e}"))?;

            let tun_mtu = config
                .interface
                .as_ref()
                .and_then(|i| i.mtu)
                .unwrap_or(prrr::tunnel::tun_device::DEFAULT_TUNNEL_MTU);

            // Derive gateway from client address (first host in subnet, e.g. 10.66.66.1)
            let octets = tun_address.octets();
            let gateway = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 1);

            let tun_config = prrr::tunnel::TunConfig::new(tun_address)
                .with_mtu(tun_mtu)
                .with_destination(gateway)
                .with_netmask(std::net::Ipv4Addr::new(255, 255, 255, 255));
            let tun = prrr::tunnel::SystemTun::from_config(&tun_config)
                .map_err(|e| anyhow::anyhow!("failed to create TUN device (need root/CAP_NET_ADMIN): {e}"))?;
            tracing::info!(name = tun_config.name, address = %tun_address, gateway = %gateway, mtu = tun_mtu, "TUN device created");

            // Resolve transport protocol: interface.transport_protocol > transport.protocol > default
            let transport_protocol = config
                .interface
                .as_ref()
                .and_then(|i| i.transport_protocol.as_deref())
                .or_else(|| config.transport.as_ref().and_then(|t| t.protocol.as_deref()))
                .unwrap_or(prrr::config::DEFAULT_TRANSPORT_PROTOCOL);

            // Resolve fwmark for policy routing
            let fwmark = config
                .routing
                .as_ref()
                .and_then(|r| r.fwmark)
                .unwrap_or(prrr::routing::DEFAULT_FWMARK);
            let fwmark_opt = Some(fwmark);

            // Build transport via trait-based dispatch
            let transport: Box<dyn prrr::transport::ClientTransport> = match transport_protocol {
                "harp" => {
                    tracing::info!("using HARP transport");
                    let preferred_binding = config.transport.as_ref().and_then(|t| t.preferred_binding.clone());
                    let tls_profile = config
                        .transport
                        .as_ref()
                        .and_then(|t| t.tls_profile.as_deref())
                        .and_then(|s| s.parse::<prrr::obfuscation::tls_mimicry::TlsProfile>().ok())
                        .unwrap_or(prrr::obfuscation::tls_mimicry::TlsProfile::Chrome);
                    let direct_timeout_secs = config
                        .transport
                        .as_ref()
                        .and_then(|t| t.direct_timeout_secs)
                        .unwrap_or(prrr::config::DEFAULT_DIRECT_TIMEOUT_SECS);
                    let cdn_fronting_domain = config.transport.as_ref().and_then(|t| t.cdn_fronting_domain.clone());
                    let cdn_fronting_enabled = config.transport.as_ref().and_then(|t| t.cdn_fronting_enabled).unwrap_or(false);
                    let direct_retry_interval_secs = config
                        .transport
                        .as_ref()
                        .and_then(|t| t.direct_retry_interval_secs)
                        .unwrap_or(prrr::config::DEFAULT_DIRECT_RETRY_INTERVAL_SECS);
                    Box::new(prrr::client::HarpClientTransport::new(prrr::client::HarpClientConfig {
                        server_endpoint: server_addr.to_string(),
                        server_name: server_name.to_string(),
                        insecure,
                        fwmark: fwmark_opt,
                        preferred_binding,
                        tls_profile,
                        direct_timeout: std::time::Duration::from_secs(direct_timeout_secs),
                        cdn_fronting_domain,
                        cdn_fronting_enabled,
                        direct_retry_interval: std::time::Duration::from_secs(direct_retry_interval_secs),
                    }))
                }
                _ => {
                    tracing::info!("using MASQUE transport");
                    Box::new(prrr::client::MasqueClientTransport::new(
                        server_addr,
                        server_name.to_string(),
                        25,
                        300,
                        insecure,
                        fwmark_opt,
                    ))
                }
            };

            // Resolve reconnection config from client transport section
            let reconnect_config = prrr::reconnect::ReconnectConfig {
                backoff_initial_ms: config
                    .transport
                    .as_ref()
                    .and_then(|t| t.reconnect_backoff_ms)
                    .unwrap_or(prrr::reconnect::DEFAULT_BACKOFF_INITIAL_MS),
                backoff_max_ms: config
                    .transport
                    .as_ref()
                    .and_then(|t| t.reconnect_max_backoff_ms)
                    .unwrap_or(prrr::reconnect::DEFAULT_BACKOFF_MAX_MS),
            };

            // Wrap TUN in Arc for persistence across reconnections
            let tun = std::sync::Arc::new(tun);

            // Build RouteManager for binary-driven routing lifecycle
            let all_traffic = config.routing.as_ref().and_then(|r| r.all_traffic).unwrap_or(false);
            let dns_servers = config.interface.as_ref().and_then(|i| i.dns.as_ref()).cloned().unwrap_or_default();
            let allowed_ips = config
                .routing
                .as_ref()
                .and_then(|r| r.allowed_ips.as_ref())
                .cloned()
                .unwrap_or_default();
            let user_excluded_ips = config
                .routing
                .as_ref()
                .and_then(|r| r.excluded_ips.as_ref())
                .cloned()
                .unwrap_or_default();
            // Local-LAN auto-exclusion (split-tunnel courtesy, FRD-001): by
            // default, exclude the active interface's RFC1918 subnet so a sibling
            // on the same LAN stays reachable. `full_tunnel = true` opts back into
            // strict full-tunnel capture of LAN traffic.
            let full_tunnel = config.routing.as_ref().and_then(|r| r.full_tunnel).unwrap_or(false);
            let tun_octets = gateway.octets();
            let tun_subnet = format!("{}.{}.{}.0/24", tun_octets[0], tun_octets[1], tun_octets[2]);
            let interfaces = prrr::routing::InterfaceEnumerator::enumerate(&prrr::routing::SystemInterfaceEnumerator);
            let excluded_ips = prrr::routing::compute_excluded_ips(&user_excluded_ips, &interfaces, &[tun_subnet], full_tunnel);
            let resources = config
                .routing
                .as_ref()
                .and_then(|r| r.resources.as_ref())
                .cloned()
                .unwrap_or_default();
            let resource_ips = prrr::routing::resolve_resource_ips(&resources, &prrr::routing::SystemResourceResolver)?;
            // Keep a copy for the ecosystem descriptor (route_params consumes the original).
            let eco_excluded_ips = excluded_ips.clone();
            tracing::info!(full_tunnel, ?excluded_ips, "computed tunnel exclusion set (LAN auto-exclusion)");
            let hook_script = config
                .routing
                .as_ref()
                .and_then(|r| r.hook_script.as_deref())
                .unwrap_or(prrr::routing::DEFAULT_ROUTE_HOOK_SCRIPT)
                .to_string();

            let route_params = prrr::routing::RouteParams {
                tun_device: tun_config.name.clone(),
                client_ip: tun_address,
                gateway_ip: gateway,
                server_ip: server_addr.ip(),
                server_endpoint: server_name.to_string(),
                all_traffic,
                dns_servers,
                allowed_ips,
                excluded_ips,
                resource_ips,
                fwmark,
            };

            let mut route_manager = prrr::routing::RouteManager::new(route_params, hook_script);
            tracing::info!(fwmark, "route manager ready");

            // Ecosystem registry registration (SPEC §3, FRD-002): publish
            // prrr's descriptor on tunnel up and update it on tunnel down.
            // Best-effort via the file fallback ($XDG_RUNTIME_DIR/sy/ecosystem).
            let eco_transport_kind = match transport_protocol {
                "harp" => prrr::ecosystem::TransportKind::Harp,
                _ => prrr::ecosystem::TransportKind::Masque,
            };
            let eco_port = server_addr.port();
            let eco_pubkey = *noise_keypair.public_key();
            // Reflect the Step 4 sharing toggle in the descriptor's
            // client_to_client flag (best-effort read of the local state store).
            let eco_sharing = prrr::sharing::SharingStore::new(prrr::sharing::default_state_path()).load();
            let eco_client_to_client = eco_sharing.enabled;
            // Step 5: publish the peer's mesh address ONLY after probing that the
            // inter-client route is actually up (probe before publish, SPEC §7).
            // The connected descriptor carries it; the down descriptor clears it.
            let eco_mesh_addr = prrr::sharing::resolve_mesh_addr(
                eco_sharing.enabled,
                eco_sharing.peer_mesh_addr.as_deref(),
                &prrr::sharing::TcpMeshProbe::default(),
            );
            let make_eco_state = |excluded: Vec<String>, mesh_peer_addr: Option<String>| prrr::ecosystem::DescriptorState {
                pubkey: &eco_pubkey,
                transport: eco_transport_kind,
                port: eco_port,
                iface: &tun_config.name,
                server_endpoint: Some(server_name),
                full_tunnel,
                excluded_cidrs: excluded,
                client_to_client: eco_client_to_client,
                mesh_peer_addr,
            };
            let connected_descriptor = prrr::ecosystem::build_descriptor(make_eco_state(eco_excluded_ips.clone(), eco_mesh_addr));
            let down_descriptor = prrr::ecosystem::build_descriptor(make_eco_state(Vec::new(), None));
            let registrar = prrr::ecosystem::EcosystemRegistrar::new(
                Box::new(prrr::ecosystem::FileRegistryTransport::new()),
                connected_descriptor,
                down_descriptor,
            );

            // Run with automatic reconnection on transport failure
            let crypto_params = prrr::reconnect::ReconnectCryptoParams {
                noise_keypair: &noise_keypair,
                server_noise_pub: &server_noise_pub,
                server_kem_pub: &server_kem_pub,
            };
            let result = prrr::reconnect::run_with_reconnect(
                transport.as_ref(),
                &crypto_params,
                tun,
                &reconnect_config,
                Some(&mut route_manager),
                Some(&registrar),
                cancel,
            )
            .await;
            // On full command exit, remove prrr's descriptor (best-effort).
            prrr::ecosystem::RegistryTransport::clear(&prrr::ecosystem::FileRegistryTransport::new());
            result
        }
        Command::Sharing(args) => {
            init_tracing("info", None);
            let store = prrr::sharing::SharingStore::new(prrr::sharing::default_state_path());
            let mut stdout = std::io::stdout();
            prrr::cli::handle_sharing_action(&store, &args.action, &mut stdout)
        }
    }
}

/// Wait for SIGINT (Ctrl+C) or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
