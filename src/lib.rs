/// CLI command handlers for client management subcommands.
pub mod cli;

/// VPN client orchestrator.
pub mod client;

/// CLI argument parsing and TOML configuration.
pub mod config;

/// Diagnostic checks for `prrr server doctor` and `prrr client doctor`.
pub mod diagnostics;

/// Cryptographic primitives for the PRRR protocol.
pub mod crypto;

/// Client configuration distribution: config export, QR codes, short URLs.
pub mod distribution;

/// Noise protocol handshake implementations.
pub mod handshake;

/// Persistent key management for server identity keys.
pub mod keys;

/// Messaging layer: PQXDH key agreement and end-to-end encryption.
pub mod messaging;

/// Obfuscation and anti-censorship techniques.
pub mod obfuscation;

/// Prometheus metrics server and health endpoint.
pub mod metrics;

/// Transport-agnostic client reconnection with exponential backoff.
pub mod reconnect;

/// Binary-driven routing lifecycle with fwmark policy routing.
pub mod routing;

/// Client registry for authorized VPN clients.
pub mod registry;

/// VPN server orchestrator.
pub mod server;

/// Encrypted transport layer for post-handshake packet encryption.
pub mod transport;

/// IP tunneling: TUN device abstraction and packet pipeline.
pub mod tunnel;

/// REST API backend for web-based VPN administration.
pub mod web;
