// FRD: specs/frds/FRD-P004.md, specs/frds/FRD-P008.md

//! Client registry for authorized VPN clients.
//!
//! Provides [`ClientRegistry`] for managing authorized clients with
//! assigned IP addresses, backed by SQLite for persistence.
//! Clients are identified by their Noise IK X25519 public key.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use rusqlite::params;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::handshake::noise_ik::PUBLIC_KEY_LEN;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of reserved addresses at the start of a subnet (network + gateway).
const RESERVED_HOST_OFFSET: u32 = 2;

/// Minimum usable prefix length for client subnets.
const MIN_PREFIX_LEN: u8 = 2;

/// Maximum prefix length (at least 2 host addresses needed: gateway + 1 client).
const MAX_PREFIX_LEN: u8 = 30;

/// Default file name for the client registry JSON file (legacy).
pub const REGISTRY_FILENAME: &str = "clients.json";

/// Default file name for the SQLite database.
pub const DATABASE_FILENAME: &str = "clients.db";

/// Current schema version.
const SCHEMA_VERSION: i32 = 3;

/// Status string stored in SQLite for active clients.
const STATUS_ACTIVE: &str = "active";

/// Status string stored in SQLite for suspended clients.
const STATUS_SUSPENDED: &str = "suspended";

/// Status string stored in SQLite for revoked clients.
const STATUS_REVOKED: &str = "revoked";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Status of a registered client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientStatus {
    /// Client is active and allowed to connect.
    Active,
    /// Client is temporarily suspended (cannot connect).
    Suspended,
    /// Client is permanently revoked (IP released for reuse).
    Revoked,
}

impl ClientStatus {
    /// Convert to the string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => STATUS_ACTIVE,
            Self::Suspended => STATUS_SUSPENDED,
            Self::Revoked => STATUS_REVOKED,
        }
    }

    /// Parse from SQLite TEXT representation.
    fn from_str(s: &str) -> Option<Self> {
        match s {
            STATUS_ACTIVE => Some(Self::Active),
            STATUS_SUSPENDED => Some(Self::Suspended),
            STATUS_REVOKED => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// A registered VPN client record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRecord {
    /// Unique identifier for this client.
    pub id: Uuid,
    /// Human-readable client name.
    pub name: String,
    /// Noise IK X25519 public key (32 bytes), base64-encoded for JSON.
    #[serde(serialize_with = "serialize_public_key", deserialize_with = "deserialize_public_key")]
    pub public_key: [u8; PUBLIC_KEY_LEN],
    /// Optional ML-KEM-768 encapsulation key, base64-encoded for JSON.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_bytes",
        deserialize_with = "deserialize_optional_bytes"
    )]
    pub pq_public_key: Option<Vec<u8>>,
    /// Assigned VPN IP address.
    pub ip_address: Ipv4Addr,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Last seen timestamp (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<u64>,
    /// Client status.
    pub status: ClientStatus,
    /// Total bytes sent by client (TUN → network).
    #[serde(default)]
    pub bytes_sent: u64,
    /// Total bytes received by client (network → TUN).
    #[serde(default)]
    pub bytes_received: u64,
    /// Optional 256-bit PSK obfuscation key (32 bytes when present).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_bytes",
        deserialize_with = "deserialize_optional_bytes"
    )]
    pub obfuscation_key: Option<Vec<u8>>,
}

/// Connection event types for history logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// Client connected successfully.
    Connect,
    /// Client disconnected.
    Disconnect,
    /// Authentication failed.
    AuthFailed,
}

impl ConnectionEvent {
    /// Convert to the string representation stored in SQLite.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Disconnect => "disconnect",
            Self::AuthFailed => "auth_failed",
        }
    }
}

/// A connection history record from the `connection_history` table.
#[derive(Debug, Clone)]
pub struct ConnectionHistoryRecord {
    /// Auto-incremented row ID.
    pub id: i64,
    /// Client UUID (or nil UUID for auth failures).
    pub client_id: String,
    /// Event type string.
    pub event_type: String,
    /// Unix timestamp of the event.
    pub timestamp: u64,
    /// Remote address of the connection.
    pub remote_addr: Option<String>,
    /// Error message (for disconnect/auth failure).
    pub error_message: Option<String>,
    /// Bytes sent during this session (for disconnect events).
    pub bytes_sent: u64,
    /// Bytes received during this session (for disconnect events).
    pub bytes_received: u64,
}

/// Errors returned by registry operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// A client with this name already exists.
    #[error("client name already exists: {0}")]
    DuplicateName(String),
    /// A client with this public key already exists.
    #[error("client with this public key already exists")]
    DuplicatePublicKey,
    /// No more IP addresses available in the subnet.
    #[error("subnet exhausted: no free IP addresses")]
    SubnetExhausted,
    /// Client not found by the given identifier.
    #[error("client not found: {0}")]
    ClientNotFound(Uuid),
    /// Invalid subnet CIDR string.
    #[error("invalid subnet: {0}")]
    InvalidSubnet(String),
    /// I/O error during persistence.
    #[error("registry I/O error at {path}: {source}")]
    Io {
        /// Path that caused the error.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// JSON serialization/deserialization error.
    #[error("registry serialization error: {0}")]
    Serialization(String),
    /// SQLite database error.
    #[error("database error: {0}")]
    Database(String),
}

impl From<rusqlite::Error> for RegistryError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Database(err.to_string())
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Client registry backed by SQLite for persistent storage.
///
/// Manages authorized clients with unique names, public keys, and
/// assigned IP addresses from a configured subnet.
pub struct ClientRegistry {
    /// SQLite database connection.
    conn: rusqlite::Connection,
    /// Set of currently allocated IP addresses (in-memory cache for fast allocation).
    allocated_ips: BTreeSet<Ipv4Addr>,
    /// Network address of the subnet.
    network_addr: Ipv4Addr,
    /// First usable host IP (network + 2, skipping gateway).
    first_host: Ipv4Addr,
    /// Last usable host IP (broadcast - 1).
    last_host: Ipv4Addr,
}

impl ClientRegistry {
    /// Create a new in-memory client registry for the given subnet CIDR.
    ///
    /// Uses an in-memory SQLite database (ideal for tests).
    /// The subnet must be a valid IPv4 CIDR (e.g., `"10.66.66.0/24"`).
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::InvalidSubnet`] if the CIDR is malformed
    /// or the prefix length is out of range.
    pub fn new(subnet_cidr: &str) -> Result<Self, RegistryError> {
        let (network_addr, first_host, last_host) = parse_subnet(subnet_cidr)?;
        let conn = rusqlite::Connection::open_in_memory()?;
        run_migrations(&conn)?;

        Ok(Self {
            conn,
            allocated_ips: BTreeSet::new(),
            network_addr,
            first_host,
            last_host,
        })
    }

    /// Open a file-backed client registry for the given subnet CIDR.
    ///
    /// Creates the database file and parent directories if they don't exist.
    /// Runs schema migrations on first open. Rebuilds the IP allocation
    /// cache from existing records.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::InvalidSubnet`] if the CIDR is malformed,
    /// [`RegistryError::Io`] if parent directory creation fails, or
    /// [`RegistryError::Database`] on SQLite errors.
    pub fn open(subnet_cidr: &str, db_path: &Path) -> Result<Self, RegistryError> {
        let (network_addr, first_host, last_host) = parse_subnet(subnet_cidr)?;

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| RegistryError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let conn = rusqlite::Connection::open(db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        run_migrations(&conn)?;

        let allocated_ips = {
            let mut ips = BTreeSet::new();
            let mut stmt = conn.prepare("SELECT ip_address FROM clients WHERE status != ?1")?;
            let rows = stmt.query_map(params![STATUS_REVOKED], |row| {
                let ip_str: String = row.get(0)?;
                Ok(ip_str)
            })?;
            for row in rows {
                let ip_str = row?;
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    ips.insert(ip);
                }
            }
            ips
        };

        Ok(Self {
            conn,
            allocated_ips,
            network_addr,
            first_host,
            last_host,
        })
    }

    /// Add a new client to the registry.
    ///
    /// Allocates the next available IP address from the subnet.
    /// The client starts in [`ClientStatus::Active`] status.
    ///
    /// # Errors
    ///
    /// - [`RegistryError::DuplicateName`] if a non-revoked client with this name exists
    /// - [`RegistryError::DuplicatePublicKey`] if a non-revoked client with this key exists
    /// - [`RegistryError::SubnetExhausted`] if no IPs are available
    pub fn add(
        &mut self,
        name: &str,
        public_key: [u8; PUBLIC_KEY_LEN],
        pq_public_key: Option<Vec<u8>>,
        obfuscation_key: Option<Vec<u8>>,
    ) -> Result<ClientRecord, RegistryError> {
        // Check for duplicate name among non-revoked clients
        let name_exists: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM clients WHERE name = ?1 AND status != ?2)",
            params![name, STATUS_REVOKED],
            |row| row.get(0),
        )?;
        if name_exists {
            return Err(RegistryError::DuplicateName(name.to_string()));
        }

        // Check for duplicate public key among non-revoked clients
        let key_exists: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM clients WHERE public_key = ?1 AND status != ?2)",
            params![public_key.as_slice(), STATUS_REVOKED],
            |row| row.get(0),
        )?;
        if key_exists {
            return Err(RegistryError::DuplicatePublicKey);
        }

        let ip = self.allocate_ip()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs();

        let record = ClientRecord {
            id: Uuid::new_v4(),
            name: name.to_string(),
            public_key,
            pq_public_key: pq_public_key.clone(),
            ip_address: ip,
            created_at: now,
            last_seen: None,
            status: ClientStatus::Active,
            bytes_sent: 0,
            bytes_received: 0,
            obfuscation_key: obfuscation_key.clone(),
        };

        self.conn.execute(
            "INSERT INTO clients (id, name, public_key, pq_public_key, ip_address, created_at, last_seen, status, obfuscation_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                record.id.to_string(),
                record.name,
                record.public_key.as_slice(),
                pq_public_key.as_deref(),
                record.ip_address.to_string(),
                record.created_at as i64,
                Option::<i64>::None,
                record.status.as_str(),
                obfuscation_key.as_deref(),
            ],
        )?;

        Ok(record)
    }

    /// Remove (revoke) a client by UUID.
    ///
    /// The client's status is set to [`ClientStatus::Revoked`] and its
    /// IP address is released for reallocation.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::ClientNotFound`] if no client with this UUID exists.
    pub fn remove(&mut self, id: Uuid) -> Result<(), RegistryError> {
        let client = self.get(id).ok_or(RegistryError::ClientNotFound(id))?;
        self.allocated_ips.remove(&client.ip_address);

        let updated = self.conn.execute(
            "UPDATE clients SET status = ?1 WHERE id = ?2",
            params![STATUS_REVOKED, id.to_string()],
        )?;

        if updated == 0 {
            return Err(RegistryError::ClientNotFound(id));
        }

        Ok(())
    }

    /// Get a client record by UUID.
    pub fn get(&self, id: Uuid) -> Option<ClientRecord> {
        self.conn
            .query_row(
                "SELECT id, name, public_key, pq_public_key, ip_address, created_at, last_seen, status, bytes_sent, bytes_received, obfuscation_key FROM clients WHERE id = ?1",
                params![id.to_string()],
                row_to_record,
            )
            .ok()
    }

    /// Get a client record by Noise IK public key.
    pub fn get_by_public_key(&self, key: &[u8; PUBLIC_KEY_LEN]) -> Option<ClientRecord> {
        self.conn
            .query_row(
                "SELECT id, name, public_key, pq_public_key, ip_address, created_at, last_seen, status, bytes_sent, bytes_received, obfuscation_key FROM clients WHERE public_key = ?1",
                params![key.as_slice()],
                row_to_record,
            )
            .ok()
    }

    /// Get a non-revoked client record by name.
    pub fn get_by_name(&self, name: &str) -> Option<ClientRecord> {
        self.conn
            .query_row(
                "SELECT id, name, public_key, pq_public_key, ip_address, created_at, last_seen, status, bytes_sent, bytes_received, obfuscation_key FROM clients WHERE name = ?1 AND status != ?2",
                params![name, STATUS_REVOKED],
                row_to_record,
            )
            .ok()
    }

    /// List all non-revoked clients.
    pub fn list(&self) -> Vec<ClientRecord> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, public_key, pq_public_key, ip_address, created_at, last_seen, status, bytes_sent, bytes_received, obfuscation_key FROM clients WHERE status != ?1 ORDER BY created_at")
            .expect("prepare list query");
        let rows = stmt.query_map(params![STATUS_REVOKED], row_to_record).expect("query list");
        rows.filter_map(|r| r.ok()).collect()
    }

    /// Authenticate a client by their Noise IK static public key.
    ///
    /// Returns the client record only if the client is active (not suspended or revoked).
    pub fn authenticate(&self, initiator_static: &[u8; PUBLIC_KEY_LEN]) -> Option<ClientRecord> {
        self.conn
            .query_row(
                "SELECT id, name, public_key, pq_public_key, ip_address, created_at, last_seen, status, bytes_sent, bytes_received, obfuscation_key FROM clients WHERE public_key = ?1 AND status = ?2",
                params![initiator_static.as_slice(), STATUS_ACTIVE],
                row_to_record,
            )
            .ok()
    }

    /// Update the `last_seen` timestamp for a client.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::ClientNotFound`] if no client with this UUID exists.
    pub fn update_last_seen(&mut self, id: Uuid, timestamp: u64) -> Result<(), RegistryError> {
        let updated = self.conn.execute(
            "UPDATE clients SET last_seen = ?1 WHERE id = ?2",
            params![timestamp as i64, id.to_string()],
        )?;

        if updated == 0 {
            return Err(RegistryError::ClientNotFound(id));
        }

        Ok(())
    }

    /// Suspend a client (temporarily prevent connections).
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::ClientNotFound`] if no client with this UUID exists.
    pub fn suspend(&mut self, id: Uuid) -> Result<(), RegistryError> {
        let updated = self.conn.execute(
            "UPDATE clients SET status = ?1 WHERE id = ?2",
            params![STATUS_SUSPENDED, id.to_string()],
        )?;

        if updated == 0 {
            return Err(RegistryError::ClientNotFound(id));
        }

        Ok(())
    }

    /// Reactivate a suspended client.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::ClientNotFound`] if no client with this UUID exists.
    pub fn reactivate(&mut self, id: Uuid) -> Result<(), RegistryError> {
        let updated = self.conn.execute(
            "UPDATE clients SET status = ?1 WHERE id = ?2",
            params![STATUS_ACTIVE, id.to_string()],
        )?;

        if updated == 0 {
            return Err(RegistryError::ClientNotFound(id));
        }

        Ok(())
    }

    /// Increment traffic counters for a client.
    ///
    /// Adds `sent_delta` to `bytes_sent` and `recv_delta` to `bytes_received`.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::ClientNotFound`] if no client with this UUID exists.
    pub fn update_traffic(&mut self, id: Uuid, sent_delta: u64, recv_delta: u64) -> Result<(), RegistryError> {
        let updated = self.conn.execute(
            "UPDATE clients SET bytes_sent = bytes_sent + ?1, bytes_received = bytes_received + ?2 WHERE id = ?3",
            params![sent_delta as i64, recv_delta as i64, id.to_string()],
        )?;
        if updated == 0 {
            return Err(RegistryError::ClientNotFound(id));
        }
        Ok(())
    }

    /// Log a connection event to the connection history.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Database`] on SQLite errors.
    pub fn log_connection_event(
        &mut self,
        client_id: Uuid,
        event: ConnectionEvent,
        remote_addr: Option<&str>,
        error: Option<&str>,
        bytes_sent: u64,
        bytes_received: u64,
    ) -> Result<(), RegistryError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs();

        self.conn.execute(
            "INSERT INTO connection_history (client_id, event_type, timestamp, remote_addr, error_message, bytes_sent, bytes_received) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                client_id.to_string(),
                event.as_str(),
                now as i64,
                remote_addr,
                error,
                bytes_sent as i64,
                bytes_received as i64,
            ],
        )?;

        Ok(())
    }

    /// Query connection history for a client, most recent first.
    ///
    /// Returns up to `limit` records ordered by timestamp descending.
    pub fn get_connection_history(&self, client_id: Uuid, limit: u32) -> Result<Vec<ConnectionHistoryRecord>, RegistryError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, client_id, event_type, timestamp, remote_addr, error_message, bytes_sent, bytes_received FROM connection_history WHERE client_id = ?1 ORDER BY timestamp DESC LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![client_id.to_string(), limit], |row| {
            let bytes_sent_val: i64 = row.get(6)?;
            let bytes_received_val: i64 = row.get(7)?;
            Ok(ConnectionHistoryRecord {
                id: row.get(0)?,
                client_id: row.get(1)?,
                event_type: row.get(2)?,
                timestamp: {
                    let ts: i64 = row.get(3)?;
                    ts as u64
                },
                remote_addr: row.get(4)?,
                error_message: row.get(5)?,
                bytes_sent: bytes_sent_val as u64,
                bytes_received: bytes_received_val as u64,
            })
        })?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    /// Return the number of non-revoked clients.
    pub fn count(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(*) FROM clients WHERE status != ?1", params![STATUS_REVOKED], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as usize
    }

    /// Return the number of suspended clients.
    pub fn suspended_count(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(*) FROM clients WHERE status = ?1", params![STATUS_SUSPENDED], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as usize
    }

    /// Return the network address of the configured subnet.
    pub fn network_addr(&self) -> Ipv4Addr {
        self.network_addr
    }

    /// Return the gateway address of the configured subnet (network + 1).
    pub fn gateway_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network_addr) + 1)
    }

    // -- Legacy persistence (no-ops with SQLite) ------------------------------

    /// Save the registry (no-op with SQLite — data is auto-persisted).
    pub fn save(&self, _path: &Path) -> Result<(), RegistryError> {
        Ok(())
    }

    /// Load the registry (no-op with SQLite — data is loaded on open).
    pub fn load(&mut self, _path: &Path) -> Result<(), RegistryError> {
        Ok(())
    }

    // -- Private helpers ------------------------------------------------------

    /// Allocate the next available IP address from the subnet.
    fn allocate_ip(&mut self) -> Result<Ipv4Addr, RegistryError> {
        let first = u32::from(self.first_host);
        let last = u32::from(self.last_host);

        for ip_u32 in first..=last {
            let candidate = Ipv4Addr::from(ip_u32);
            if !self.allocated_ips.contains(&candidate) {
                self.allocated_ips.insert(candidate);
                return Ok(candidate);
            }
        }

        Err(RegistryError::SubnetExhausted)
    }
}

impl std::fmt::Debug for ClientRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRegistry")
            .field("client_count", &self.count())
            .field("allocated_ips", &self.allocated_ips.len())
            .field("network", &self.network_addr)
            .field("first_host", &self.first_host)
            .field("last_host", &self.last_host)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Parse a subnet CIDR string and return (network_addr, first_host, last_host).
fn parse_subnet(subnet_cidr: &str) -> Result<(Ipv4Addr, Ipv4Addr, Ipv4Addr), RegistryError> {
    let network: ipnet::Ipv4Net = subnet_cidr
        .parse()
        .map_err(|e: ipnet::AddrParseError| RegistryError::InvalidSubnet(e.to_string()))?;

    let prefix_len = network.prefix_len();
    if !(MIN_PREFIX_LEN..=MAX_PREFIX_LEN).contains(&prefix_len) {
        return Err(RegistryError::InvalidSubnet(format!(
            "prefix length {prefix_len} out of range ({MIN_PREFIX_LEN}..={MAX_PREFIX_LEN})"
        )));
    }

    let network_addr = network.network();
    let broadcast = network.broadcast();

    let first_host = Ipv4Addr::from(u32::from(network_addr) + RESERVED_HOST_OFFSET);
    let last_host = Ipv4Addr::from(u32::from(broadcast) - 1);

    Ok((network_addr, first_host, last_host))
}

/// Run database schema migrations.
fn run_migrations(conn: &rusqlite::Connection) -> Result<(), RegistryError> {
    let version: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

    if version < 1 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS clients (
                id            TEXT PRIMARY KEY,
                name          TEXT NOT NULL,
                public_key    BLOB NOT NULL,
                pq_public_key BLOB,
                ip_address    TEXT NOT NULL,
                created_at    INTEGER NOT NULL,
                last_seen     INTEGER,
                status        TEXT NOT NULL DEFAULT 'active'
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_name_active
                ON clients(name) WHERE status != 'revoked';
            CREATE INDEX IF NOT EXISTS idx_clients_public_key_active
                ON clients(public_key) WHERE status != 'revoked';",
        )?;
    }

    if version < 2 {
        conn.execute_batch(
            "ALTER TABLE clients ADD COLUMN bytes_sent INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE clients ADD COLUMN bytes_received INTEGER NOT NULL DEFAULT 0;
             CREATE TABLE IF NOT EXISTS connection_history (
                 id             INTEGER PRIMARY KEY AUTOINCREMENT,
                 client_id      TEXT NOT NULL,
                 event_type     TEXT NOT NULL,
                 timestamp      INTEGER NOT NULL,
                 remote_addr    TEXT,
                 error_message  TEXT,
                 bytes_sent     INTEGER NOT NULL DEFAULT 0,
                 bytes_received INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS idx_conn_history_client
                 ON connection_history(client_id);
             CREATE INDEX IF NOT EXISTS idx_conn_history_ts
                 ON connection_history(timestamp DESC);",
        )?;
    }

    if version < 3 {
        conn.execute_batch("ALTER TABLE clients ADD COLUMN obfuscation_key BLOB;")?;
    }

    if version < SCHEMA_VERSION {
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }

    Ok(())
}

/// Convert a SQLite row to a `ClientRecord`.
fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ClientRecord> {
    let id_str: String = row.get(0)?;
    let name: String = row.get(1)?;
    let public_key_blob: Vec<u8> = row.get(2)?;
    let pq_public_key: Option<Vec<u8>> = row.get(3)?;
    let ip_str: String = row.get(4)?;
    let created_at: i64 = row.get(5)?;
    let last_seen: Option<i64> = row.get(6)?;
    let status_str: String = row.get(7)?;
    let bytes_sent: i64 = row.get(8)?;
    let bytes_received: i64 = row.get(9)?;
    let obfuscation_key: Option<Vec<u8>> = row.get(10)?;

    let id =
        Uuid::parse_str(&id_str).map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;

    let public_key: [u8; PUBLIC_KEY_LEN] = public_key_blob
        .try_into()
        .map_err(|_| rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Blob, "invalid public key length".into()))?;

    let ip_address: Ipv4Addr = ip_str
        .parse()
        .map_err(|e: std::net::AddrParseError| rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e)))?;

    let status = ClientStatus::from_str(&status_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, format!("unknown status: {status_str}").into())
    })?;

    Ok(ClientRecord {
        id,
        name,
        public_key,
        pq_public_key,
        ip_address,
        created_at: created_at as u64,
        last_seen: last_seen.map(|t| t as u64),
        status,
        bytes_sent: bytes_sent as u64,
        bytes_received: bytes_received as u64,
        obfuscation_key,
    })
}

// ---------------------------------------------------------------------------
// Serde helpers for byte arrays in JSON (base64 encoding)
// ---------------------------------------------------------------------------

fn serialize_public_key<S: serde::Serializer>(key: &[u8; PUBLIC_KEY_LEN], serializer: S) -> Result<S::Ok, S::Error> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    serializer.serialize_str(&BASE64_STANDARD.encode(key))
}

fn deserialize_public_key<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<[u8; PUBLIC_KEY_LEN], D::Error> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    let s = String::deserialize(deserializer)?;
    let bytes = BASE64_STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
    bytes.try_into().map_err(|_| serde::de::Error::custom("invalid public key length"))
}

fn serialize_optional_bytes<S: serde::Serializer>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    match bytes {
        Some(b) => serializer.serialize_str(&BASE64_STANDARD.encode(b)),
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_bytes<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(s) => {
            let bytes = BASE64_STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
            Ok(Some(bytes))
        }
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-P004.md, specs/frds/FRD-P008.md
    use super::*;

    const TEST_SUBNET: &str = "10.66.66.0/24";
    const TEST_FIRST_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 66, 66, 2);
    const TEST_SECOND_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 66, 66, 3);
    const TEST_CLIENT_NAME: &str = "test-client";
    const TEST_CLIENT_NAME_2: &str = "test-client-2";

    fn test_public_key(fill: u8) -> [u8; PUBLIC_KEY_LEN] {
        [fill; PUBLIC_KEY_LEN]
    }

    // AC-1: Registry creation with valid subnet
    #[test]
    fn registry_new_valid_subnet() {
        let reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        assert_eq!(reg.count(), 0);
        assert_eq!(reg.network_addr(), Ipv4Addr::new(10, 66, 66, 0));
    }

    // AC-15: Invalid subnet returns error
    #[test]
    fn registry_invalid_subnet() {
        let err = ClientRegistry::new("not-a-cidr").unwrap_err();
        assert!(matches!(err, RegistryError::InvalidSubnet(_)), "expected InvalidSubnet, got: {err}");
    }

    // AC-15b: Prefix length too large
    #[test]
    fn registry_invalid_prefix_too_large() {
        let err = ClientRegistry::new("10.0.0.0/31").unwrap_err();
        assert!(
            matches!(err, RegistryError::InvalidSubnet(_)),
            "expected InvalidSubnet for /31, got: {err}"
        );
    }

    // AC-2: Sequential IP allocation
    #[test]
    fn registry_add_sequential_ips() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");

        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add first");
        assert_eq!(c1.ip_address, TEST_FIRST_CLIENT_IP);
        assert_eq!(c1.status, ClientStatus::Active);
        assert_eq!(c1.name, TEST_CLIENT_NAME);

        let c2 = reg.add(TEST_CLIENT_NAME_2, test_public_key(0x02), None, None).expect("add second");
        assert_eq!(c2.ip_address, TEST_SECOND_CLIENT_IP);
    }

    // AC-3: Duplicate name rejected
    #[test]
    fn registry_add_duplicate_name() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("first add");

        let err = reg.add(TEST_CLIENT_NAME, test_public_key(0x02), None, None).unwrap_err();
        assert!(matches!(err, RegistryError::DuplicateName(_)), "expected DuplicateName, got: {err}");
    }

    // AC-4: Duplicate public key rejected
    #[test]
    fn registry_add_duplicate_public_key() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let key = test_public_key(0xAA);
        reg.add(TEST_CLIENT_NAME, key, None, None).expect("first add");

        let err = reg.add(TEST_CLIENT_NAME_2, key, None, None).unwrap_err();
        assert!(
            matches!(err, RegistryError::DuplicatePublicKey),
            "expected DuplicatePublicKey, got: {err}"
        );
    }

    // AC-5: Subnet exhaustion
    #[test]
    fn registry_subnet_exhausted() {
        let mut reg = ClientRegistry::new("192.168.1.0/30").expect("valid /30");

        reg.add("c1", test_public_key(0x01), None, None).expect("first");

        let err = reg.add("c2", test_public_key(0x02), None, None).unwrap_err();
        assert!(
            matches!(err, RegistryError::SubnetExhausted),
            "expected SubnetExhausted, got: {err}"
        );
    }

    // AC-6: Remove marks as revoked and releases IP
    #[test]
    fn registry_remove_releases_ip() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");
        let id = c1.id;
        let ip = c1.ip_address;

        reg.remove(id).expect("remove");

        let record = reg.get(id).expect("still in registry");
        assert_eq!(record.status, ClientStatus::Revoked);
        assert!(!reg.allocated_ips.contains(&ip), "IP should be released");
    }

    // AC-7: Get by UUID
    #[test]
    fn registry_get_by_id() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");

        let found = reg.get(c1.id).expect("should find");
        assert_eq!(found.name, TEST_CLIENT_NAME);

        assert!(reg.get(Uuid::new_v4()).is_none(), "random UUID not found");
    }

    // AC-8: Get by public key
    #[test]
    fn registry_get_by_public_key() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let key = test_public_key(0xBB);
        reg.add(TEST_CLIENT_NAME, key, None, None).expect("add");

        let found = reg.get_by_public_key(&key).expect("should find");
        assert_eq!(found.name, TEST_CLIENT_NAME);

        let missing = test_public_key(0xCC);
        assert!(reg.get_by_public_key(&missing).is_none());
    }

    // AC-9: List excludes revoked
    #[test]
    fn registry_list_excludes_revoked() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add c1");
        reg.add(TEST_CLIENT_NAME_2, test_public_key(0x02), None, None).expect("add c2");

        assert_eq!(reg.list().len(), 2);

        reg.remove(c1.id).expect("remove c1");
        let listed = reg.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, TEST_CLIENT_NAME_2);
    }

    // AC-10: Authenticate active client, reject suspended/revoked/unknown
    #[test]
    fn registry_authenticate() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let active_key = test_public_key(0x01);
        let suspended_key = test_public_key(0x02);
        let revoked_key = test_public_key(0x03);
        let unknown_key = test_public_key(0xFF);

        let c_active = reg.add("active-client", active_key, None, None).expect("add active");
        let c_suspended = reg.add("suspended-client", suspended_key, None, None).expect("add suspended");
        let c_revoked = reg.add("revoked-client", revoked_key, None, None).expect("add revoked");

        reg.suspend(c_suspended.id).expect("suspend");
        reg.remove(c_revoked.id).expect("revoke");

        let authed = reg.authenticate(&active_key).expect("should auth");
        assert_eq!(authed.id, c_active.id);

        assert!(reg.authenticate(&suspended_key).is_none(), "suspended should not auth");
        assert!(reg.authenticate(&revoked_key).is_none(), "revoked should not auth");
        assert!(reg.authenticate(&unknown_key).is_none(), "unknown should not auth");
    }

    // AC-11: Update last_seen
    #[test]
    fn registry_update_last_seen() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");

        assert!(reg.get(c1.id).expect("get").last_seen.is_none());

        let ts = 1_700_000_000u64;
        reg.update_last_seen(c1.id, ts).expect("update");
        assert_eq!(reg.get(c1.id).expect("get").last_seen, Some(ts));
    }

    // AC-11b: Update last_seen for unknown client
    #[test]
    fn registry_update_last_seen_not_found() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let err = reg.update_last_seen(Uuid::new_v4(), 0).unwrap_err();
        assert!(matches!(err, RegistryError::ClientNotFound(_)));
    }

    // AC-12: Persistence round-trip via open()
    #[test]
    fn registry_persistence_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join(DATABASE_FILENAME);

        let key1 = test_public_key(0x01);
        let pq_key = vec![0xBBu8; 1184];
        let ts = 1_700_000_000u64;
        let client_id;

        {
            let mut reg = ClientRegistry::open(TEST_SUBNET, &db_path).expect("open");
            let c1 = reg.add(TEST_CLIENT_NAME, key1, Some(pq_key.clone()), None).expect("add");
            reg.update_last_seen(c1.id, ts).expect("update");
            client_id = c1.id;
        }

        // Reopen — data should persist
        let reg2 = ClientRegistry::open(TEST_SUBNET, &db_path).expect("reopen");
        assert_eq!(reg2.count(), 1);
        let loaded = reg2.get(client_id).expect("find loaded");
        assert_eq!(loaded.name, TEST_CLIENT_NAME);
        assert_eq!(loaded.public_key, key1);
        assert_eq!(loaded.pq_public_key.as_deref(), Some(pq_key.as_slice()));
        assert_eq!(loaded.ip_address, TEST_FIRST_CLIENT_IP);
        assert_eq!(loaded.last_seen, Some(ts));
        assert_eq!(loaded.status, ClientStatus::Active);
    }

    // AC-13: IP allocation skips reserved addresses
    #[test]
    fn ip_allocation_skips_reserved() {
        let reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        assert_eq!(reg.first_host, TEST_FIRST_CLIENT_IP);
        assert_eq!(reg.last_host, Ipv4Addr::new(10, 66, 66, 254));
    }

    // AC-14: Revoked client IP is reusable
    #[test]
    fn registry_revoked_ip_reusable() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");

        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add first");
        let first_ip = c1.ip_address;

        reg.add(TEST_CLIENT_NAME_2, test_public_key(0x02), None, None).expect("add second");

        reg.remove(c1.id).expect("revoke");

        let c3 = reg.add("third-client", test_public_key(0x03), None, None).expect("add third");
        assert_eq!(c3.ip_address, first_ip, "revoked IP should be reused");
    }

    // Additional: Remove nonexistent client
    #[test]
    fn registry_remove_not_found() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let err = reg.remove(Uuid::new_v4()).unwrap_err();
        assert!(matches!(err, RegistryError::ClientNotFound(_)));
    }

    // Additional: Duplicate name allowed after revocation
    #[test]
    fn registry_duplicate_name_after_revoke() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add first");
        reg.remove(c1.id).expect("revoke");

        let c2 = reg
            .add(TEST_CLIENT_NAME, test_public_key(0x02), None, None)
            .expect("add after revoke");
        assert_ne!(c2.id, c1.id);
    }

    // Additional: Duplicate public key allowed after revocation
    #[test]
    fn registry_duplicate_key_after_revoke() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let key = test_public_key(0xAA);
        let c1 = reg.add(TEST_CLIENT_NAME, key, None, None).expect("add first");
        reg.remove(c1.id).expect("revoke");

        let c2 = reg.add(TEST_CLIENT_NAME_2, key, None, None).expect("add after revoke");
        assert_ne!(c2.id, c1.id);
    }

    // Additional: Persistence preserves revoked status
    #[test]
    fn registry_persistence_preserves_revoked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join(DATABASE_FILENAME);
        let client_id;

        {
            let mut reg = ClientRegistry::open(TEST_SUBNET, &db_path).expect("open");
            let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");
            reg.remove(c1.id).expect("revoke");
            client_id = c1.id;
        }

        let reg2 = ClientRegistry::open(TEST_SUBNET, &db_path).expect("reopen");
        let loaded = reg2.get(client_id).expect("find loaded");
        assert_eq!(loaded.status, ClientStatus::Revoked);
        // Revoked IPs should not be in allocated set
        assert!(!reg2.allocated_ips.contains(&loaded.ip_address));
    }

    // Additional: Count reflects non-revoked only
    #[test]
    fn registry_count_excludes_revoked() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");
        reg.add(TEST_CLIENT_NAME_2, test_public_key(0x02), None, None).expect("add");
        assert_eq!(reg.count(), 2);

        reg.remove(c1.id).expect("revoke");
        assert_eq!(reg.count(), 1);
    }

    // Additional: Suspend and reactivate
    #[test]
    fn registry_suspend_reactivate() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");

        reg.suspend(c1.id).expect("suspend");
        assert_eq!(reg.get(c1.id).expect("get").status, ClientStatus::Suspended);

        reg.reactivate(c1.id).expect("reactivate");
        assert_eq!(reg.get(c1.id).expect("get").status, ClientStatus::Active);
    }

    // Additional: Load rebuilds allocated IPs correctly
    #[test]
    fn registry_load_rebuilds_allocated_ips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join(DATABASE_FILENAME);

        {
            let mut reg = ClientRegistry::open(TEST_SUBNET, &db_path).expect("open");
            reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add c1");
            reg.add(TEST_CLIENT_NAME_2, test_public_key(0x02), None, None).expect("add c2");
        }

        let mut reg2 = ClientRegistry::open(TEST_SUBNET, &db_path).expect("reopen");

        // Adding a third client should get .4 (not .2 or .3 which are taken)
        let c3 = reg2.add("third-client", test_public_key(0x03), None, None).expect("add c3");
        assert_eq!(c3.ip_address, Ipv4Addr::new(10, 66, 66, 4));
    }

    // P-008 AC-1: open() creates file if not exists
    #[test]
    fn registry_open_creates_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("subdir").join(DATABASE_FILENAME);

        assert!(!db_path.exists());
        let _reg = ClientRegistry::open(TEST_SUBNET, &db_path).expect("open creates file");
        assert!(db_path.exists());
    }

    // P-008: Schema version is set
    #[test]
    fn registry_migration_v1() {
        let reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let version: i32 = reg
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("query version");
        assert_eq!(version, SCHEMA_VERSION);
    }

    // P-008: Database error variant
    #[test]
    fn registry_database_error_from_rusqlite() {
        let err = RegistryError::Database("test error".to_string());
        assert!(err.to_string().contains("test error"));
    }

    // P-008: suspended_count
    #[test]
    fn registry_suspended_count() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        assert_eq!(reg.suspended_count(), 0);

        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");
        let c2 = reg.add(TEST_CLIENT_NAME_2, test_public_key(0x02), None, None).expect("add");

        reg.suspend(c1.id).expect("suspend");
        assert_eq!(reg.suspended_count(), 1);

        reg.suspend(c2.id).expect("suspend");
        assert_eq!(reg.suspended_count(), 2);

        reg.reactivate(c1.id).expect("reactivate");
        assert_eq!(reg.suspended_count(), 1);
    }

    // P-009B AC-B1: get_by_name returns matching client
    #[test]
    fn get_by_name_found() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");

        let found = reg.get_by_name(TEST_CLIENT_NAME).expect("should find");
        assert_eq!(found.id, c1.id);
        assert_eq!(found.name, TEST_CLIENT_NAME);
    }

    // P-009B AC-B2: get_by_name returns None for unknown
    #[test]
    fn get_by_name_not_found() {
        let reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        assert!(reg.get_by_name("nonexistent").is_none());
    }

    // P-009B AC-B3: get_by_name skips revoked clients
    #[test]
    fn get_by_name_skips_revoked() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");
        reg.remove(c1.id).expect("revoke");

        assert!(
            reg.get_by_name(TEST_CLIENT_NAME).is_none(),
            "revoked client should not be found by name"
        );
    }

    // --- Traffic counters (P-009 R2/R4) ---

    // New client starts with zero traffic counters
    #[test]
    fn new_client_has_zero_traffic() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");
        assert_eq!(c1.bytes_sent, 0);
        assert_eq!(c1.bytes_received, 0);

        let loaded = reg.get(c1.id).expect("get");
        assert_eq!(loaded.bytes_sent, 0);
        assert_eq!(loaded.bytes_received, 0);
    }

    // update_traffic increments counters
    #[test]
    fn update_traffic_increments() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");

        reg.update_traffic(c1.id, 1000, 2000).expect("update traffic");
        let loaded = reg.get(c1.id).expect("get");
        assert_eq!(loaded.bytes_sent, 1000);
        assert_eq!(loaded.bytes_received, 2000);

        // Increments are additive
        reg.update_traffic(c1.id, 500, 300).expect("update traffic again");
        let loaded = reg.get(c1.id).expect("get");
        assert_eq!(loaded.bytes_sent, 1500);
        assert_eq!(loaded.bytes_received, 2300);
    }

    // update_traffic on unknown UUID returns error
    #[test]
    fn update_traffic_not_found() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let err = reg.update_traffic(Uuid::new_v4(), 100, 200).unwrap_err();
        assert!(matches!(err, RegistryError::ClientNotFound(_)));
    }

    // Schema migration sets correct version (v3 adds obfuscation_key)
    #[test]
    fn migration_v3_schema_version() {
        let reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let version: i32 = reg
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("query version");
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(SCHEMA_VERSION, 3);
    }

    // Traffic counters persist across reopen
    #[test]
    fn traffic_persists_across_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join(DATABASE_FILENAME);
        let client_id;

        {
            let mut reg = ClientRegistry::open(TEST_SUBNET, &db_path).expect("open");
            let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");
            client_id = c1.id;
            reg.update_traffic(client_id, 5000, 3000).expect("update traffic");
        }

        let reg2 = ClientRegistry::open(TEST_SUBNET, &db_path).expect("reopen");
        let loaded = reg2.get(client_id).expect("find loaded");
        assert_eq!(loaded.bytes_sent, 5000);
        assert_eq!(loaded.bytes_received, 3000);
    }

    // --- Connection history (P-009 R5) ---

    // Log connect event and query
    #[test]
    fn log_connect_event() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");

        reg.log_connection_event(c1.id, ConnectionEvent::Connect, Some("127.0.0.1:4433"), None, 0, 0)
            .expect("log connect");

        let history = reg.get_connection_history(c1.id, 10).expect("get history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].event_type, "connect");
        assert_eq!(history[0].client_id, c1.id.to_string());
        assert_eq!(history[0].remote_addr.as_deref(), Some("127.0.0.1:4433"));
        assert!(history[0].error_message.is_none());
        assert_eq!(history[0].bytes_sent, 0);
        assert_eq!(history[0].bytes_received, 0);
    }

    // Log disconnect with traffic
    #[test]
    fn log_disconnect_with_traffic() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");

        reg.log_connection_event(c1.id, ConnectionEvent::Disconnect, Some("10.0.0.1:5555"), None, 4096, 8192)
            .expect("log disconnect");

        let history = reg.get_connection_history(c1.id, 10).expect("get history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].event_type, "disconnect");
        assert_eq!(history[0].bytes_sent, 4096);
        assert_eq!(history[0].bytes_received, 8192);
    }

    // get_connection_history respects limit
    #[test]
    fn get_history_respects_limit() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let c1 = reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, None).expect("add");

        let event_count = 5u32;
        let query_limit = 3u32;
        for _ in 0..event_count {
            reg.log_connection_event(c1.id, ConnectionEvent::Connect, None, None, 0, 0)
                .expect("log");
        }

        let history = reg.get_connection_history(c1.id, query_limit).expect("get history");
        assert_eq!(history.len(), query_limit as usize);
    }

    // Log auth failed event with nil UUID
    #[test]
    fn log_auth_failed_event() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let nil_id = Uuid::nil();

        reg.log_connection_event(
            nil_id,
            ConnectionEvent::AuthFailed,
            Some("192.168.1.1:9999"),
            Some("unknown public key"),
            0,
            0,
        )
        .expect("log auth failed");

        let history = reg.get_connection_history(nil_id, 10).expect("get history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].event_type, "auth_failed");
        assert_eq!(history[0].error_message.as_deref(), Some("unknown public key"));
        assert_eq!(history[0].remote_addr.as_deref(), Some("192.168.1.1:9999"));
    }

    // ConnectionEvent as_str returns expected strings
    #[test]
    fn connection_event_as_str() {
        assert_eq!(ConnectionEvent::Connect.as_str(), "connect");
        assert_eq!(ConnectionEvent::Disconnect.as_str(), "disconnect");
        assert_eq!(ConnectionEvent::AuthFailed.as_str(), "auth_failed");
    }

    // -----------------------------------------------------------------------
    // PSK obfuscation key tests (FRD-DPI007)
    // -----------------------------------------------------------------------

    /// Length of a 256-bit obfuscation key.
    const OBFUSCATION_KEY_LEN: usize = 32;

    // T-5 / AC-5: Registry stores and retrieves obfuscation key
    #[test]
    fn registry_add_with_obfuscation_key() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let key = vec![0xAA; OBFUSCATION_KEY_LEN];

        let record = reg
            .add(TEST_CLIENT_NAME, test_public_key(0x01), None, Some(key.clone()))
            .expect("add with obfuscation key");
        assert_eq!(record.obfuscation_key, Some(key.clone()));

        let loaded = reg.get(record.id).expect("get by id");
        assert_eq!(loaded.obfuscation_key, Some(key.clone()));

        let by_name = reg.get_by_name(TEST_CLIENT_NAME).expect("get by name");
        assert_eq!(by_name.obfuscation_key, Some(key));
    }

    // T-6 / AC-6: Registry add without obfuscation key stores NULL
    #[test]
    fn registry_add_without_obfuscation_key() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");

        let record = reg
            .add(TEST_CLIENT_NAME, test_public_key(0x01), None, None)
            .expect("add without obfuscation key");
        assert!(record.obfuscation_key.is_none());

        let loaded = reg.get(record.id).expect("get by id");
        assert!(loaded.obfuscation_key.is_none());
    }

    // T-12: Obfuscation key persists across file-backed registry reopen
    #[test]
    fn registry_obfuscation_key_persists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join(DATABASE_FILENAME);
        let key = vec![0xBB; OBFUSCATION_KEY_LEN];

        let client_id;
        {
            let mut reg = ClientRegistry::open(TEST_SUBNET, &db_path).expect("open");
            let record = reg
                .add(TEST_CLIENT_NAME, test_public_key(0x01), None, Some(key.clone()))
                .expect("add");
            client_id = record.id;
        }

        let reg2 = ClientRegistry::open(TEST_SUBNET, &db_path).expect("reopen");
        let loaded = reg2.get(client_id).expect("get after reopen");
        assert_eq!(loaded.obfuscation_key, Some(key));
    }

    // AC-DPI007: Obfuscation key appears in list() results
    #[test]
    fn registry_list_includes_obfuscation_key() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let key = vec![0xCC; OBFUSCATION_KEY_LEN];

        reg.add(TEST_CLIENT_NAME, test_public_key(0x01), None, Some(key.clone()))
            .expect("add");

        let clients = reg.list();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].obfuscation_key, Some(key));
    }

    // AC-DPI007: Obfuscation key appears in authenticate() results
    #[test]
    fn registry_authenticate_includes_obfuscation_key() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("valid subnet");
        let key = vec![0xDD; OBFUSCATION_KEY_LEN];
        let pub_key = test_public_key(0x01);

        reg.add(TEST_CLIENT_NAME, pub_key, None, Some(key.clone())).expect("add");

        let record = reg.authenticate(&pub_key).expect("authenticate");
        assert_eq!(record.obfuscation_key, Some(key));
    }
}
