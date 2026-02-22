// FRD: specs/frds/FRD-M005-core-connection.md

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::{MobileError, VpnConfig};

/// Internal connection state (not exposed via FFI)
#[derive(Debug, Clone)]
enum ConnectionState {
    Disconnected,
    Connecting,
    Connected { started_at: Instant },
}

/// VPN connection manager
#[derive(uniffi::Object)]
pub struct VpnConnection {
    state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<ConnectionStats>>,
}

/// Connection statistics
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct ConnectionStats {
    /// Total bytes uploaded
    pub bytes_sent: u64,
    /// Total bytes downloaded
    pub bytes_received: u64,
    /// Connection duration in seconds
    pub duration_secs: u64,
    /// Server round-trip time in milliseconds
    pub server_latency_ms: u32,
}

/// Connection status (exposed via FFI)
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionStatus {
    /// No active connection
    Disconnected,
    /// Connection attempt in progress
    Connecting,
    /// Active VPN tunnel
    Connected,
    /// Attempting to restore connection
    Reconnecting,
    /// Connection failed or encountered error
    Error,
}

#[uniffi::export]
impl VpnConnection {
    /// Create a new VPN connection with the given configuration
    #[uniffi::constructor]
    pub fn new(config: VpnConfig) -> Result<Self, MobileError> {
        crate::validate_config(config)?;

        Ok(Self {
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(ConnectionStats::default())),
        })
    }

    /// Initiate VPN connection
    pub fn connect(&self) -> Result<(), MobileError> {
        let mut state = self.state.write().unwrap();

        match *state {
            ConnectionState::Disconnected => {
                *state = ConnectionState::Connecting;
                drop(state); // Release lock before spawning

                // Spawn background connection task
                let state_arc = Arc::clone(&self.state);
                std::thread::spawn(move || {
                    // Simulate async connection with tokio runtime
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async {
                        simulate_connection_async(state_arc).await;
                    });
                });

                Ok(())
            }
            ConnectionState::Connecting | ConnectionState::Connected { .. } => Err(MobileError::InvalidConfig {
                reason: "already connecting or connected".to_string(),
            }),
        }
    }

    /// Tear down VPN connection
    pub fn disconnect(&self) {
        let mut state = self.state.write().unwrap();
        *state = ConnectionState::Disconnected;

        // Reset stats
        let mut stats = self.stats.write().unwrap();
        *stats = ConnectionStats::default();
    }

    /// Get current connection status
    pub fn status(&self) -> ConnectionStatus {
        let state = self.state.read().unwrap();
        match *state {
            ConnectionState::Disconnected => ConnectionStatus::Disconnected,
            ConnectionState::Connecting => ConnectionStatus::Connecting,
            ConnectionState::Connected { .. } => ConnectionStatus::Connected,
        }
    }

    /// Get connection statistics (None if not connected)
    pub fn stats(&self) -> Option<ConnectionStats> {
        let state = self.state.read().unwrap();
        if let ConnectionState::Connected { started_at } = *state {
            let mut stats = self.stats.read().unwrap().clone();
            stats.duration_secs = started_at.elapsed().as_secs();
            Some(stats)
        } else {
            None
        }
    }
}

/// Simulate async connection (stub implementation for Feature 1.5)
///
/// In a real implementation, this would:
/// 1. Create QUIC endpoint
/// 2. Connect to server
/// 3. Establish MASQUE tunnel
/// 4. Perform hybrid handshake
///
/// For the stub, we simulate a successful connection after 100ms.
async fn simulate_connection_async(state: Arc<RwLock<ConnectionState>>) {
    // Simulate connection delay
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Transition to connected
    let mut s = state.write().unwrap();
    *s = ConnectionState::Connected {
        started_at: Instant::now(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> VpnConfig {
        VpnConfig {
            client_name: "test-client".to_string(),
            server_endpoint: "vpn.example.com:443".to_string(),
            server_public_key: vec![0u8; 32],
            server_pq_public_key: vec![0u8; 1184],
            client_private_key: vec![0u8; 32],
            assigned_ip: "10.66.66.2/32".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
            mtu: 1280,
        }
    }

    #[test]
    fn test_new_with_valid_config() {
        // Test mutant: verify constructor validates config
        let config = create_test_config();
        let result = VpnConnection::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_new_with_invalid_config() {
        // Test mutant: verify constructor rejects invalid config
        let mut config = create_test_config();
        config.server_endpoint = String::new(); // Invalid

        let result = VpnConnection::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_initial_state_is_disconnected() {
        // Test mutant: verify initial state
        let conn = VpnConnection::new(create_test_config()).unwrap();
        assert_eq!(conn.status(), ConnectionStatus::Disconnected);
    }

    #[test]
    fn test_connect_transitions_to_connecting() {
        // Test mutant: verify state transition
        let conn = VpnConnection::new(create_test_config()).unwrap();
        conn.connect().unwrap();
        assert_eq!(conn.status(), ConnectionStatus::Connecting);
    }

    #[test]
    fn test_connect_while_connecting_fails() {
        // Test mutant: verify invalid transition is rejected
        let conn = VpnConnection::new(create_test_config()).unwrap();
        conn.connect().unwrap();

        let result = conn.connect();
        assert!(result.is_err());
    }

    #[test]
    fn test_disconnect_from_any_state() {
        // Test mutant: verify disconnect always works
        let conn = VpnConnection::new(create_test_config()).unwrap();

        // From disconnected
        conn.disconnect();
        assert_eq!(conn.status(), ConnectionStatus::Disconnected);

        // From connecting
        conn.connect().unwrap();
        conn.disconnect();
        assert_eq!(conn.status(), ConnectionStatus::Disconnected);
    }

    #[test]
    fn test_stats_none_when_disconnected() {
        // Test mutant: verify stats not available when disconnected
        let conn = VpnConnection::new(create_test_config()).unwrap();
        assert!(conn.stats().is_none());
    }

    #[test]
    fn test_async_connection_succeeds() {
        // Test mutant: verify async connection simulation works
        let conn = VpnConnection::new(create_test_config()).unwrap();
        conn.connect().unwrap();

        // Wait for async connection to complete
        std::thread::sleep(Duration::from_millis(200));

        assert_eq!(conn.status(), ConnectionStatus::Connected);
    }

    #[test]
    fn test_stats_available_when_connected() {
        // Test mutant: verify stats returns Some when connected
        let conn = VpnConnection::new(create_test_config()).unwrap();
        conn.connect().unwrap();

        // Wait for connection
        std::thread::sleep(Duration::from_millis(200));

        let stats = conn.stats();
        assert!(stats.is_some());
        assert_eq!(stats.unwrap().duration_secs, 0); // Just connected
    }

    #[test]
    fn test_disconnect_while_connected() {
        // Test mutant: verify can disconnect from connected state
        let conn = VpnConnection::new(create_test_config()).unwrap();
        conn.connect().unwrap();
        std::thread::sleep(Duration::from_millis(200));

        assert_eq!(conn.status(), ConnectionStatus::Connected);

        conn.disconnect();
        assert_eq!(conn.status(), ConnectionStatus::Disconnected);
        assert!(conn.stats().is_none());
    }
}
