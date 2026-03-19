// FRD: specs/frds/FRD-008.md

//! TUN device abstraction and configuration.
//!
//! The [`TunDevice`] trait enables testing the VPN tunnel logic without
//! requiring root privileges or a real TUN device. Production code uses
//! `SystemTun` (Linux, requires `CAP_NET_ADMIN`), while tests use
//! [`MockTun`](super::MockTun).

use std::net::Ipv4Addr;

/// Default inner tunnel MTU.
///
/// Must fit within a single QUIC datagram after encryption (26 bytes) and
/// MASQUE framing (~4 bytes) overhead. Quinn's min QUIC UDP payload is
/// 1200 bytes, but QUIC packet headers consume ~30 bytes, leaving ~1170
/// bytes for datagram payload. With 30 bytes of tunnel overhead:
/// 1170 − 30 = 1140, rounded down to 1100 for safety.
pub const DEFAULT_TUNNEL_MTU: u16 = 1100;

/// Minimum allowed tunnel MTU (conservative lower bound).
pub const MIN_TUNNEL_MTU: u16 = 576;

/// Maximum allowed tunnel MTU (WireGuard-equivalent for Ethernet).
pub const MAX_TUNNEL_MTU: u16 = 1420;

/// Default TUN device name.
pub const DEFAULT_TUN_NAME: &str = "prrr0";

/// Configuration for creating a TUN device.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (e.g., "prrr0").
    pub name: String,
    /// IPv4 address for the tunnel interface.
    pub address: Ipv4Addr,
    /// IPv4 netmask for the tunnel interface.
    pub netmask: Ipv4Addr,
    /// Point-to-point destination address (optional).
    pub destination: Option<Ipv4Addr>,
    /// Maximum transmission unit for inner packets.
    pub mtu: u16,
}

impl TunConfig {
    /// Create a new TUN configuration with the given address.
    ///
    /// Uses default name, netmask (/24), and MTU.
    pub fn new(address: Ipv4Addr) -> Self {
        Self {
            name: DEFAULT_TUN_NAME.to_string(),
            address,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            destination: None,
            mtu: DEFAULT_TUNNEL_MTU,
        }
    }

    /// Set the device name.
    pub fn with_name(mut self, name: String) -> Self {
        self.name = name;
        self
    }

    /// Set the netmask.
    pub fn with_netmask(mut self, netmask: Ipv4Addr) -> Self {
        self.netmask = netmask;
        self
    }

    /// Set point-to-point destination address.
    pub fn with_destination(mut self, dest: Ipv4Addr) -> Self {
        self.destination = Some(dest);
        self
    }

    /// Set the MTU, clamped to the valid range.
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu.clamp(MIN_TUNNEL_MTU, MAX_TUNNEL_MTU);
        self
    }
}

/// A real Linux TUN device backed by `tokio_tun`.
///
/// Requires `CAP_NET_ADMIN` or root privileges to create.
#[cfg(feature = "system-tun")]
pub struct SystemTun {
    inner: tokio_tun::Tun,
    device_name: String,
    device_mtu: u16,
}

#[cfg(feature = "system-tun")]
impl SystemTun {
    /// Create a new system TUN device from a [`TunConfig`].
    pub fn from_config(config: &TunConfig) -> std::io::Result<Self> {
        let mut builder = tokio_tun::Tun::builder()
            .name(&config.name)
            .address(config.address)
            .netmask(config.netmask)
            .mtu(i32::from(config.mtu))
            .up();

        if let Some(dest) = config.destination {
            builder = builder.destination(dest);
        }

        let tuns = builder.build().map_err(|e| std::io::Error::other(e.to_string()))?;

        let tun = tuns
            .into_iter()
            .next()
            .ok_or_else(|| std::io::Error::other("no TUN device created"))?;

        let device_name = tun.name().to_string();
        let device_mtu = config.mtu;

        Ok(Self {
            inner: tun,
            device_name,
            device_mtu,
        })
    }
}

#[cfg(feature = "system-tun")]
impl TunDevice for SystemTun {
    fn name(&self) -> &str {
        &self.device_name
    }

    fn mtu(&self) -> u16 {
        self.device_mtu
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.recv(buf).await
    }

    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.send(buf).await
    }
}

/// Factory for creating real Linux TUN devices.
///
/// Each call to `create_tun()` creates a system TUN interface with a
/// unique name (`prrr0`, `prrr1`, ...) using the IP address from the
/// provided [`TunConfig`]. The handle type is `()` since real TUN
/// devices don't need a test handle.
///
/// Requires `CAP_NET_ADMIN` or root privileges.
#[cfg(feature = "system-tun")]
pub struct SystemTunFactory {
    counter: std::sync::atomic::AtomicU32,
}

#[cfg(feature = "system-tun")]
impl SystemTunFactory {
    /// Create a new factory starting device names at `prrr0`.
    pub fn new() -> Self {
        Self {
            counter: std::sync::atomic::AtomicU32::new(0),
        }
    }
}

#[cfg(feature = "system-tun")]
impl Default for SystemTunFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "system-tun")]
impl super::TunFactory for SystemTunFactory {
    type Tun = SystemTun;
    type Handle = ();

    fn create_tun(&self, config: &TunConfig) -> Result<(SystemTun, ()), super::TunnelError> {
        let index = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let device_name = format!("prrr{index}");
        let config = TunConfig {
            name: device_name,
            ..config.clone()
        };
        let tun = SystemTun::from_config(&config)?;
        Ok((tun, ()))
    }
}

/// Abstraction over a TUN network device for reading/writing IP packets.
///
/// Implementations must be `Send + Sync` for use in async pipelines.
/// The trait uses `&self` (not `&mut self`) to allow concurrent read/write
/// from separate tasks.
pub trait TunDevice: Send + Sync {
    /// Returns the device name (e.g., "prrr0").
    fn name(&self) -> &str;

    /// Returns the configured MTU.
    fn mtu(&self) -> u16;

    /// Receive an IP packet from the TUN device.
    ///
    /// Reads into `buf` and returns the number of bytes read.
    /// This is an async operation that blocks until a packet is available.
    fn recv(&self, buf: &mut [u8]) -> impl std::future::Future<Output = std::io::Result<usize>> + Send;

    /// Send an IP packet into the TUN device.
    ///
    /// Returns the number of bytes written.
    fn send(&self, buf: &[u8]) -> impl std::future::Future<Output = std::io::Result<usize>> + Send;
}

/// Blanket implementation allowing a TUN device wrapped in [`Arc`] to be
/// shared across reconnection attempts. Each reconnect creates a new
/// [`TunnelPipeline`] with a clone of the `Arc`, while the underlying
/// TUN device persists.
///
/// [`TunnelPipeline`]: crate::tunnel::TunnelPipeline
impl<T: TunDevice> TunDevice for std::sync::Arc<T> {
    fn name(&self) -> &str {
        (**self).name()
    }

    fn mtu(&self) -> u16 {
        (**self).mtu()
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        (**self).recv(buf).await
    }

    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        (**self).send(buf).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-3: TunConfig builds with all fields
    #[test]
    fn tun_config_default_values() {
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let config = TunConfig::new(addr);

        assert_eq!(config.name, DEFAULT_TUN_NAME);
        assert_eq!(config.address, addr);
        assert_eq!(config.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(config.mtu, DEFAULT_TUNNEL_MTU);
    }

    #[test]
    fn tun_config_builder_methods() {
        let config = TunConfig::new(Ipv4Addr::new(10, 0, 0, 1))
            .with_name("test0".to_string())
            .with_netmask(Ipv4Addr::new(255, 255, 0, 0))
            .with_mtu(1400);

        assert_eq!(config.name, "test0");
        assert_eq!(config.netmask, Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(config.mtu, 1400);
    }

    #[test]
    fn tun_config_mtu_clamped_to_min() {
        let config = TunConfig::new(Ipv4Addr::new(10, 0, 0, 1)).with_mtu(100);
        assert_eq!(config.mtu, MIN_TUNNEL_MTU);
    }

    #[test]
    fn tun_config_mtu_clamped_to_max() {
        let config = TunConfig::new(Ipv4Addr::new(10, 0, 0, 1)).with_mtu(9000);
        assert_eq!(config.mtu, MAX_TUNNEL_MTU);
    }
}
