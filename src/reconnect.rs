// FRD: specs/frds/FRD-20260223-client-reconnection.md

//! Transport-agnostic client reconnection with exponential backoff.
//!
//! When a VPN transport connection drops, the client re-establishes a
//! new session (new handshake, new keys) automatically. The TUN device
//! persists across reconnections so the client's IP address does not
//! change.
//!
//! The reconnection loop calls [`ClientTransport::connect()`] in a retry
//! loop with exponential backoff and jitter. On cancellation the loop
//! exits cleanly.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::{
    handshake::noise_ik::KeyPair,
    transport::{ClientTransport, encrypted_channel::EncryptedChannel, traits::ClientConnectParams},
    tunnel::{TunnelError, pipeline::TrafficStats, tun_device::TunDevice},
};

/// Default initial backoff delay in milliseconds.
pub const DEFAULT_BACKOFF_INITIAL_MS: u64 = 1000;

/// Default maximum backoff delay in milliseconds.
pub const DEFAULT_BACKOFF_MAX_MS: u64 = 30_000;

/// Jitter fraction applied to backoff delays (+-25%).
const JITTER_FRACTION_PERCENT: u64 = 25;

/// Percentage base for jitter calculation.
const PERCENT_BASE: u64 = 100;

/// Exponential backoff state with jitter.
///
/// Starts at `initial_ms`, doubles on each consecutive failure, and
/// caps at `max_ms`. Each delay has +-25% jitter applied.
pub struct BackoffState {
    initial_ms: u64,
    max_ms: u64,
    current_ms: u64,
}

impl BackoffState {
    /// Create a new backoff state with the given initial and maximum delays.
    pub fn new(initial_ms: u64, max_ms: u64) -> Self {
        Self {
            initial_ms,
            max_ms,
            current_ms: initial_ms,
        }
    }

    /// Return the next backoff delay (without jitter) and advance the state.
    ///
    /// The delay doubles on each call, capped at `max_ms`.
    pub fn next_delay_ms(&mut self) -> u64 {
        let delay = self.current_ms;
        self.current_ms = self.current_ms.saturating_mul(2).min(self.max_ms);
        delay
    }

    /// Return the next backoff delay with +-25% jitter applied.
    pub fn next_delay_with_jitter(&mut self) -> Duration {
        let base_ms = self.next_delay_ms();
        let jitter_range = base_ms * JITTER_FRACTION_PERCENT / PERCENT_BASE;
        let jittered = if jitter_range > 0 {
            let offset = crate::obfuscation::traffic_morph::compute_jitter(jitter_range * 2);
            let offset_ms = offset.as_millis() as u64;
            // Shift from [0, 2*range) to [-range, +range)
            base_ms.saturating_add(offset_ms).saturating_sub(jitter_range)
        } else {
            base_ms
        };
        Duration::from_millis(jittered)
    }

    /// Reset the backoff state to the initial delay.
    pub fn reset(&mut self) {
        self.current_ms = self.initial_ms;
    }
}

/// Parameters for the reconnection loop.
pub struct ReconnectConfig {
    /// Initial backoff delay in milliseconds.
    pub backoff_initial_ms: u64,
    /// Maximum backoff delay in milliseconds.
    pub backoff_max_ms: u64,
    /// Interval between resource hostname re-resolution rounds while the
    /// tunnel is up. Also applied once before every route setup (each
    /// connect/reconnect). See BUG-resource-ip-staleness.
    pub resource_refresh: std::time::Duration,
    /// Interval between data-plane liveness checks while the pipeline runs.
    /// See [`DEFAULT_DEAD_TUNNEL_CHECK`].
    pub dead_tunnel_check: std::time::Duration,
    /// Consecutive checks that must show outbound progress with zero inbound
    /// progress before the tunnel is declared black-holed.
    pub dead_tunnel_strikes: u32,
    /// Interval between liveness probes of the DNS servers this tunnel
    /// advertises to the host. See [`DEFAULT_DNS_CHECK`].
    pub dns_check: std::time::Duration,
    /// How long one DNS probe waits for an answer. See [`DEFAULT_DNS_PROBE_TIMEOUT`].
    pub dns_probe_timeout: std::time::Duration,
    /// UDP port the DNS probe questions. Production keeps 53; black-box tests
    /// point it at a fixture responder, because port 53 needs privileges.
    pub dns_probe_port: u16,
    /// Wall-clock budget for one resource-resolution round before it is
    /// abandoned and the next tick retries. See [`DEFAULT_RESOURCE_REFRESH_BUDGET`].
    pub resource_refresh_budget: Duration,
    /// How long a DNS liveness verdict may go unrefreshed before the tunnel
    /// resolver is withdrawn. See [`DEFAULT_DNS_VERDICT_LEASE`].
    pub dns_verdict_lease: Duration,
}

/// Default interval for resource hostname re-resolution (1 minute).
pub const DEFAULT_RESOURCE_REFRESH: std::time::Duration = std::time::Duration::from_secs(60);

/// Default interval between data-plane liveness checks (5 seconds).
pub const DEFAULT_DEAD_TUNNEL_CHECK: std::time::Duration = std::time::Duration::from_secs(5);

/// Default number of silent liveness checks before a sending tunnel is
/// declared dead (3 × 5 s = 15 s of one-way traffic).
pub const DEFAULT_DEAD_TUNNEL_STRIKES: u32 = 3;

/// Default interval between tunnel-resolver liveness probes (15 seconds).
///
/// Long enough that a healthy tunnel pays one extra datagram per interval,
/// short enough that a tunnel whose resolver died stops starving host
/// resolution within a human-noticeable window.
pub const DEFAULT_DNS_CHECK: std::time::Duration = std::time::Duration::from_secs(15);

/// Default wait for a DNS probe answer (2 seconds).
pub const DEFAULT_DNS_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Default DNS port the probe questions.
pub const DEFAULT_DNS_PROBE_PORT: u16 = crate::dns_probe::DNS_PORT;

/// Default budget for one resource-resolution round (20 seconds).
///
/// A round that cannot answer its own hostnames inside this window is dropped
/// rather than awaited: the previous routes keep working, and the data plane
/// keeps moving packets. It is a pass/fail gate on the lookup path, not a
/// forecast of how long a round takes.
pub const DEFAULT_RESOURCE_REFRESH_BUDGET: Duration = Duration::from_secs(20);

/// Default age a DNS liveness verdict may reach before the tunnel resolver is
/// withdrawn (45 seconds, three probe intervals).
///
/// Three intervals so a couple of lost probe datagrams on a lossy path do not
/// make the host's resolver flap, while a prober that stopped reporting at all
/// cannot keep the host pinned to a dead resolver indefinitely.
pub const DEFAULT_DNS_VERDICT_LEASE: Duration = Duration::from_secs(45);

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            backoff_initial_ms: DEFAULT_BACKOFF_INITIAL_MS,
            backoff_max_ms: DEFAULT_BACKOFF_MAX_MS,
            resource_refresh: DEFAULT_RESOURCE_REFRESH,
            dead_tunnel_check: DEFAULT_DEAD_TUNNEL_CHECK,
            dead_tunnel_strikes: DEFAULT_DEAD_TUNNEL_STRIKES,
            dns_check: DEFAULT_DNS_CHECK,
            dns_probe_timeout: DEFAULT_DNS_PROBE_TIMEOUT,
            dns_probe_port: DEFAULT_DNS_PROBE_PORT,
            resource_refresh_budget: DEFAULT_RESOURCE_REFRESH_BUDGET,
            dns_verdict_lease: DEFAULT_DNS_VERDICT_LEASE,
        }
    }
}

impl ReconnectConfig {
    /// Wall-clock window of sending-without-receiving that condemns the tunnel
    /// (`dead_tunnel_check` × `dead_tunnel_strikes`).
    pub fn dead_tunnel_deadline(&self) -> std::time::Duration {
        self.dead_tunnel_check * self.dead_tunnel_strikes
    }
}

/// Cryptographic material needed for each reconnection handshake.
pub struct ReconnectCryptoParams<'a> {
    /// Client's Noise IK keypair.
    pub noise_keypair: &'a KeyPair,
    /// Server's Noise IK public key.
    pub server_noise_pub: &'a [u8; 32],
    /// Server's ML-KEM-768 encapsulation key.
    pub server_kem_pub: &'a [u8],
}

/// Detects a one-way (black-holed) tunnel from traffic-counter progress.
///
/// A tunnel whose TUN address was flushed, or whose peer relay died while QUIC
/// keeps answering, still *accepts* our packets: `bytes_sent` advances while
/// `bytes_received` never moves, and no transport error is ever raised. The
/// detector turns that signature into a verdict so the reconnect loop can tear
/// routing down (traffic falls back to the host default route) and re-establish
/// the session. An idle tunnel — no progress in either direction — proves
/// nothing and never trips.
/// BUG: specs/bugs/BUG-network-manager-tun-address-loss.md
#[derive(Debug)]
pub(crate) struct BlackHoleDetector {
    /// Consecutive one-way checks required before declaring the tunnel dead.
    strikes_max: u32,
    /// Last observed `bytes_sent`, to spot outbound progress.
    last_sent: u64,
    /// Last observed `bytes_received`, to spot inbound progress.
    last_received: u64,
    /// Consecutive one-way checks so far.
    strikes: u32,
}

impl BlackHoleDetector {
    /// Create a detector tripping after `strikes_max` one-way checks.
    pub(crate) fn new(strikes_max: u32) -> Self {
        Self {
            strikes_max,
            last_sent: 0,
            last_received: 0,
            strikes: 0,
        }
    }

    /// Record one observation of the shared counters; `true` means the tunnel
    /// is black-holing. Any inbound progress clears the strike count.
    pub(crate) fn observe(&mut self, stats: &TrafficStats) -> bool {
        let order = std::sync::atomic::Ordering::Relaxed;
        let sent = stats.bytes_sent.load(order);
        let received = stats.bytes_received.load(order);
        let sent_advanced = sent > self.last_sent;
        let received_advanced = received > self.last_received;
        self.last_sent = sent;
        self.last_received = received;

        if received_advanced {
            self.strikes = 0;
            return false;
        }
        if sent_advanced {
            self.strikes += 1;
            return self.strikes >= self.strikes_max;
        }
        false
    }
}

/// Per-session prober for the DNS servers the tunnel advertises.
///
/// The configured resolvers are pinned through the TUN and handed to the system
/// resolver, so a resolver that stops answering hangs every lookup on the host
/// — worse than the uncensored-but-working resolver it replaced. One
/// well-formed question per round tells a live responder from a black hole; the
/// verdict travels on a [`tokio::sync::watch`] channel because only the newest
/// answer matters.
/// BUG: specs/bugs/BUG-network-manager-tun-address-loss.md
struct DnsProber {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl DnsProber {
    /// Stop publishing verdicts and drop the task. The in-flight blocking
    /// probe finishes on its own within the probe timeout.
    fn stop(self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

/// Spawn a [`DnsProber`] that questions every pinned `targets` address
/// immediately and then every `config.dns_check`, waiting at most
/// `config.dns_probe_timeout` per server.
///
/// The question leaves on a plain UDP socket (no `SO_MARK`) from the blocking
/// pool, so the kernel picks the path exactly as it does for an application
/// lookup — which is the path being gated, thanks to the `/32` pin the hook
/// keeps installed in both gate states. It must not run on the pipeline's task:
/// a dead resolver would otherwise stall the tunnel for one timeout per round.
///
/// Each round reports the responders that answered, not a single yes/no: the
/// first configured address may be unreachable for this peer while a later one
/// answers, and that tunnel still has working DNS.
/// BUG: specs/bugs/BUG-tunnel-dns-single-probe-target.md
fn spawn_dns_prober(
    targets: Vec<std::net::Ipv4Addr>,
    config: &ReconnectConfig,
    health: tokio::sync::watch::Sender<Vec<std::net::Ipv4Addr>>,
    parent: &CancellationToken,
) -> DnsProber {
    let cancel = parent.child_token();
    let (interval, timeout, port) = (config.dns_check, config.dns_probe_timeout, config.dns_probe_port);
    let targets = std::sync::Arc::new(targets);
    let task = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            let mut ticker = tokio::time::interval_at(tokio::time::Instant::now(), interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    _ = ticker.tick() => {}
                }
                let targets = std::sync::Arc::clone(&targets);
                let probe = tokio::task::spawn_blocking(move || {
                    targets
                        .iter()
                        .copied()
                        .filter(|target| {
                            let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(*target), port);
                            crate::dns_probe::responds_at_addr(addr, timeout)
                        })
                        .collect::<Vec<_>>()
                })
                .await;
                match probe {
                    // A closed receiver means the tunnel loop has moved on.
                    Ok(alive) => {
                        if health.send(alive).is_err() {
                            break;
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "DNS liveness probe task failed; keeping the current DNS gate"),
                }
            }
        }
    });
    DnsProber { cancel, task }
}

/// Run the VPN client with automatic reconnection on transport failure.
///
/// Creates a new session (new handshake, new keys) on each reconnection
/// attempt. The TUN device persists across reconnections.
///
/// When `route_manager` is provided, routes are set up after each successful
/// transport connection and torn down before retrying or exiting. This
/// ensures routing only exists while the tunnel is active.
///
/// When `registrar` is provided, prrr publishes its ecosystem descriptor
/// (SPEC §3) on tunnel up and updates it to the not-connected state on tunnel
/// down. Registration is best-effort and never blocks the tunnel.
///
/// Exits cleanly when `cancel` is triggered (returns `Ok(())`).
/// Only retries on transport/pipeline errors, not on cancellation.
pub async fn run_with_reconnect<T: TunDevice + Clone>(
    transport: &dyn ClientTransport,
    crypto: &ReconnectCryptoParams<'_>,
    tun: T,
    config: &ReconnectConfig,
    mut route_manager: Option<&mut crate::routing::RouteManager>,
    registrar: Option<&crate::ecosystem::EcosystemRegistrar>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let mut backoff = BackoffState::new(config.backoff_initial_ms, config.backoff_max_ms);

    loop {
        let params = ClientConnectParams {
            noise_keypair: crypto.noise_keypair,
            server_noise_pub: crypto.server_noise_pub,
            server_kem_pub: crypto.server_kem_pub,
            cancel: cancel.clone(),
        };

        let conn = match transport.connect(params).await {
            Ok(conn) => {
                backoff.reset();
                tracing::info!(transport = transport.name(), "transport connected");
                conn
            }
            Err(e) => {
                if cancel.is_cancelled() {
                    tracing::info!("reconnect loop cancelled during connect");
                    return Ok(());
                }
                let delay = backoff.next_delay_with_jitter();
                tracing::warn!(
                    transport = transport.name(),
                    error = %e,
                    backoff_ms = delay.as_millis() as u64,
                    "transport connect failed, retrying"
                );
                tokio::select! {
                    () = tokio::time::sleep(delay) => continue,
                    () = cancel.cancelled() => {
                        tracing::info!("reconnect loop cancelled during backoff");
                        return Ok(());
                    }
                }
            }
        };

        // Set up routes after transport connects. The first re-resolution round
        // comes from the refresher task instead of being awaited here: the
        // lookup path is precisely what stalls when DNS is unhealthy, and
        // `up()` already installs the answers captured at startup.
        // BUG: specs/bugs/BUG-pipeline-refresh-starves-packet-pump.md
        if let Some(ref mut rm) = route_manager {
            rm.up();
        }
        // Register with the ecosystem registry on tunnel up (best-effort).
        if let Some(reg) = registrar {
            reg.on_up();
        }

        let channel = EncryptedChannel::new(conn.session_keys.tx_key, conn.session_keys.rx_key);
        let stats = std::sync::Arc::new(TrafficStats::new());
        let watchdog_stats = std::sync::Arc::clone(&stats);
        let pipeline = crate::tunnel::TunnelPipeline::new(tun.clone(), channel, conn.sender, conn.receiver, stats);

        tracing::info!("tunnel pipeline running");
        // Drive the pipeline alongside two independent timers:
        //   * resource refresh — re-resolve hostname resources so rotating CDN
        //     answers keep the policy-table /32 routes effective;
        //   * black-hole watchdog — catch a tunnel that keeps swallowing our
        //     packets while nothing ever comes back (no transport error is
        //     raised in that state, so the loop would otherwise run forever).
        let pipeline_fut = std::pin::pin!(pipeline.run(cancel.clone()));
        let mut pipeline_fut = pipeline_fut;
        // Resource re-resolution lives on its own task and reports through this
        // channel. It is never awaited in this loop, because this loop is the
        // only thing polling the packet pump, the black-hole watchdog and the
        // DNS gate — a round awaited here stops all three while it waits.
        // BUG: specs/bugs/BUG-pipeline-refresh-starves-packet-pump.md
        let (refresh_tx, mut refresh_rx) = tokio::sync::mpsc::unbounded_channel();
        let refresh_enabled = match route_manager.as_deref().and_then(|rm| rm.resource_refresh_inputs()) {
            Some((resources, resolver)) => {
                spawn_resource_refresher(resources, resolver, config, &cancel, refresh_tx);
                true
            }
            None => false,
        };
        // The tunnel's resolvers are pinned through this device and handed to
        // the system resolver, so their liveness is probed off-loop and fed to
        // the route manager, which re-runs the hook on a change. Until the
        // first verdict lands the gate stays as the hook last left it.
        let (dns_health_tx, mut dns_health_rx) = tokio::sync::watch::channel(Vec::new());
        let dns_prober = route_manager
            .as_deref()
            .map(|rm| rm.dns_probe_targets())
            .filter(|targets| !targets.is_empty())
            .map(|targets| spawn_dns_prober(targets, config, dns_health_tx, &cancel));
        // Without a prober the sender was dropped with the mapping closure, so
        // the branch must stay disabled — a closed watch channel would resolve
        // instantly and spin the pipeline loop.
        let mut dns_verdicts = dns_prober.is_some();
        let mut refresh_open = refresh_enabled;
        let mut dns_lease = DnsVerdictLease::new(config.dns_verdict_lease, tokio::time::Instant::now());
        let mut watchdog = tokio::time::interval_at(tokio::time::Instant::now() + config.dead_tunnel_check, config.dead_tunnel_check);
        watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut detector = BlackHoleDetector::new(config.dead_tunnel_strikes);
        let outcome = loop {
            tokio::select! {
                result = &mut pipeline_fut => break result,
                _ = watchdog.tick() => {
                    if dns_verdicts && dns_lease.expire_if_stale(tokio::time::Instant::now()) {
                        tracing::warn!(
                            lease_secs = config.dns_verdict_lease.as_secs(),
                            "no DNS liveness verdict within its lease; withdrawing the tunnel resolver rather than trusting a stale verdict"
                        );
                        if let Some(rm) = route_manager.as_deref_mut() {
                            rm.observe_dns_health(&[]);
                        }
                    }
                    if detector.observe(&watchdog_stats) {
                        tracing::error!(
                            transport = transport.name(),
                            deadline_secs = config.dead_tunnel_deadline().as_secs(),
                            bytes_sent = watchdog_stats.bytes_sent.load(std::sync::atomic::Ordering::Relaxed),
                            "tunnel is black-holing — outbound traffic with no inbound answer, reconnecting"
                        );
                        break Err(TunnelError::BlackHoled {
                            deadline_secs: config.dead_tunnel_deadline().as_secs(),
                        });
                    }
                }
                round = refresh_rx.recv(), if refresh_open => {
                    match round {
                        Some(ips) => {
                            if let Some(rm) = route_manager.as_deref_mut() {
                                rm.apply_resource_ips(ips);
                            }
                        }
                        // The refresher exited (cancelled or dropped its
                        // sender): stop polling a channel that cannot deliver.
                        None => refresh_open = false,
                    }
                }
                alive = dns_health_rx.changed(), if dns_verdicts => {
                    match alive {
                        Ok(()) => {
                            let responders = dns_health_rx.borrow_and_update().clone();
                            dns_lease.note_verdict(tokio::time::Instant::now());
                            if let Some(rm) = route_manager.as_deref_mut() {
                                rm.observe_dns_health(&responders);
                            }
                        }
                        // The prober is gone (cancelled or panicked) and no
                        // verdict can ever arrive again. Stop listening *and*
                        // withdraw the advertisement: a verdict that can never
                        // be refreshed must not leave the host pointed at a
                        // resolver nobody is checking anymore.
                        Err(_) => {
                            dns_verdicts = false;
                            // Only a prober that died on its own is an emergency:
                            // during shutdown `down()` reverts the link anyway, and
                            // withdrawing here would re-run the hook for nothing.
                            if !cancel.is_cancelled() {
                                if let Some(rm) = route_manager.as_deref_mut() {
                                    rm.observe_dns_health(&[]);
                                }
                            }
                        }
                    }
                }
            }
        };
        // Stop probing before the routes come down: the tunnel it measured is
        // over, and a late verdict must not re-shuffle the host's resolvers.
        if let Some(prober) = dns_prober {
            prober.stop();
        }
        match outcome {
            Ok(()) => {
                // Tear down routes on clean exit
                if let Some(ref mut rm) = route_manager {
                    rm.down();
                }
                if let Some(reg) = registrar {
                    reg.on_down();
                }
                tracing::info!("tunnel pipeline exited cleanly");
                return Ok(());
            }
            Err(TunnelError::Cancelled) => {
                // Tear down routes on cancellation
                if let Some(ref mut rm) = route_manager {
                    rm.down();
                }
                if let Some(reg) = registrar {
                    reg.on_down();
                }
                tracing::info!("tunnel pipeline cancelled — shutting down");
                return Ok(());
            }
            Err(e) => {
                // Tear down routes before retry
                if let Some(ref mut rm) = route_manager {
                    rm.down();
                }
                if let Some(reg) = registrar {
                    reg.on_down();
                }
                if cancel.is_cancelled() {
                    tracing::info!("reconnect loop cancelled after pipeline error");
                    return Ok(());
                }
                let delay = backoff.next_delay_with_jitter();
                tracing::warn!(
                    transport = transport.name(),
                    error = %e,
                    backoff_ms = delay.as_millis() as u64,
                    "pipeline error, reconnecting"
                );
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    () = cancel.cancelled() => {
                        tracing::info!("reconnect loop cancelled during backoff");
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Re-resolve configured resource hostnames and apply the answer to the
/// route manager. Failures keep the previous route set: the tunnel must
/// survive DNS hiccups (fail-closed remains a start-time contract).
/// Drive resource re-resolution off the pipeline loop.
///
/// Each round re-resolves the configured hostname resources on the blocking
/// pool and hands the fresh answers to the pipeline loop through `out`, which
/// folds them into the routed set. It runs on its own task with its own
/// interval on purpose: resolution goes through the host's resolver, which can
/// stall for minutes when DNS is unhealthy, and the pipeline loop is the only
/// thing polling the packet pump, the black-hole watchdog and the DNS gate.
/// A round awaited inline therefore freezes the tunnel for the duration of the
/// lookup — and a frozen tunnel makes those very lookups less likely to
/// answer, which is a deadlock by starvation rather than a slow path.
///
/// A round that overruns `budget` is abandoned, not awaited: the routes already
/// installed keep working and the next tick retries. The detached blocking
/// lookup cannot be cancelled (it is `getaddrinfo`), but it can no longer hold
/// the data plane hostage.
///
/// BUG: specs/bugs/BUG-pipeline-refresh-starves-packet-pump.md
fn spawn_resource_refresher(
    resources: Vec<String>,
    resolver: std::sync::Arc<dyn crate::routing::ResourceResolver + Send + Sync>,
    config: &ReconnectConfig,
    parent: &CancellationToken,
    out: tokio::sync::mpsc::UnboundedSender<Vec<std::net::Ipv4Addr>>,
) {
    let cancel = parent.child_token();
    let (interval, budget) = (config.resource_refresh, config.resource_refresh_budget);
    tokio::spawn(async move {
        // Immediate first round: the answers captured at startup start rotating
        // as soon as the tunnel is up rather than a full interval later.
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now(), interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                _ = ticker.tick() => {}
            }
            let (resources, resolver) = (resources.clone(), std::sync::Arc::clone(&resolver));
            let round = tokio::task::spawn_blocking(move || crate::routing::resolve_resource_ips(&resources, resolver.as_ref()));
            match tokio::time::timeout(budget, round).await {
                Ok(Ok(Ok(ips))) => {
                    if out.send(ips).is_err() {
                        // The pipeline loop has moved on to another session.
                        break;
                    }
                }
                Ok(Ok(Err(e))) => {
                    tracing::warn!(error = %e, "resource refresh failed; keeping previous resource routes");
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "resource refresh task failed; keeping previous resource routes");
                }
                Err(_) => {
                    tracing::warn!(
                        budget_secs = budget.as_secs(),
                        "resource refresh exceeded its budget; abandoning the round so the packet pump keeps running"
                    );
                }
            }
        }
    });
}

/// Age of the newest DNS liveness verdict, as enforced by the pipeline loop.
///
/// The host's resolver is pointed at the tunnel's resolver only while a probe
/// says that resolver answers. A prober that stops reporting — cancelled,
/// panicked, or starved by the loop meant to consume its verdicts — must not
/// leave the host trusting the last verdict forever. The lease withdraws the
/// tunnel resolver when no verdict arrives in time, handing lookups back to the
/// host's own resolver.
///
/// BUG: specs/bugs/BUG-pipeline-refresh-starves-packet-pump.md
#[derive(Debug, Clone)]
pub struct DnsVerdictLease {
    lease: Duration,
    seen: tokio::time::Instant,
}

impl DnsVerdictLease {
    /// Start a lease whose most recent verdict was seen at `now`.
    #[must_use]
    pub fn new(lease: Duration, now: tokio::time::Instant) -> Self {
        Self { lease, seen: now }
    }

    /// Record a fresh verdict, restarting the lease.
    pub fn note_verdict(&mut self, now: tokio::time::Instant) {
        self.seen = now;
    }

    /// Report whether the lease ran out, resetting the clock so one stale
    /// verdict costs exactly one withdrawal instead of one per tick.
    pub fn expire_if_stale(&mut self, now: tokio::time::Instant) -> bool {
        if now.duration_since(self.seen) > self.lease {
            self.seen = now;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-20260223-client-reconnection.md

    use super::*;

    // -- AC-1: BackoffState::next_delay_ms() returns initial_ms on first call --

    #[test]
    fn backoff_initial_delay() {
        let mut backoff = BackoffState::new(DEFAULT_BACKOFF_INITIAL_MS, DEFAULT_BACKOFF_MAX_MS);
        assert_eq!(backoff.next_delay_ms(), DEFAULT_BACKOFF_INITIAL_MS);
    }

    // -- AC-2: BackoffState::next_delay_ms() doubles on consecutive calls --

    #[test]
    fn backoff_doubles_on_consecutive() {
        let mut backoff = BackoffState::new(DEFAULT_BACKOFF_INITIAL_MS, DEFAULT_BACKOFF_MAX_MS);
        let first = backoff.next_delay_ms();
        let second = backoff.next_delay_ms();
        let third = backoff.next_delay_ms();
        assert_eq!(first, DEFAULT_BACKOFF_INITIAL_MS);
        assert_eq!(second, DEFAULT_BACKOFF_INITIAL_MS * 2);
        assert_eq!(third, DEFAULT_BACKOFF_INITIAL_MS * 4);
    }

    // -- AC-3: BackoffState::next_delay_ms() caps at max_ms --

    #[test]
    fn backoff_caps_at_max() {
        let initial_ms: u64 = 1000;
        let max_ms: u64 = 5000;
        let mut backoff = BackoffState::new(initial_ms, max_ms);
        let _ = backoff.next_delay_ms(); // 1000
        let _ = backoff.next_delay_ms(); // 2000
        let _ = backoff.next_delay_ms(); // 4000
        let fourth = backoff.next_delay_ms(); // capped at 5000
        assert_eq!(fourth, max_ms);
        let fifth = backoff.next_delay_ms(); // still 5000
        assert_eq!(fifth, max_ms);
    }

    // -- AC-4: BackoffState::reset() returns to initial_ms --

    #[test]
    fn backoff_reset() {
        let mut backoff = BackoffState::new(DEFAULT_BACKOFF_INITIAL_MS, DEFAULT_BACKOFF_MAX_MS);
        let _ = backoff.next_delay_ms(); // 1000
        let _ = backoff.next_delay_ms(); // 2000
        backoff.reset();
        assert_eq!(backoff.next_delay_ms(), DEFAULT_BACKOFF_INITIAL_MS);
    }

    // -- AC-5: Jitter applied to backoff delay (within +-25%) --

    #[test]
    fn backoff_jitter_within_bounds() {
        let initial_ms: u64 = 1000;
        let max_ms: u64 = 30_000;
        let jitter_range = initial_ms * JITTER_FRACTION_PERCENT / PERCENT_BASE; // 250
        let lower_bound = initial_ms - jitter_range;
        let upper_bound = initial_ms + jitter_range;
        let sample_count: usize = 100;

        for _ in 0..sample_count {
            let mut backoff = BackoffState::new(initial_ms, max_ms);
            let delay = backoff.next_delay_with_jitter();
            let ms = delay.as_millis() as u64;
            assert!(
                ms >= lower_bound && ms <= upper_bound,
                "jittered delay {ms}ms outside [{lower_bound}, {upper_bound}]"
            );
        }
    }

    // -- AC-9: TunDevice for Arc<T> --

    #[tokio::test]
    async fn tun_device_arc_wrapper() {
        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let (tun, handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = std::sync::Arc::new(tun);
        let tun_clone = std::sync::Arc::clone(&tun);

        // Both clones should reference the same device
        assert_eq!(tun.name(), tun_clone.name());
        assert_eq!(tun.mtu(), tun_clone.mtu());

        // Inject through handle, receive through Arc-wrapped TUN clone
        let test_packet = b"reconnect-tun-test";
        handle.inject_packet(test_packet).await.expect("inject");

        let mut buf = vec![0u8; 1500];
        let n = tun_clone.recv(&mut buf).await.expect("recv");
        assert_eq!(&buf[..n], test_packet);
    }

    // -- AC-6: run_with_reconnect retries on transport error --
    // -- AC-7: run_with_reconnect exits cleanly on cancellation --
    // -- AC-8: run_with_reconnect resets backoff after successful connect --

    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };

    use crate::{
        handshake::hybrid::SessionKeys,
        transport::{TransportError, traits::TransportConnection},
    };

    /// Mock transport that fails N times then succeeds once (pipeline immediately errors).
    struct FailNTransport {
        fail_count: AtomicU32,
        fail_target: u32,
        connect_count: Arc<AtomicU32>,
    }

    impl FailNTransport {
        fn new(fail_target: u32, connect_count: Arc<AtomicU32>) -> Self {
            Self {
                fail_count: AtomicU32::new(0),
                fail_target,
                connect_count,
            }
        }
    }

    impl ClientTransport for FailNTransport {
        fn name(&self) -> &str {
            "mock-fail-n"
        }

        fn connect<'a>(
            &'a self,
            _params: ClientConnectParams<'a>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<TransportConnection>> + Send + 'a>> {
            Box::pin(async {
                self.connect_count.fetch_add(1, Ordering::Relaxed);
                let count = self.fail_count.fetch_add(1, Ordering::Relaxed);
                if count < self.fail_target {
                    Err(anyhow::anyhow!("mock transport error #{}", count + 1))
                } else {
                    // Return a connection whose receiver immediately errors
                    // (simulates a very short-lived connection that triggers reconnect
                    // or the test cancels before pipeline runs)
                    Ok(mock_transport_connection())
                }
            })
        }
    }

    /// Mock transport that always succeeds but whose pipeline errors.
    struct PipelineErrorTransport {
        connect_count: Arc<AtomicU32>,
    }

    impl ClientTransport for PipelineErrorTransport {
        fn name(&self) -> &str {
            "mock-pipe-error"
        }

        fn connect<'a>(
            &'a self,
            _params: ClientConnectParams<'a>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<TransportConnection>> + Send + 'a>> {
            Box::pin(async {
                self.connect_count.fetch_add(1, Ordering::Relaxed);
                Ok(mock_transport_connection_that_errors())
            })
        }
    }

    /// Create a mock TransportConnection where receiver immediately returns an error.
    fn mock_transport_connection_that_errors() -> TransportConnection {
        use crate::{
            crypto::aead::KEY_LEN,
            transport::traits::{BoxedDatagramReceiver, BoxedDatagramSender},
        };

        struct ErrorSender;
        impl BoxedDatagramSender for ErrorSender {
            fn send_datagram(&self, _payload: &[u8]) -> Result<(), TransportError> {
                Err(TransportError::HarpChannelClosed)
            }
        }

        struct ErrorReceiver;
        impl BoxedDatagramReceiver for ErrorReceiver {
            fn recv_datagram(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>> {
                Box::pin(async { Err(TransportError::HarpChannelClosed) })
            }
        }

        TransportConnection {
            sender: Box::new(ErrorSender),
            receiver: Box::new(ErrorReceiver),
            session_keys: SessionKeys {
                tx_key: [0x01; KEY_LEN],
                rx_key: [0x02; KEY_LEN],
                header_key: [0x03; KEY_LEN],
            },
        }
    }

    /// Create a mock TransportConnection that blocks forever on recv.
    fn mock_transport_connection() -> TransportConnection {
        use crate::{
            crypto::aead::KEY_LEN,
            transport::traits::{BoxedDatagramReceiver, BoxedDatagramSender},
        };

        struct NoopSender;
        impl BoxedDatagramSender for NoopSender {
            fn send_datagram(&self, _payload: &[u8]) -> Result<(), TransportError> {
                Ok(())
            }
        }

        struct BlockingReceiver;
        impl BoxedDatagramReceiver for BlockingReceiver {
            fn recv_datagram(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>> {
                Box::pin(async {
                    // Block forever — test will cancel
                    std::future::pending().await
                })
            }
        }

        TransportConnection {
            sender: Box::new(NoopSender),
            receiver: Box::new(BlockingReceiver),
            session_keys: SessionKeys {
                tx_key: [0x01; KEY_LEN],
                rx_key: [0x02; KEY_LEN],
                header_key: [0x03; KEY_LEN],
            },
        }
    }

    struct TestCryptoMaterial {
        noise_keypair: KeyPair,
        server_noise_pub: [u8; 32],
        server_kem_pub: Vec<u8>,
    }

    impl TestCryptoMaterial {
        fn new() -> Self {
            Self {
                noise_keypair: KeyPair::generate().expect("keygen"),
                server_noise_pub: [0xAA; 32],
                server_kem_pub: vec![0xBB; 64],
            }
        }

        fn as_params(&self) -> ReconnectCryptoParams<'_> {
            ReconnectCryptoParams {
                noise_keypair: &self.noise_keypair,
                server_noise_pub: &self.server_noise_pub,
                server_kem_pub: &self.server_kem_pub,
            }
        }
    }

    // BUG: specs/bugs/BUG-resource-ip-staleness.md
    /// Resolver whose answer changes on every call, mimicking CDN rotation.
    struct ScriptedResolver {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl ScriptedResolver {
        fn answers(&self) -> Vec<std::net::IpAddr> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 10 + n as u8))]
        }
    }

    impl crate::routing::ResourceResolver for ScriptedResolver {
        fn resolve(&self, _host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
            Ok(self.answers())
        }
    }

    #[tokio::test]
    async fn reconnect_refreshes_resource_routes_from_its_own_task_while_running() {
        use std::sync::Arc;

        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let dir = Arc::new(tempfile::tempdir().expect("tempdir"));
        let log = dir.path().join("hook.log");
        let hook = dir.path().join("hook.sh");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/bash\nif [ \"$1\" = up ]; then grep PRRR_RESOURCE_IPS \"$PRRR_ENV_FILE\" >> '{}' 2>/dev/null || true; fi\n",
                log.display()
            ),
        )
        .expect("write hook");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).expect("chmod hook");
        }

        let params = crate::routing::RouteParams {
            tun_device: "prrr0".to_string(),
            client_ip: std::net::Ipv4Addr::new(10, 66, 66, 2),
            gateway_ip: std::net::Ipv4Addr::new(10, 66, 66, 1),
            server_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            server_endpoint: "vpn.example".to_string(),
            all_traffic: false,
            dns_servers: vec![],
            allowed_ips: vec![],
            excluded_ips: vec![],
            resources: vec!["chatgpt.test".to_string()],
            resource_ips: vec![std::net::Ipv4Addr::new(203, 0, 113, 1)],
            fwmark: crate::routing::DEFAULT_FWMARK,
        };
        let resolver = Arc::new(ScriptedResolver {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut route_manager = crate::routing::RouteManager::new(params, hook.display().to_string())
            .with_resolver(resolver)
            .with_env_file(dir.path().join("env"));

        let connect_count = Arc::new(AtomicU32::new(0));
        let transport = FailNTransport::new(0, Arc::clone(&connect_count));
        let crypto = TestCryptoMaterial::new();
        let (tun, _handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = Arc::new(tun);
        let cancel = CancellationToken::new();

        let config = ReconnectConfig {
            backoff_initial_ms: 1,
            backoff_max_ms: 10,
            // Load-independent budgets: a starved spawn_blocking round must
            // not flake the observation window.
            resource_refresh: Duration::from_millis(200),
            ..Default::default()
        };

        // Watch for the hook being re-run with a rotated answer while the
        // pipeline runs (proves the refresher's immediate first round and its
        // later ticks both reach the route manager without blocking the pump).
        let cancel_watcher = cancel.clone();
        let log_path = log.clone();
        let rotator = tokio::spawn(async move {
            let budget = tokio::time::sleep(Duration::from_secs(30));
            tokio::pin!(budget);
            loop {
                tokio::select! {
                    () = &mut budget => {
                        return std::fs::read_to_string(&log_path).unwrap_or_default();
                    }
                    () = tokio::time::sleep(Duration::from_millis(50)) => {
                        if let Ok(text) = std::fs::read_to_string(&log_path) {
                            if text.contains("203.0.113.12") {
                                cancel_watcher.cancel();
                                return text;
                            }
                        }
                    }
                }
            }
        });

        let result = run_with_reconnect(
            &transport,
            &crypto.as_params(),
            tun,
            &config,
            Some(&mut route_manager),
            None,
            cancel,
        )
        .await;

        assert!(result.is_ok());
        let text = rotator.await.expect("watcher task");
        assert!(
            text.contains("PRRR_RESOURCE_IPS=\"203.0.113.10 203.0.113.1\""),
            "pre-up refresh must install the resolver answer: {text}"
        );
        assert!(
            text.contains("203.0.113.12"),
            "live refresh tick must fold rotated answers into the route set: {text}"
        );
    }

    #[tokio::test]
    async fn reconnect_retries_on_connect_error() {
        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let connect_count = Arc::new(AtomicU32::new(0));
        let transport = FailNTransport::new(2, Arc::clone(&connect_count));

        let crypto = TestCryptoMaterial::new();
        let (tun, _handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = Arc::new(tun);
        let cancel = CancellationToken::new();

        let config = ReconnectConfig {
            backoff_initial_ms: 1, // 1ms for fast test
            backoff_max_ms: 10,
            resource_refresh: Duration::from_secs(300),
            ..Default::default()
        };

        // Cancel after transport succeeds and pipeline blocks
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            // Wait for 3 connect attempts (2 fail + 1 success)
            loop {
                if connect_count.load(Ordering::Relaxed) >= 3 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            cancel_clone.cancel();
        });

        let result = run_with_reconnect(&transport, &crypto.as_params(), tun, &config, None, None, cancel).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn reconnect_exits_on_cancel() {
        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let connect_count = Arc::new(AtomicU32::new(0));
        let transport = FailNTransport::new(0, Arc::clone(&connect_count));

        let crypto = TestCryptoMaterial::new();
        let (tun, _handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = Arc::new(tun);
        let cancel = CancellationToken::new();

        let config = ReconnectConfig {
            backoff_initial_ms: 1,
            backoff_max_ms: 10,
            resource_refresh: Duration::from_secs(300),
            ..Default::default()
        };

        // Cancel immediately after first connect
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            loop {
                if connect_count.load(Ordering::Relaxed) >= 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            cancel_clone.cancel();
        });

        let result = run_with_reconnect(&transport, &crypto.as_params(), tun, &config, None, None, cancel).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn reconnect_retries_on_pipeline_error() {
        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let connect_count = Arc::new(AtomicU32::new(0));
        let transport = PipelineErrorTransport {
            connect_count: Arc::clone(&connect_count),
        };

        let crypto = TestCryptoMaterial::new();
        let (tun, _handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = Arc::new(tun);
        let cancel = CancellationToken::new();

        let config = ReconnectConfig {
            backoff_initial_ms: 1,
            backoff_max_ms: 10,
            resource_refresh: Duration::from_secs(300),
            ..Default::default()
        };

        // Cancel after a few reconnect attempts
        let cancel_clone = cancel.clone();
        let count_clone = Arc::clone(&connect_count);
        let min_connect_attempts: u32 = 3;
        tokio::spawn(async move {
            loop {
                if count_clone.load(Ordering::Relaxed) >= min_connect_attempts {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            cancel_clone.cancel();
        });

        let result = run_with_reconnect(&transport, &crypto.as_params(), tun, &config, None, None, cancel).await;

        assert!(result.is_ok());
        assert!(connect_count.load(Ordering::Relaxed) >= min_connect_attempts);
    }

    // -----------------------------------------------------------------------
    // Black-holed tunnel detection (BUG-network-manager-tun-address-loss)
    //
    // A TUN that lost its address (NetworkManager flush) keeps swallowing our
    // packets while the server's relay never answers. No transport error is
    // ever raised, so only data-plane liveness can catch it.
    // -----------------------------------------------------------------------

    fn stats_with(sent: u64, received: u64) -> TrafficStats {
        let stats = TrafficStats::new();
        stats.bytes_sent.store(sent, Ordering::Relaxed);
        stats.bytes_received.store(received, Ordering::Relaxed);
        stats
    }

    #[test]
    fn detector_trips_after_consecutive_one_way_checks() {
        let stats = TrafficStats::new();
        let mut detector = BlackHoleDetector::new(3);

        stats.bytes_sent.store(100, Ordering::Relaxed);
        assert!(!detector.observe(&stats), "first one-way check must not trip");
        stats.bytes_sent.store(200, Ordering::Relaxed);
        assert!(!detector.observe(&stats), "second one-way check must not trip");
        stats.bytes_sent.store(300, Ordering::Relaxed);
        assert!(detector.observe(&stats), "third consecutive one-way check trips");
    }

    #[test]
    fn detector_clears_strikes_when_the_tunnel_answers() {
        let mut detector = BlackHoleDetector::new(2);

        assert!(!detector.observe(&stats_with(100, 0)), "one strike");
        assert!(!detector.observe(&stats_with(200, 50)), "inbound answer clears the strikes");
        assert!(!detector.observe(&stats_with(300, 50)), "one strike again after the reset");
        assert!(detector.observe(&stats_with(400, 50)), "two consecutive silent checks trip");
    }

    #[test]
    fn detector_never_trips_on_an_idle_tunnel() {
        let stats = stats_with(4096, 2048);
        let mut detector = BlackHoleDetector::new(1);
        for round in 0..5 {
            assert!(!detector.observe(&stats), "idle round {round} proves nothing");
        }
    }

    #[test]
    fn detector_ignores_inbound_only_progress() {
        let mut detector = BlackHoleDetector::new(1);
        assert!(!detector.observe(&stats_with(0, 0)), "nothing yet");
        assert!(!detector.observe(&stats_with(0, 64)), "inbound-only progress is healthy");
    }

    #[test]
    fn reconnect_deadline_is_check_times_strikes() {
        let tuned = ReconnectConfig {
            dead_tunnel_check: Duration::from_millis(500),
            dead_tunnel_strikes: 4,
            ..Default::default()
        };
        assert_eq!(tuned.dead_tunnel_deadline(), Duration::from_secs(2));
        assert_eq!(
            ReconnectConfig::default().dead_tunnel_deadline(),
            Duration::from_secs(15),
            "shipped default is 3 checks x 5s"
        );
    }

    #[tokio::test]
    async fn black_holed_tunnel_tears_down_routes_and_reconnects() {
        use std::sync::Arc;

        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("hook.log");
        let hook = dir.path().join("hook.sh");
        std::fs::write(&hook, format!("#!/bin/bash\necho \"$1\" >> '{}'\n", log.display())).expect("write hook");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).expect("chmod hook");
        }

        let params = crate::routing::RouteParams {
            tun_device: "prrr0".to_string(),
            client_ip: std::net::Ipv4Addr::new(10, 66, 66, 2),
            gateway_ip: std::net::Ipv4Addr::new(10, 66, 66, 1),
            server_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 79)),
            server_endpoint: "vpn.example".to_string(),
            all_traffic: false,
            dns_servers: vec![],
            allowed_ips: vec![],
            excluded_ips: vec![],
            resources: vec![],
            resource_ips: vec![std::net::Ipv4Addr::new(203, 0, 113, 10)],
            fwmark: crate::routing::DEFAULT_FWMARK,
        };
        let mut route_manager = crate::routing::RouteManager::new(params, hook.display().to_string()).with_env_file(dir.path().join("env"));

        let connect_count = Arc::new(AtomicU32::new(0));
        let transport = FailNTransport::new(0, Arc::clone(&connect_count));
        let crypto = TestCryptoMaterial::new();
        let (tun, handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = Arc::new(tun);
        let cancel = CancellationToken::new();

        let config = ReconnectConfig {
            backoff_initial_ms: 1,
            backoff_max_ms: 10,
            resource_refresh: Duration::from_secs(300),
            dead_tunnel_check: Duration::from_millis(20),
            dead_tunnel_strikes: 2,
            ..Default::default()
        };

        // Host keeps sending: outbound progress with a receiver that never
        // answers is precisely the one-way signature under test.
        let feeder = tokio::spawn(async move {
            let packet = vec![0x45u8; 60];
            loop {
                if handle.inject_packet(&packet).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        // Stop once the watchdog has forced a second connect.
        let cancel_watcher = {
            let cancel = cancel.clone();
            let count = Arc::clone(&connect_count);
            tokio::spawn(async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                loop {
                    if count.load(Ordering::Relaxed) >= 2 {
                        break;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                cancel.cancel();
            })
        };

        let result = run_with_reconnect(
            &transport,
            &crypto.as_params(),
            tun,
            &config,
            Some(&mut route_manager),
            None,
            cancel,
        )
        .await;

        cancel_watcher.await.expect("watcher");
        feeder.abort();
        assert!(result.is_ok(), "run must exit cleanly after cancel: {result:?}");

        assert!(
            connect_count.load(Ordering::Relaxed) >= 2,
            "a one-way tunnel must trigger a reconnect, connects={}",
            connect_count.load(Ordering::Relaxed)
        );
        let text = std::fs::read_to_string(&log).expect("read hook log");
        let calls: Vec<&str> = text.lines().collect();
        let first_up = calls.iter().position(|c| *c == "up").expect("hook up call");
        let down_after_up = calls[first_up + 1..].contains(&"down");
        assert!(down_after_up, "routes must come down when the tunnel black-holes: {calls:?}");
    }

    // BUG: specs/bugs/BUG-network-manager-tun-address-loss.md
    /// Read the `(action, gate)` pairs a hook log recorded, in order.
    fn gate_history(text: &str) -> Vec<(&str, &str)> {
        let mut history = Vec::new();
        let mut action = "";
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("action=") {
                action = rest;
            } else if let Some(gate) = line.strip_prefix("PRRR_DNS_GATE=") {
                history.push((action, gate));
            }
        }
        history
    }

    /// RouteManager whose hook records every action plus the DNS gate line the
    /// binary published, so a test can read the gate's whole history.
    fn dns_gate_route_manager(
        dir: &std::path::Path,
        dns_servers: Vec<String>,
        resource_ips: Vec<std::net::Ipv4Addr>,
    ) -> crate::routing::RouteManager {
        use std::os::unix::fs::PermissionsExt as _;

        let log = dir.join("hook.log");
        let hook = dir.join("hook.sh");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/bash\necho \"action=$1\" >> '{log}'\nwhile IFS= read -r line; do case \"$line\" in PRRR_DNS_GATE=*|PRRR_DNS_ADVERTISE_SERVERS=*) echo \"$line\" >> '{log}';; esac; done < \"$PRRR_ENV_FILE\"\n",
                log = log.display()
            ),
        )
        .expect("write hook");
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).expect("chmod hook");

        let params = crate::routing::RouteParams {
            tun_device: "prrr0".to_string(),
            client_ip: std::net::Ipv4Addr::new(10, 66, 66, 2),
            gateway_ip: std::net::Ipv4Addr::new(10, 66, 66, 1),
            server_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 79)),
            server_endpoint: "vpn.example".to_string(),
            all_traffic: false,
            dns_servers,
            allowed_ips: vec![],
            excluded_ips: vec![],
            resources: vec![],
            resource_ips,
            fwmark: crate::routing::DEFAULT_FWMARK,
        };
        crate::routing::RouteManager::new(params, hook.display().to_string()).with_env_file(dir.join("env"))
    }

    /// Loopback DNS responder for the gate tests. It answers every question
    /// with the `QR` bit set and stops on a `stop` datagram, so the test controls
    /// liveness without touching the system resolver.
    struct FixtureResolver {
        socket: Arc<std::net::UdpSocket>,
        addr: std::net::SocketAddr,
        done: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    }

    impl FixtureResolver {
        fn start() -> Self {
            let socket = Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").expect("bind resolver fixture"));
            let addr = socket.local_addr().expect("fixture addr");
            let reader = Arc::clone(&socket);
            let done = std::thread::spawn(move || {
                let mut buffer = [0u8; 512];
                while let Ok((read, peer)) = reader.recv_from(&mut buffer) {
                    if &buffer[..read] == b"stop" {
                        break;
                    }
                    let mut answer = buffer[..read].to_vec();
                    answer[2] |= 0x80; // set QR: this is a response
                    if reader.send_to(&answer, peer).is_err() {
                        break;
                    }
                }
            });
            Self {
                socket,
                addr,
                done: std::sync::Mutex::new(Some(done)),
            }
        }

        /// Port the fixture answers on, for the prober's `dns_probe_port`.
        fn port(&self) -> u16 {
            self.addr.port()
        }
    }

    impl Drop for FixtureResolver {
        fn drop(&mut self) {
            // A datagram to its own port wakes the reader and ends the thread.
            let _ = self.socket.send_to(b"stop", self.addr);
            if let Some(handle) = self.done.lock().expect("lock").take() {
                let _ = handle.join();
            }
        }
    }

    #[tokio::test]
    async fn dead_tunnel_resolver_closes_the_dns_gate_and_reruns_the_hook() {
        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("hook.log");
        // Bind then release a port: nothing listens there afterwards, so the
        // probe is answered with ICMP port-unreachable — a dead resolver.
        let dead_port = {
            let scratch = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind scratch");
            scratch.local_addr().expect("scratch addr").port()
        };
        let mut route_manager = dns_gate_route_manager(
            dir.path(),
            vec!["127.0.0.1".to_string()],
            vec![std::net::Ipv4Addr::new(203, 0, 113, 10)],
        );

        let connect_count = Arc::new(AtomicU32::new(0));
        let transport = FailNTransport::new(0, Arc::clone(&connect_count));
        let crypto = TestCryptoMaterial::new();
        let (tun, _handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = Arc::new(tun);
        let cancel = CancellationToken::new();

        let config = ReconnectConfig {
            backoff_initial_ms: 1,
            backoff_max_ms: 10,
            resource_refresh: Duration::from_secs(300),
            dns_check: Duration::from_millis(20),
            dns_probe_timeout: Duration::from_millis(200),
            dns_probe_port: dead_port,
            ..Default::default()
        };

        let watcher = {
            let cancel = cancel.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                loop {
                    if std::fs::read_to_string(&log).unwrap_or_default().contains("PRRR_DNS_GATE=off") {
                        break;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                cancel.cancel();
            })
        };

        let result = run_with_reconnect(
            &transport,
            &crypto.as_params(),
            tun,
            &config,
            Some(&mut route_manager),
            None,
            cancel,
        )
        .await;
        watcher.await.expect("watcher");
        assert!(result.is_ok(), "run must exit cleanly after cancel: {result:?}");

        let text = std::fs::read_to_string(&log).expect("hook log");
        let gate_history = gate_history(&text);
        assert_eq!(
            gate_history,
            vec![("up", "on"), ("up", "off"), ("down", "off")],
            "advertise at start, withdraw once the probe fails, stay withdrawn on teardown: {text}"
        );
        assert_eq!(
            connect_count.load(Ordering::Relaxed),
            1,
            "a dead resolver is a DNS problem, not a reason to drop the tunnel"
        );
    }

    /// A deployment whose *first* configured resolver never answers but whose
    /// second one does must keep DNS inside the tunnel. Probing only the first
    /// address closed the gate forever and left the host on its uncensored LAN
    /// resolver. BUG: specs/bugs/BUG-tunnel-dns-single-probe-target.md
    #[tokio::test]
    async fn dns_gate_opens_for_a_later_configured_responder_and_advertises_only_the_live_one() {
        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("hook.log");
        let resolver = FixtureResolver::start();
        // 127.0.0.2 has no listener: the probe gets ICMP port-unreachable there,
        // while 127.0.0.1 is the fixture that answers on the probe port.
        let mut route_manager = dns_gate_route_manager(
            dir.path(),
            vec!["127.0.0.2".to_string(), "127.0.0.1".to_string()],
            vec![std::net::Ipv4Addr::new(203, 0, 113, 10)],
        );

        let connect_count = Arc::new(AtomicU32::new(0));
        let transport = FailNTransport::new(0, Arc::clone(&connect_count));
        let crypto = TestCryptoMaterial::new();
        let (tun, _handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = Arc::new(tun);
        let cancel = CancellationToken::new();

        let config = ReconnectConfig {
            backoff_initial_ms: 1,
            backoff_max_ms: 10,
            resource_refresh: Duration::from_secs(300),
            dns_check: Duration::from_millis(20),
            dns_probe_timeout: Duration::from_millis(200),
            dns_probe_port: resolver.port(),
            ..Default::default()
        };

        let watcher = {
            let cancel = cancel.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                loop {
                    let text = std::fs::read_to_string(&log).unwrap_or_default();
                    if text.contains("PRRR_DNS_ADVERTISE_SERVERS=\"127.0.0.1\"") {
                        break;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                cancel.cancel();
            })
        };

        let result = run_with_reconnect(
            &transport,
            &crypto.as_params(),
            tun,
            &config,
            Some(&mut route_manager),
            None,
            cancel,
        )
        .await;
        watcher.await.expect("watcher");
        assert!(result.is_ok(), "run must exit cleanly after cancel: {result:?}");

        let text = std::fs::read_to_string(&log).expect("hook log");
        assert!(
            !text.contains("PRRR_DNS_GATE=off"),
            "a responder that answers further down the list keeps the gate open: {text}"
        );
        assert!(text.contains("PRRR_DNS_GATE=on"), "DNS stays in the tunnel: {text}");
        assert!(
            text.contains("PRRR_DNS_ADVERTISE_SERVERS=\"127.0.0.1\""),
            "the dead server is dropped from the system resolver, not advertised: {text}"
        );
    }

    #[tokio::test]
    async fn healthy_tunnel_resolver_keeps_dns_in_the_tunnel_without_hook_churn() {
        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("hook.log");
        let resolver = FixtureResolver::start();
        let mut route_manager = dns_gate_route_manager(
            dir.path(),
            vec!["127.0.0.1".to_string()],
            vec![std::net::Ipv4Addr::new(203, 0, 113, 10)],
        );

        let connect_count = Arc::new(AtomicU32::new(0));
        let transport = FailNTransport::new(0, Arc::clone(&connect_count));
        let crypto = TestCryptoMaterial::new();
        let (tun, _handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = Arc::new(tun);
        let cancel = CancellationToken::new();

        let config = ReconnectConfig {
            backoff_initial_ms: 1,
            backoff_max_ms: 10,
            resource_refresh: Duration::from_secs(300),
            dns_check: Duration::from_millis(20),
            dns_probe_timeout: Duration::from_millis(200),
            dns_probe_port: resolver.port(),
            ..Default::default()
        };

        // Several probe rounds must pass with the gate untouched.
        let watcher = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(400)).await;
                cancel.cancel();
            })
        };

        let result = run_with_reconnect(
            &transport,
            &crypto.as_params(),
            tun,
            &config,
            Some(&mut route_manager),
            None,
            cancel,
        )
        .await;
        watcher.await.expect("watcher");
        assert!(result.is_ok(), "run must exit cleanly after cancel: {result:?}");

        let text = std::fs::read_to_string(&log).expect("hook log");
        assert!(text.contains("PRRR_DNS_GATE=on"), "DNS stays in the tunnel: {text}");
        assert!(
            !text.contains("PRRR_DNS_GATE=off"),
            "a live resolver must not close the gate: {text}"
        );
        assert_eq!(
            text.matches("action=up").count(),
            1,
            "healthy probes must never re-run the hook: {text}"
        );
    }

    #[tokio::test]
    async fn split_tunnel_without_resources_probes_no_dns_and_never_closes_the_gate() {
        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("hook.log");
        // No resource IPs and no full tunnel: nothing reaches the tunnel, so the
        // hook never touches the resolver and there is nothing to probe.
        let mut route_manager = dns_gate_route_manager(dir.path(), vec!["127.0.0.1".to_string()], vec![]);

        let transport = FailNTransport::new(0, Arc::new(AtomicU32::new(0)));
        let crypto = TestCryptoMaterial::new();
        let (tun, _handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = Arc::new(tun);
        let cancel = CancellationToken::new();

        let config = ReconnectConfig {
            backoff_initial_ms: 1,
            backoff_max_ms: 10,
            resource_refresh: Duration::from_secs(300),
            dns_check: Duration::from_millis(20),
            dns_probe_timeout: Duration::from_millis(200),
            dns_probe_port: 1,
            ..Default::default()
        };

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_with_reconnect(
                &transport,
                &crypto.as_params(),
                tun,
                &config,
                Some(&mut route_manager),
                None,
                cancel.clone(),
            ),
        )
        .await;
        assert!(result.is_err(), "the pipeline must still be running (nothing probed it out of it)");
        cancel.cancel();
        result.unwrap_err();

        let text = std::fs::read_to_string(&log).expect("hook log");
        assert_eq!(text.matches("action=up").count(), 1, "bare split mode runs one hook: {text}");
        assert!(!text.contains("PRRR_DNS_GATE=off"), "nothing to probe, so nothing to close: {text}");
    }

    // -- AC: a DNS verdict nobody refreshes cannot outlive its lease ---------
    // BUG: specs/bugs/BUG-pipeline-refresh-starves-packet-pump.md

    #[test]
    fn a_fresh_dns_verdict_is_within_its_lease() {
        let now = tokio::time::Instant::now();
        let mut lease = DnsVerdictLease::new(Duration::from_millis(50), now);

        assert!(!lease.expire_if_stale(now), "a verdict seen this instant must not be judged stale");
    }

    #[test]
    fn a_dns_verdict_past_its_lease_withdraws_once_and_not_again() {
        let now = tokio::time::Instant::now();
        let mut lease = DnsVerdictLease::new(Duration::from_millis(50), now);
        let past_lease = now + Duration::from_millis(51);

        assert!(
            lease.expire_if_stale(past_lease),
            "a verdict older than the lease means nobody is probing: withdraw"
        );
        assert!(
            !lease.expire_if_stale(past_lease),
            "one stale verdict must not re-run the hook on every watchdog tick"
        );
    }

    #[test]
    fn a_new_dns_verdict_restarts_the_lease() {
        let now = tokio::time::Instant::now();
        let mut lease = DnsVerdictLease::new(Duration::from_millis(50), now);
        lease.note_verdict(now + Duration::from_millis(40));

        assert!(
            !lease.expire_if_stale(now + Duration::from_millis(80)),
            "the lease runs from the newest verdict, not the first one"
        );
        assert!(
            lease.expire_if_stale(now + Duration::from_millis(91)),
            "and it does expire 50 ms after that newest verdict"
        );
    }
}
