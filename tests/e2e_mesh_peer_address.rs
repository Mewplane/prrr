// FRD: specs/frds/FRD-005-publish-mesh-peer-address.md
//
//! End-to-end coverage for Step 5: publishing the authorized peer's reachable
//! mesh address into the ecosystem registry (`flags.mesh_peer_addr`) so a
//! sibling (cathouse) reaches the laptop at that address when the LAN path is
//! absent — and clearing it when sharing drops.
//!
//! The full path under test is the real one a sibling would use:
//!   sharing state -> resolve_mesh_addr (probe before publish) ->
//!   build_descriptor -> EcosystemRegistrar publish to disk ->
//!   sibling reads the on-disk descriptor -> connects to the published address.
//!
//! Simulation boundary: a true off-LAN topology needs two hosts / CAP_NET_ADMIN.
//! We simulate "LAN path absent" by binding a loopback `TcpListener`, publishing
//! its `127.0.0.1:<port>` as the mesh address, then having the "sibling" read the
//! published address from the descriptor and connect to *that* address (never a
//! hard-coded one). Only network locality is simulated; the publish->read->connect
//! seam is exercised for real.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use prrr::{
    ecosystem::{DescriptorState, EcosystemRegistrar, FileRegistryTransport, TransportKind, build_descriptor},
    sharing::{MeshProbe, SharingState, TcpMeshProbe, resolve_mesh_addr},
};

const TEST_PORT: u16 = 443;
const TEST_IFACE: &str = "prrr0";
const E2E_PAYLOAD: &[u8] = b"prrr-mesh-roundtrip";

/// Build the connected/down descriptors for a sharing state, resolving the mesh
/// address with the supplied probe (probe before publish).
fn descriptors_for(
    pubkey: &[u8],
    state: &SharingState,
    probe: &impl MeshProbe,
) -> (prrr::ecosystem::Descriptor, prrr::ecosystem::Descriptor) {
    let mesh_addr = resolve_mesh_addr(state.enabled, state.peer_mesh_addr.as_deref(), probe);
    let make = |mesh: Option<String>| DescriptorState {
        pubkey,
        transport: TransportKind::Masque,
        port: TEST_PORT,
        iface: TEST_IFACE,
        server_endpoint: Some("vpn.example.com:443"),
        full_tunnel: false,
        excluded_cidrs: Vec::new(),
        client_to_client: state.enabled,
        mesh_peer_addr: mesh,
    };
    (build_descriptor(make(mesh_addr)), build_descriptor(make(None)))
}

/// Read `flags.mesh_peer_addr` from the on-disk descriptor (the sibling's view).
fn read_published_mesh_addr(transport: &FileRegistryTransport) -> Option<String> {
    let path = transport.descriptor_path()?;
    let contents = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&contents).ok()?;
    v["flags"]["mesh_peer_addr"].as_str().map(str::to_string)
}

/// Spawn a loopback echo listener that serves connections until `stop` is set.
///
/// Multi-accept: each probe (a bare TCP connect) and the sibling's data
/// round-trip is a separate connection, so the listener must keep accepting.
/// Returns its `host:port`, the stop flag, and the join handle.
fn spawn_echo_listener() -> (String, std::sync::Arc<std::sync::atomic::AtomicBool>, std::thread::JoinHandle<()>) {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("addr").to_string();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        while !stop_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; E2E_PAYLOAD.len()];
                    // Echo only when a full payload arrives (bare probes send nothing).
                    if stream.read_exact(&mut buf).is_ok() {
                        let _ = stream.write_all(&buf);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (addr, stop, handle)
}

#[test]
fn off_lan_connect_via_published_address_succeeds_end_to_end() {
    // A laptop bound to a loopback listener stands in for the off-LAN peer
    // reachable only via the published mesh address.
    let (mesh_addr, stop, server) = spawn_echo_listener();

    // Sharing established to that address; probe (real TCP connect) confirms it.
    let state = SharingState::default().establish(&mesh_addr);
    let probe = TcpMeshProbe::default();
    assert!(probe.probe(&mesh_addr), "listener is reachable");

    // Publish prrr's descriptor to the registry (file fallback under a temp dir).
    let base = tempfile::TempDir::new().expect("temp dir");
    let transport = FileRegistryTransport::with_base(base.path().to_path_buf());
    let pubkey = [0x21u8; 32];
    let (connected, down) = descriptors_for(&pubkey, &state, &probe);
    let registrar = EcosystemRegistrar::new(Box::new(transport), connected, down);
    registrar.on_up();

    // The sibling reads the registry — with the LAN path absent it has only the
    // published address — and connects to exactly that address.
    let reader = FileRegistryTransport::with_base(base.path().to_path_buf());
    let published = read_published_mesh_addr(&reader).expect("mesh_peer_addr published");
    assert_eq!(published, mesh_addr, "sibling reads the published address");

    let mut conn = TcpStream::connect(&published).expect("sibling connects via published addr");
    conn.write_all(E2E_PAYLOAD).expect("send");
    let mut echoed = [0u8; E2E_PAYLOAD.len()];
    conn.read_exact(&mut echoed).expect("receive echo");
    assert_eq!(&echoed, E2E_PAYLOAD, "off-LAN round-trip via published address");

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    server.join().expect("listener thread");
}

#[test]
fn mesh_peer_addr_clears_on_disable() {
    let (mesh_addr, stop, server) = spawn_echo_listener();
    let probe = TcpMeshProbe::default();
    let base = tempfile::TempDir::new().expect("temp dir");
    let transport = FileRegistryTransport::with_base(base.path().to_path_buf());
    let pubkey = [0x22u8; 32];

    // Established: address appears.
    let established = SharingState::default().establish(&mesh_addr);
    let (connected, down) = descriptors_for(&pubkey, &established, &probe);
    let registrar = EcosystemRegistrar::new(Box::new(transport), connected, down);
    registrar.on_up();
    let reader = FileRegistryTransport::with_base(base.path().to_path_buf());
    assert_eq!(read_published_mesh_addr(&reader).as_deref(), Some(mesh_addr.as_str()));

    // Disable: re-resolve from the disabled state and republish — address clears.
    let disabled = established.disable();
    let (connected2, down2) = descriptors_for(&pubkey, &disabled, &probe);
    let registrar2 = EcosystemRegistrar::new(
        Box::new(FileRegistryTransport::with_base(base.path().to_path_buf())),
        connected2,
        down2,
    );
    registrar2.on_up();
    assert_eq!(read_published_mesh_addr(&reader), None, "disable clears mesh_peer_addr");

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    server.join().expect("listener thread");
}

#[test]
fn probe_failure_keeps_mesh_peer_addr_null() {
    // Sharing is enabled with a candidate address, but the probe fails: the
    // address must NOT be published (probe before publish, fail-closed).
    struct FailingProbe;
    impl MeshProbe for FailingProbe {
        fn probe(&self, _addr: &str) -> bool {
            false
        }
    }

    let base = tempfile::TempDir::new().expect("temp dir");
    let transport = FileRegistryTransport::with_base(base.path().to_path_buf());
    let pubkey = [0x23u8; 32];
    let state = SharingState::default().establish("100.64.0.9:51820");
    let (connected, down) = descriptors_for(&pubkey, &state, &FailingProbe);
    let registrar = EcosystemRegistrar::new(Box::new(transport), connected, down);
    registrar.on_up();

    let reader = FileRegistryTransport::with_base(base.path().to_path_buf());
    assert_eq!(
        read_published_mesh_addr(&reader),
        None,
        "probe failed => mesh_peer_addr stays null even though sharing is enabled"
    );
}
