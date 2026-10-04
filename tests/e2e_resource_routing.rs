// FRD: specs/frds/FRD-resource-routing.md

//! Black-box tests for the client resource-routing CLI path.

use std::{fs, process::Command};

#[test]
fn client_route_commands_update_a_real_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("client.toml");
    fs::write(&config, "# preserved comment\n[server]\nendpoint = \"vpn.example:443\"\n").expect("write config");

    let add = Command::new(env!("CARGO_BIN_EXE_prrr"))
        .args(["client", "--config"])
        .arg(&config)
        .args(["route", "add", "chatgpt.com"])
        .output()
        .expect("run route add");
    assert!(add.status.success(), "route add failed: {}", String::from_utf8_lossy(&add.stderr));

    let list = Command::new(env!("CARGO_BIN_EXE_prrr"))
        .args(["client", "--config"])
        .arg(&config)
        .args(["route", "list"])
        .output()
        .expect("run route list");
    assert!(
        list.status.success(),
        "route list failed: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&list.stdout).trim(), "chatgpt.com");

    let remove = Command::new(env!("CARGO_BIN_EXE_prrr"))
        .args(["client", "--config"])
        .arg(&config)
        .args(["route", "remove", "chatgpt.com"])
        .output()
        .expect("run route remove");
    assert!(
        remove.status.success(),
        "route remove failed: {}",
        String::from_utf8_lossy(&remove.stderr)
    );

    let final_config = fs::read_to_string(&config).expect("read config");
    assert!(final_config.contains("# preserved comment"));
    assert!(!final_config.contains("chatgpt.com"));
}

// ---------------------------------------------------------------------------
// Real route-hook execution tests (BUG-resource-routing-service-not-updated).
//
// The previous "lifecycle test" only grep'ed the hook source and never ran it,
// so a shell bug (space-separated PRRR_RESOURCE_IPS consumed via `read <<<`,
// which yields a single malformed line) shipped green. These tests execute
// deploy/client/prrr-route against stub `ip`/`resolvectl` binaries and assert
// the exact commands issued.
// ---------------------------------------------------------------------------

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

const HOOK_SCRIPT: &str = "deploy/client/prrr-route";
const RESOURCE_IPS: [&str; 3] = ["203.0.113.10", "203.0.113.11", "203.0.113.12"];
const FWMARK: &str = "51820";

struct HookSandbox {
    dir: tempfile::TempDir,
    env_file: PathBuf,
    log: PathBuf,
    /// stdout the stub `ip` returns for `ip -4 addr show` — lets a test model
    /// the kernel having (or having lost) the tunnel address.
    /// BUG: specs/bugs/BUG-network-manager-tun-address-loss.md
    addr_fixture: PathBuf,
}

impl HookSandbox {
    /// Write a hook env file and stub `ip`/`resolvectl` that record argv.
    fn new(all_traffic: bool, resource_ips: &[&str]) -> Self {
        Self::new_with_stale(all_traffic, resource_ips, &[])
    }

    /// As [`Self::new`], additionally priming `PRRR_STALE_RESOURCE_IPS` —
    /// resource IPs that left the retention window and must be removed on `up`.
    /// FRD: specs/frds/FRD-resource-routing.md; BUG: specs/bugs/BUG-resource-ip-staleness.md
    fn new_with_stale(all_traffic: bool, resource_ips: &[&str], stale_resource_ips: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let stub_bin = dir.path().join("bin");
        fs::create_dir(&stub_bin).expect("stub bin dir");

        let log = dir.path().join("calls.log");
        let addr_fixture = dir.path().join("addr.txt");
        fs::write(&addr_fixture, "").expect("write addr fixture");
        for tool in ["ip", "resolvectl", "nmcli"] {
            let body = if tool == "ip" {
                // `ip -4 addr show …` must echo the fixture so both the
                // "address present" and "address flushed" hook paths run.
                format!(
                    "#!/bin/bash\necho \"ip $*\" >> '{}'\nif [[ \"$1 $2\" == \"-4 addr\" ]]; then cat '{}' 2>/dev/null; fi\nexit 0\n",
                    log.display(),
                    addr_fixture.display()
                )
            } else {
                format!("#!/bin/bash\necho \"{tool} $*\" >> '{}'\nexit 0\n", log.display())
            };
            let stub = stub_bin.join(tool);
            fs::write(&stub, body).expect("write stub");
            fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).expect("chmod stub");
        }

        let env_file = dir.path().join("env");
        fs::write(
            &env_file,
            format!(
                "PRRR_DEVICE=prrr0\n\
                 PRRR_CLIENT_IP=10.66.66.2\n\
                 PRRR_GATEWAY_IP=10.66.66.1\n\
                 PRRR_SERVER_IP=203.0.113.79\n\
                 PRRR_SERVER_ENDPOINT=vpn.example\n\
                 PRRR_ALL_TRAFFIC={all_traffic}\n\
                 PRRR_DNS_SERVERS=\"1.1.1.1\"\n\
                 PRRR_ALLOWED_IPS=\"\"\n\
                 PRRR_EXCLUDED_IPS=\"\"\n\
                 PRRR_RESOURCE_IPS=\"{}\"\n\
                 PRRR_STALE_RESOURCE_IPS=\"{}\"\n\
                 PRRR_DNS_GATE=on\n\
                 PRRR_FWMARK={FWMARK}\n",
                resource_ips.join(" "),
                stale_resource_ips.join(" ")
            ),
        )
        .expect("write env");

        // Record the stub dir path for run().
        fs::write(dir.path().join("stub_bin"), stub_bin.display().to_string()).expect("record stub dir");
        Self {
            dir,
            env_file,
            log,
            addr_fixture,
        }
    }

    fn run(&self, action: &str) -> std::process::Output {
        let stub_bin = fs::read_to_string(self.dir.path().join("stub_bin")).expect("stub dir");
        let output = Command::new("/bin/bash")
            .arg(HOOK_SCRIPT)
            .arg(action)
            .env("PATH", format!("{stub_bin}:/usr/bin:/bin"))
            .env("PRRR_ENV_FILE", &self.env_file)
            .output()
            .expect("run hook");
        assert!(
            output.status.success(),
            "hook {action} failed: {}\n{}",
            String::from_utf8_lossy(&output.stderr),
            fs::read_to_string(&self.log).unwrap_or_default()
        );
        output
    }

    /// Replace the configured DNS servers in the env fixture.
    /// BUG: specs/bugs/BUG-tunnel-dns-single-probe-target.md
    fn set_dns_servers(&self, servers: &[&str]) {
        let raw = fs::read_to_string(&self.env_file).expect("env");
        let replaced = raw.replace(
            "PRRR_DNS_SERVERS=\"1.1.1.1\"",
            &format!("PRRR_DNS_SERVERS=\"{}\"", servers.join(" ")),
        );
        assert!(replaced != raw, "the fixture's DNS line was not found");
        fs::write(&self.env_file, replaced).expect("rewrite servers");
    }

    /// Publish the binary's verdict about which responders actually answered.
    fn set_dns_advertise(&self, servers: &[&str]) {
        let raw = fs::read_to_string(&self.env_file).expect("env");
        let with_advertise = format!("{raw}PRRR_DNS_ADVERTISE_SERVERS=\"{}\"\n", servers.join(" "));
        fs::write(&self.env_file, with_advertise).expect("add advertise line");
    }

    /// Move the binary's DNS gate to another state in the env fixture.
    fn set_dns_gate(&self, gate: &str) {
        let raw = fs::read_to_string(&self.env_file).expect("env");
        fs::write(&self.env_file, raw.replace("PRRR_DNS_GATE=on", &format!("PRRR_DNS_GATE={gate}"))).expect("rewrite gate");
    }

    /// Emulate an older binary that does not publish the gate at all.
    fn drop_dns_gate(&self) {
        let raw = fs::read_to_string(&self.env_file).expect("env");
        fs::write(
            &self.env_file,
            raw.lines()
                .filter(|line| !line.starts_with("PRRR_DNS_GATE="))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
        .expect("strip gate");
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

fn assert_contains(calls: &[String], needle: &str, context: &str) {
    assert!(
        calls.iter().any(|call| call == needle),
        "missing call {needle:?} in {context}; calls:\n{}",
        calls.join("\n")
    );
}

fn hook_calls_path(hook: &Path) -> String {
    hook.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

#[test]
fn route_hook_installs_one_route_per_resource_ip_in_split_mode() {
    let sandbox = HookSandbox::new(false, &RESOURCE_IPS);
    sandbox.run("up");
    let calls = sandbox.calls();

    for ip in RESOURCE_IPS {
        assert_contains(
            &calls,
            &format!("ip -4 route replace {ip}/32 dev prrr0 table {FWMARK}"),
            "up: one /32 replace per resource",
        );
    }
    // The historical bug: all IPs consumed as a single word.
    assert!(
        !calls.iter().any(|call| call.contains("203.0.113.10 203.0.113.11")),
        "resource IPs collapsed into one route: {}",
        calls.join("\n")
    );
    // Split + resources must still install the policy rules, or the table is inert.
    assert_contains(
        &calls,
        &format!("ip -4 rule add not fwmark {FWMARK} table {FWMARK} priority 32765"),
        "up: fwmark rule",
    );
    assert_contains(
        &calls,
        "ip -4 rule add table main suppress_prefixlength 0 priority 32764",
        "up: suppress rule",
    );
    // Split mode must not capture the default route.
    assert!(
        !calls.iter().any(|call| call.starts_with("ip -4 route add default")),
        "split mode captured the default route: {}",
        calls.join("\n")
    );
    // Routes into a DOWN device are inert; the hook must ensure the link is up.
    assert_contains(&calls, "ip link set prrr0 up", "up: link bring-up");
}

#[test]
fn route_hook_removes_every_resource_route_on_down() {
    let sandbox = HookSandbox::new(false, &RESOURCE_IPS);
    sandbox.run("up");
    let calls = sandbox.calls();
    for ip in RESOURCE_IPS {
        assert_contains(
            &calls,
            &format!("ip -4 route replace {ip}/32 dev prrr0 table {FWMARK}"),
            "up before down",
        );
    }

    sandbox.run("down");
    let calls = sandbox.calls();
    for ip in RESOURCE_IPS {
        assert_contains(
            &calls,
            &format!("ip -4 route del {ip}/32 dev prrr0 table {FWMARK}"),
            "down: symmetric removal",
        );
    }
    assert_contains(
        &calls,
        &format!("ip -4 rule del not fwmark {FWMARK} table {FWMARK}"),
        "down: fwmark rule",
    );
    assert_contains(&calls, "ip -4 rule del table main suppress_prefixlength 0", "down: suppress rule");
}

#[test]
fn route_hook_full_tunnel_installs_default_route_and_rules() {
    let sandbox = HookSandbox::new(true, &[]);
    sandbox.run("up");
    let calls = sandbox.calls();
    assert_contains(&calls, "ip -4 route add default dev prrr0 table 51820", "full: default route");
    assert_contains(
        &calls,
        &format!("ip -4 rule add not fwmark {FWMARK} table {FWMARK} priority 32765"),
        "full: fwmark rule",
    );
    assert_contains(
        &calls,
        "ip -4 rule add table main suppress_prefixlength 0 priority 32764",
        "full: suppress rule",
    );
}

#[test]
fn route_hook_split_mode_without_resources_installs_no_routes_or_rules() {
    let sandbox = HookSandbox::new(false, &[]);
    sandbox.run("up");
    let calls = sandbox.calls();
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("ip -4 route") || call.starts_with("ip -4 rule")),
        "bare split mode touched routing: {}",
        calls.join("\n")
    );
}

#[test]
fn route_hook_is_executable_shell_not_text_only() {
    let hook = Path::new(HOOK_SCRIPT);
    assert!(hook.is_file(), "hook {HOOK_SCRIPT} missing");
    assert!(!hook_calls_path(hook).is_empty());
    let mode = fs::metadata(hook).expect("hook metadata").permissions().mode();
    assert!(mode & 0o111 != 0, "hook must be executable");
}

#[test]
fn route_hook_removes_stale_resource_routes_before_installing_current() {
    let stale = ["203.0.113.9"];
    let sandbox = HookSandbox::new_with_stale(false, &RESOURCE_IPS, &stale);
    sandbox.run("up");
    let calls = sandbox.calls();

    assert_contains(
        &calls,
        &format!("ip -4 route del {}/32 dev prrr0 table {FWMARK}", stale[0]),
        "up: stale /32 removed",
    );
    for ip in RESOURCE_IPS {
        assert_contains(
            &calls,
            &format!("ip -4 route replace {ip}/32 dev prrr0 table {FWMARK}"),
            "up: current set installed",
        );
    }
    let del_at = calls
        .iter()
        .position(|c| c.contains("route del 203.0.113.9/32"))
        .expect("stale del call present");
    let first_replace = calls
        .iter()
        .position(|c| c.contains("route replace 203.0.113.10/32"))
        .expect("replace call present");
    assert!(del_at < first_replace, "stale must be removed before fresh install: {calls:?}");

    // Stale IPs must NOT be re-installed as resource routes.
    assert!(
        !calls.iter().any(|c| c.contains("route replace 203.0.113.9/32")),
        "stale IP was installed: {calls:?}"
    );
}

#[test]
fn route_hook_up_without_stale_env_is_backwards_compatible() {
    // An older binary does not emit PRRR_STALE_RESOURCE_IPS; the hook must
    // behave exactly as before (no stale removals attempted).
    let sandbox = HookSandbox::new(false, &RESOURCE_IPS);
    let raw = fs::read_to_string(&sandbox.env_file).expect("env");
    fs::write(
        &sandbox.env_file,
        raw.lines()
            .filter(|line| !line.starts_with("PRRR_STALE_RESOURCE_IPS="))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
    .expect("strip stale var");
    sandbox.run("up");
    let calls = sandbox.calls();
    assert!(
        !calls.iter().any(|c| c.contains("203.0.113.9")),
        "hook invented stale removals from nothing: {calls:?}"
    );
    for ip in RESOURCE_IPS {
        assert_contains(
            &calls,
            &format!("ip -4 route replace {ip}/32 dev prrr0 table {FWMARK}"),
            "up without stale var still installs current set",
        );
    }
}

// ---------------------------------------------------------------------------
// DNS path pinning (BUG-resource-ip-staleness): the hook advertises tunnel
// DNS via resolvectl but must also make the DNS servers REACHABLE through the
// tunnel, otherwise answers come from the host's egress and the rotating
// resource answers never match the pinned /32 routes.
// ---------------------------------------------------------------------------

#[test]
fn route_hook_pins_configured_dns_servers_through_the_tunnel() {
    let sandbox = HookSandbox::new(false, &RESOURCE_IPS);
    sandbox.run("up");
    let calls = sandbox.calls();
    assert_contains(
        &calls,
        &format!("ip -4 route replace 1.1.1.1/32 dev prrr0 table {FWMARK}"),
        "up: DNS server pinned via tunnel table",
    );

    sandbox.run("down");
    let calls = sandbox.calls();
    assert_contains(
        &calls,
        &format!("ip -4 route del 1.1.1.1/32 dev prrr0 table {FWMARK}"),
        "down: DNS pin removed",
    );
}

#[test]
fn route_hook_without_dns_servers_pins_nothing() {
    let sandbox = HookSandbox::new(false, &RESOURCE_IPS);
    // Empty the DNS_SERVERS list in the env fixture.
    let raw = fs::read_to_string(&sandbox.env_file).expect("env");
    fs::write(
        &sandbox.env_file,
        raw.replace("PRRR_DNS_SERVERS=\"1.1.1.1\"", "PRRR_DNS_SERVERS=\"\""),
    )
    .expect("rewrite env");
    sandbox.run("up");
    let calls = sandbox.calls();
    assert!(
        !calls.iter().any(|c| c.contains("1.1.1.1")),
        "no DNS servers configured, nothing may be pinned: {calls:?}"
    );
}

// ---------------------------------------------------------------------------
// Tunnel address ownership (BUG-network-manager-tun-address-loss).
//
// NetworkManager can flush the TUN address while the client holds the fd. The
// kernel then sources injected packets from a LAN address, the server stops
// masquerading them, and the tunnel becomes a silent one-way black hole. The
// hook must reclaim the address on every up and keep NM off the device.
// ---------------------------------------------------------------------------

const TUNNEL_IP: &str = "10.66.66.2";

#[test]
fn route_hook_reasserts_tunnel_address_when_kernel_lost_it() {
    let sandbox = HookSandbox::new(false, &RESOURCE_IPS);
    sandbox.run("up");
    let calls = sandbox.calls();

    assert_contains(
        &calls,
        &format!("ip -4 addr add {TUNNEL_IP}/32 dev prrr0"),
        "up: address flushed by NM must be re-asserted",
    );
}

#[test]
fn route_hook_leaves_a_present_tunnel_address_alone() {
    let sandbox = HookSandbox::new(false, &RESOURCE_IPS);
    fs::write(
        &sandbox.addr_fixture,
        "13: prrr0: <POINTOPOINT,NOARP,UP> mtu 1100\n    inet 10.66.66.2/32 scope global prrr0\n       valid_lft forever preferred_lft forever\n",
    )
    .expect("write addr fixture");
    sandbox.run("up");
    let calls = sandbox.calls();

    assert!(
        !calls.iter().any(|c| c.contains("addr add")),
        "address already present, the hook must not touch it: {calls:?}"
    );
}

#[test]
fn route_hook_takes_the_device_away_from_network_manager() {
    let sandbox = HookSandbox::new(false, &RESOURCE_IPS);
    sandbox.run("up");
    let calls = sandbox.calls();

    assert_contains(
        &calls,
        "nmcli device set prrr0 managed no",
        "up: NM must not manage the tunnel device",
    );
}

#[test]
fn route_hook_down_does_not_reassert_address_or_unmanage_device() {
    let sandbox = HookSandbox::new(false, &RESOURCE_IPS);
    sandbox.run("down");
    let calls = sandbox.calls();

    assert!(
        !calls.iter().any(|c| c.contains("addr add") || c.contains("managed no")),
        "teardown must not configure addressing or NM: {calls:?}"
    );
}

// ---------------------------------------------------------------------------
// DNS gate (BUG-network-manager-tun-address-loss).
//
// The tunnel's resolvers are handed to the system resolver only while the
// binary's probe proves they answer. A closed gate withholds the advertisement
// — it must NOT drop the /32 pins, because those pins define the path the probe
// measures: without them the probe would answer from the host's own egress and
// the gate would oscillate forever.
// ---------------------------------------------------------------------------

#[test]
fn route_hook_gate_open_hands_the_tunnel_resolvers_to_the_system() {
    let sandbox = HookSandbox::new(false, &RESOURCE_IPS);
    sandbox.run("up");
    let calls = sandbox.calls();

    assert_contains(&calls, "resolvectl dns prrr0 1.1.1.1", "gate open: advertise tunnel resolver");
    assert_contains(&calls, "resolvectl domain prrr0 ~.", "gate open: route all names through it");
    assert!(
        !calls.iter().any(|c| c.starts_with("resolvectl revert")),
        "gate open must not revert the link it just configured: {calls:?}"
    );
}

#[test]
fn route_hook_gate_closed_withholds_advertisement_but_keeps_the_path() {
    let sandbox = HookSandbox::new(false, &RESOURCE_IPS);
    sandbox.set_dns_gate("off");
    sandbox.run("up");
    let calls = sandbox.calls();

    assert_contains(&calls, "resolvectl revert prrr0", "gate closed: host resolver back in charge");
    assert!(
        !calls.iter().any(|c| c.starts_with("resolvectl dns")),
        "a dead tunnel resolver must never be advertised: {calls:?}"
    );
    assert!(
        !calls.iter().any(|c| c.starts_with("resolvectl domain")),
        "a dead tunnel resolver must never capture name routing: {calls:?}"
    );
    // The pins stay: they are what the probe measures through the tunnel.
    assert_contains(
        &calls,
        &format!("ip -4 route replace 1.1.1.1/32 dev prrr0 table {FWMARK}"),
        "gate closed: pin kept so the probe still measures the tunnel",
    );
    assert!(
        !calls.iter().any(|c| c.contains("route del 1.1.1.1/32")),
        "the closed gate must not withdraw the pin: {calls:?}"
    );
    // Everything except DNS still flows: resource routes must be installed.
    for ip in RESOURCE_IPS {
        assert_contains(
            &calls,
            &format!("ip -4 route replace {ip}/32 dev prrr0 table {FWMARK}"),
            "gate closed: resource routing unaffected",
        );
    }
}

#[test]
fn route_hook_without_gate_variable_advertises_like_older_binaries() {
    let sandbox = HookSandbox::new(false, &RESOURCE_IPS);
    sandbox.drop_dns_gate();
    sandbox.run("up");
    let calls = sandbox.calls();

    assert_contains(&calls, "resolvectl dns prrr0 1.1.1.1", "absent gate defaults to open");
    assert_contains(
        &calls,
        &format!("ip -4 route replace 1.1.1.1/32 dev prrr0 table {FWMARK}"),
        "absent gate still pins",
    );
}

#[test]
fn route_hook_advertises_only_the_dns_responders_that_answered() {
    // BUG: specs/bugs/BUG-tunnel-dns-single-probe-target.md
    let sandbox = HookSandbox::new(true, &[]);
    sandbox.set_dns_servers(&["1.1.1.1", "8.8.8.8"]);
    sandbox.set_dns_advertise(&["8.8.8.8"]);
    sandbox.run("up");
    let calls = sandbox.calls();

    assert_contains(
        &calls,
        "resolvectl dns prrr0 8.8.8.8",
        "up: the system resolver gets only the responder that answered",
    );
    assert!(
        !calls
            .iter()
            .any(|call| call.contains("1.1.1.1") && call.starts_with("resolvectl dns")),
        "a responder the probe found dead must not be handed to the resolver: {}",
        calls.join("\n")
    );
    // Both /32 pins remain: they define the path the probe measures.
    assert_contains(
        &calls,
        "ip -4 route replace 1.1.1.1/32 dev prrr0 table 51820",
        "up: unresponsive server stays pinned",
    );
    assert_contains(
        &calls,
        "ip -4 route replace 8.8.8.8/32 dev prrr0 table 51820",
        "up: responsive server pinned",
    );
}

#[test]
fn route_hook_down_withdraws_the_resolver_and_the_pins_together() {
    let sandbox = HookSandbox::new(false, &RESOURCE_IPS);
    sandbox.set_dns_gate("off");
    sandbox.run("up");
    sandbox.run("down");
    let calls = sandbox.calls();

    assert_contains(&calls, "resolvectl revert prrr0", "down: resolver reverted");
    assert_contains(
        &calls,
        &format!("ip -4 route del 1.1.1.1/32 dev prrr0 table {FWMARK}"),
        "down: pin removed even though the gate had closed",
    );
}
