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
}

impl HookSandbox {
    /// Write a hook env file and stub `ip`/`resolvectl` that record argv.
    fn new(all_traffic: bool, resource_ips: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let stub_bin = dir.path().join("bin");
        fs::create_dir(&stub_bin).expect("stub bin dir");

        let log = dir.path().join("calls.log");
        for tool in ["ip", "resolvectl"] {
            let stub = stub_bin.join(tool);
            fs::write(&stub, format!("#!/bin/bash\necho \"{tool} $*\" >> '{}' \nexit 0\n", log.display())).expect("write stub");
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
                 PRRR_FWMARK={FWMARK}\n",
                resource_ips.join(" ")
            ),
        )
        .expect("write env");

        // Record the stub dir path for run().
        fs::write(dir.path().join("stub_bin"), stub_bin.display().to_string()).expect("record stub dir");
        Self { dir, env_file, log }
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
