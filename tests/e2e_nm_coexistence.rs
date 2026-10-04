// BUG: specs/bugs/BUG-network-manager-tun-address-loss.md

//! Black-box tests for NetworkManager coexistence: the drop-in that keeps NM
//! off prrr's TUN devices, and the installer wiring that installs it.
//!
//! NM adopting a prrr TUN and later flushing its address is the failure that
//! turned a running tunnel into a silent one-way black hole. These tests run
//! the real script against a temporary conf.d so the emitted keyfile is
//! verified byte-for-byte instead of grepped out of a script.

use std::{fs, path::Path, process::Command};

const NM_UNMANAGED_SCRIPT: &str = "deploy/client/nm-unmanaged.sh";
const INSTALLER_SCRIPT: &str = "deploy/client/install-client.sh";
const CONF_NAME: &str = "99-prrr-unmanaged.conf";
const DIRECTIVE: &str = "unmanaged-devices+=interface-name:prrr*";

/// Run `nm-unmanaged.sh` writing into `conf_dir`; return its stdout path.
fn run_writer(conf_dir: &Path) -> String {
    let output = Command::new("/bin/bash")
        .arg(NM_UNMANAGED_SCRIPT)
        .env("PRRR_NM_CONF_DIR", conf_dir)
        .output()
        .expect("run nm-unmanaged.sh");
    assert!(
        output.status.success(),
        "nm-unmanaged.sh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn writer_emits_a_prrr_scoped_keyfile_drop_in() {
    let dir = tempfile::tempdir().expect("tempdir");
    let reported = run_writer(dir.path());

    let expected = dir.path().join(CONF_NAME);
    assert_eq!(Path::new(&reported), expected, "script must report the file it wrote");

    let text = fs::read_to_string(&expected).expect("read drop-in");
    assert!(text.contains("[keyfile]"), "must be a keyfile snippet: {text}");
    assert!(text.contains(DIRECTIVE), "must exclude prrr devices: {text}");
    assert!(
        !text.contains("interface-name:*"),
        "a global wildcard would also unmanage unrelated tunnels (e.g. tun0): {text}"
    );
}

#[test]
fn writer_is_idempotent_and_leaves_other_d_drop_ins_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let neighbour = dir.path().join("10-something-else.conf");
    fs::write(&neighbour, "[main]\nno-auto-default=*\n").expect("write neighbour conf");

    run_writer(dir.path());
    let first = fs::read_to_string(dir.path().join(CONF_NAME)).expect("read first");
    run_writer(dir.path());
    let second = fs::read_to_string(dir.path().join(CONF_NAME)).expect("read second");

    assert_eq!(first, second, "re-running must not grow or churn the file");
    assert_eq!(
        fs::read_to_string(&neighbour).expect("re-read neighbour"),
        "[main]\nno-auto-default=*\n",
        "the installer must not disturb unrelated NetworkManager config"
    );
    let ours: Vec<_> = fs::read_dir(dir.path())
        .expect("read dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains("prrr"))
        .collect();
    assert_eq!(ours.len(), 1, "exactly one prrr drop-in expected");
}

#[test]
fn writer_creates_a_missing_conf_d_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let nested = dir.path().join("deep/NetworkManager/conf.d");

    run_writer(&nested);

    assert!(nested.join(CONF_NAME).is_file(), "must create the conf.d path");
}

#[test]
fn installer_wires_the_writer_into_client_setup() {
    let text = fs::read_to_string(INSTALLER_SCRIPT).expect("read installer");
    assert!(
        text.contains("nm-unmanaged.sh"),
        "installer must invoke the NetworkManager exclusion"
    );
    assert!(
        text.contains("nmcli general reload"),
        "installer must ask NetworkManager to re-read its config so the rule applies now"
    );
}
