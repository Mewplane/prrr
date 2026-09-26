//! Android emulator orchestration for e2e connectivity tests.
//!
//! Wraps `emulator` and `adb` CLI commands for headless testing.
//! Config injection uses deep link intents — no camera needed.
//!
//! Resolves tools from `ANDROID_HOME` env var or `android-sdk/` in the repo.

use std::{
    path::PathBuf,
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

/// Find the emulator binary.
fn find_emulator() -> Option<PathBuf> {
    // Check ANDROID_HOME first
    if let Ok(home) = std::env::var("ANDROID_HOME") {
        let p = PathBuf::from(&home).join("emulator/emulator");
        if p.exists() {
            return Some(p);
        }
    }
    // Check repo-local android-sdk
    let p = PathBuf::from("android-sdk/emulator/emulator");
    if p.exists() {
        return Some(p);
    }
    // Check PATH
    if Command::new("emulator")
        .arg("-version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Some(PathBuf::from("emulator"));
    }
    None
}

/// Find the adb binary.
fn find_adb() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("ANDROID_HOME") {
        let p = PathBuf::from(&home).join("platform-tools/adb");
        if p.exists() {
            return Some(p);
        }
    }
    let p = PathBuf::from("android-sdk/platform-tools/adb");
    if p.exists() {
        return Some(p);
    }
    if Command::new("adb")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Some(PathBuf::from("adb"));
    }
    None
}

/// Android emulator wrapper for e2e testing.
pub struct AndroidEmulator {
    avd_name: String,
    process: Option<Child>,
    serial: Option<String>,
    emulator_bin: PathBuf,
    adb_bin: PathBuf,
}

impl AndroidEmulator {
    pub fn new(avd_name: &str) -> Self {
        Self {
            avd_name: avd_name.to_string(),
            process: None,
            serial: None,
            emulator_bin: find_emulator().unwrap_or_else(|| PathBuf::from("emulator")),
            adb_bin: find_adb().unwrap_or_else(|| PathBuf::from("adb")),
        }
    }

    /// Check if emulator binary is available.
    pub fn emulator_available() -> bool {
        find_emulator().is_some()
    }

    /// Check if adb is available.
    pub fn adb_available() -> bool {
        find_adb().is_some()
    }

    /// Start the emulator headless (no window, no audio, no boot animation).
    pub fn start(&mut self) -> Result<(), String> {
        let child = Command::new(&self.emulator_bin)
            .args(["-avd", &self.avd_name, "-no-window", "-no-audio", "-no-boot-anim", "-gpu", "host"])
            .spawn()
            .map_err(|e| format!("emulator start: {e}"))?;

        self.process = Some(child);
        self.serial = Some("emulator-5554".to_string());
        Ok(())
    }

    /// Wait for the emulator to finish booting.
    pub fn wait_for_boot(&self, timeout: Duration) -> Result<(), String> {
        let start = Instant::now();
        let serial = self.serial.as_ref().ok_or("emulator not started")?;

        while start.elapsed() < timeout {
            let output = Command::new(&self.adb_bin)
                .args(["-s", serial, "shell", "getprop", "sys.boot_completed"])
                .output()
                .map_err(|e| format!("adb shell: {e}"))?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.trim() == "1" {
                return Ok(());
            }
            thread::sleep(Duration::from_secs(2));
        }
        Err(format!("emulator not booted after {:?}", timeout))
    }

    /// Install an APK on the emulator.
    pub fn install_apk(&self, apk_path: &str) -> Result<(), String> {
        let serial = self.serial.as_ref().ok_or("emulator not started")?;

        let output = Command::new(&self.adb_bin)
            .args(["-s", serial, "install", "-r", apk_path])
            .output()
            .map_err(|e| format!("adb install: {e}"))?;

        if !output.status.success() {
            return Err(format!("adb install failed:\n{}", String::from_utf8_lossy(&output.stderr)));
        }
        Ok(())
    }

    /// Inject VPN config via deep link intent (bypasses camera entirely).
    pub fn inject_config_via_deeplink(&self, prrr_url: &str) -> Result<(), String> {
        let serial = self.serial.as_ref().ok_or("emulator not started")?;

        let output = Command::new(&self.adb_bin)
            .args([
                "-s",
                serial,
                "shell",
                "am",
                "start",
                "-a",
                "android.intent.action.VIEW",
                "-d",
                prrr_url,
            ])
            .output()
            .map_err(|e| format!("adb am start: {e}"))?;

        if !output.status.success() {
            return Err(format!("deep link injection failed:\n{}", String::from_utf8_lossy(&output.stderr)));
        }
        Ok(())
    }

    /// Run a shell command on the emulator.
    pub fn shell(&self, cmd: &str) -> Result<String, String> {
        let serial = self.serial.as_ref().ok_or("emulator not started")?;

        let output = Command::new(&self.adb_bin)
            .args(["-s", serial, "shell", cmd])
            .output()
            .map_err(|e| format!("adb shell: {e}"))?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Check if VPN tunnel is active (tun0 interface exists).
    pub fn check_vpn_active(&self) -> Result<bool, String> {
        let output = self.shell("ip addr show tun0")?;
        Ok(output.contains("tun0"))
    }

    /// Grant VPN permission to a package (bypasses the system consent dialog).
    pub fn grant_vpn_permission(&self, package: &str) -> Result<(), String> {
        let serial = self.serial.as_ref().ok_or("emulator not started")?;

        // Grant ACTIVATE_VPN via appops (works on API 26+)
        let output = Command::new(&self.adb_bin)
            .args(["-s", serial, "shell", "cmd", "appops", "set", package, "ACTIVATE_VPN", "allow"])
            .output()
            .map_err(|e| format!("appops set: {e}"))?;

        if !output.status.success() {
            return Err(format!("grant VPN permission failed:\n{}", String::from_utf8_lossy(&output.stderr)));
        }
        Ok(())
    }

    /// Ping a target IP from the emulator.
    pub fn ping(&self, target_ip: &str) -> Result<bool, String> {
        let serial = self.serial.as_ref().ok_or("emulator not started")?;

        let output = Command::new(&self.adb_bin)
            .args(["-s", serial, "shell", "ping", "-c", "3", "-W", "5", target_ip])
            .output()
            .map_err(|e| format!("adb shell ping: {e}"))?;

        Ok(output.status.success())
    }
}

impl Drop for AndroidEmulator {
    fn drop(&mut self) {
        // Kill emulator via adb
        if let Some(serial) = &self.serial {
            let _ = Command::new(&self.adb_bin).args(["-s", serial, "emu", "kill"]).output();
        }
        // Also kill the process directly
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
