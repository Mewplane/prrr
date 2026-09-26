# prrr Mobile E2E Testing

End-to-end testing for the prrr Android application using an isolated, three-container
Podman harness. A prrr **server**, an **Android emulator**, and a **test-runner** run on a
private Podman bridge network with no host network access. The harness drives the *real*
Android app through its full lifecycle: a generated client config is deep-linked into the
app for import, the app's `VpnService` is started and stopped, and (in the real-transport
stage) actual tunnel connectivity is asserted over the MASQUE/HARP transport. The goal is to
exercise the genuine user path — config import → `VpnService` lifecycle → tunnel connectivity —
without touching the host network, the production VPN, or any host services.

> **Source of truth**: This document is written against
> [`specs/mobile/SPEC.md`](../../specs/mobile/SPEC.md),
> [`specs/mobile/SPEC-camera-sim.md`](../../specs/mobile/SPEC-camera-sim.md), and
> [`specs/mobile/ROADMAP.md`](../../specs/mobile/ROADMAP.md). IP addresses, ports, service
> names, environment variables, and test-case IDs below are taken from those specs.

The harness runs in two stages, selected by the `MOBILE_E2E_PHASE` environment variable:

- **Lifecycle stage** (`MOBILE_E2E_PHASE=1`, default) — config import, `VpnService` lifecycle,
  and UI state, against the stub transport. Test cases `M-E2E-01` … `M-E2E-05`.
- **Real-transport stage** (`MOBILE_E2E_PHASE=2`) — adds real-tunnel connectivity assertions
  over the MASQUE/HARP transport. Test cases `M-E2E-10` … `M-E2E-14`.

---

## Prerequisites

- **Podman** (`podman --version`) and **podman-compose** (`podman-compose --version`).
  The harness uses Podman and `podman-compose` exclusively — there is no Docker daemon
  dependency.
- **`/dev/kvm`** — hardware virtualization. The Android emulator (`budtmo/docker-android`)
  needs KVM passthrough for acceptable performance. **This is the hard requirement for every
  emulator-based step**: without `/dev/kvm` the emulator will not boot (or runs unusably slow
  under `-no-accel`). On CI this means a bare-metal KVM host or a runner with nested
  virtualization. Verify with:

  ```bash
  ls -l /dev/kvm        # expect: crw-rw-rw- ... /dev/kvm
  ```

- **Android SDK / NDK** — required only to *build* the debug APK and the native UniFFI
  library. The build path is the project's existing `make android-debug` (native `.so` via
  the NDK, then the Gradle APK). The harness itself does not build the APK; it consumes a
  pre-built one.
- **A debug APK in the shared volume** — the test-runner installs a pre-built
  `app-debug.apk` (and, for the real transport, `prrr_mobile.aar`) from the shared
  `prrr-mobile-shared` volume. Build it with `make android-debug` before running the
  emulator-based steps.

The `/dev/net/tun` device and `NET_ADMIN`/`NET_RAW` capabilities are required by the
**server** container (it terminates the VPN tunnel); these are declared in the compose file.

---

## Quick Start

From the project root:

```bash
# Lifecycle stage only (config import + VpnService lifecycle + UI state, stub transport)
make mobile-e2e

# Lifecycle stage + real-transport stage (adds real-tunnel connectivity assertions)
make mobile-e2e-full

# Build the harness container images only
make mobile-e2e-build

# Tear down containers, network, and volumes
make mobile-e2e-clean
```

A run ends by emitting a single result marker that aggregates the individual
`M-E2E-0x` / `M-E2E-1x` results:

```text
MOBILE E2E TEST RESULT: PASS
```

or, on any failed test case:

```text
MOBILE E2E TEST RESULT: FAIL
```

The orchestrator's process exit code follows this marker (`0` on `PASS`, non-zero on `FAIL`),
so it can gate CI directly.

---

## Architecture

Three containers on a dedicated Podman bridge network `prrr-mobile-e2e`
(subnet `10.77.77.0/24`), sharing the `prrr-mobile-shared` volume mounted at `/shared`:

```text
+-- Podman network: prrr-mobile-e2e (10.77.77.0/24) ----------------------+
|                                                                         |
|  +--------------+    +--------------+    +--------------+               |
|  | prrr-server  |    | android-emu  |    | test-runner  |               |
|  |              |    |              |    |              |               |
|  | 10.77.77.10  |    | 10.77.77.20  |    | 10.77.77.30  |               |
|  | :8443 MASQUE |    | :5555 adb    |    | adb client   |               |
|  | :8080 HARP   |    | :6080 noVNC  |    | test scripts |               |
|  | /dev/net/tun |    | /dev/kvm     |    |              |               |
|  +--------------+    +--------------+    +--------------+               |
|                                                                         |
|  Shared volume: prrr-mobile-shared  ->  /shared                         |
|    - server-ready  (readiness marker)                                   |
|    - client.toml   (server-generated client config)                     |
|    - app-debug.apk (pre-built debug APK)                                |
|    - prrr_mobile.aar (pre-built UniFFI library, real-transport runs)    |
+-------------------------------------------------------------------------+
```

| Service       | Container name        | Fixed IP       | Role |
|---------------|-----------------------|----------------|------|
| `prrr-server` | `prrr-mobile-server`  | `10.77.77.10`  | Runs prrr in server mode (reuses `deploy/client/Containerfile`). Listens on `:8443` (MASQUE) and `:8080` (HARP). Generates `client.toml` to the shared volume and writes the `server-ready` marker. |
| `android-emu` | `prrr-mobile-emu`     | `10.77.77.20`  | Headless Android emulator (`budtmo/docker-android`) with `/dev/kvm` passthrough. Exposes `adb` on `:5555` and noVNC on `:6080` (debugging only, not published to host). |
| `test-runner` | `prrr-mobile-runner`  | `10.77.77.30`  | Lightweight `adb` + `bash` + `base64` + `curl` + `jq` container. Drives the test flow. |

**Data flow** (per [`specs/mobile/SPEC.md`](../../specs/mobile/SPEC.md)):

1. `prrr-server` starts, registers a client, writes `/shared/client.toml`, and writes
   `/shared/server-ready`.
2. `inject-config.sh` (in the test-runner) reads `/shared/client.toml`, patches the
   `server_endpoint` to `$SERVER_IP:$SERVER_PORT` (default `10.77.77.10:8443`), and
   base64url-encodes the TOML (no padding).
3. It deep-links the config into the app over `adb`:
   ```bash
   adb -H "$ADB_HOST" shell am start -a android.intent.action.VIEW \
     -d "prrr://import?config=<base64url>" com.prrr.vpn.android
   ```
   `MainActivity` receives the intent, parses it via `parse_qr_config()`, and stores it in
   `EncryptedSharedPreferences`.
4. The test-runner triggers connect; the app's `PrrrVpnService` (`VpnService`) establishes the
   tunnel. The VPN subnet is `10.66.66.0/24`.
5. The test-runner asserts on `logcat`, `dumpsys`, and `uiautomator` output, emits each
   `M-E2E-xx` result, and finally the aggregate `MOBILE E2E TEST RESULT` marker.

---

## Orchestration

`run-mobile-e2e.sh` (invoked by `make mobile-e2e`) runs the flow described in
[`specs/mobile/SPEC.md`](../../specs/mobile/SPEC.md):

1. `podman-compose up -d prrr-server`
2. Wait for `/shared/server-ready`.
3. Copy the pre-built APK into the shared volume.
4. `podman-compose up -d android-emu`.
5. Wait for emulator boot — `wait-for-emulator.sh` polls
   `adb -H "$ADB_HOST" shell getprop sys.boot_completed` until it returns `1` (bounded by
   `EMU_BOOT_TIMEOUT`).
6. Start the test-runner, which installs the APK, injects config, and runs the assertions.
7. Collect the test-runner exit code, tear down all containers and the network (on a `trap`),
   and emit `MOBILE E2E TEST RESULT: PASS` / `FAIL`.

### Scripts

| Script | Purpose |
|--------|---------|
| `run-mobile-e2e.sh` | Top-level orchestrator. Sequences server → emulator → test-runner, copies the APK to the shared volume, drives the virtual-camera feed (when enabled), captures the test-runner exit code, cleans up on exit, and emits the final result marker. |
| `scripts/wait-for-emulator.sh` | Polls `adb -H "$ADB_HOST" shell getprop sys.boot_completed` until `1`; exits non-zero if `EMU_BOOT_TIMEOUT` is exceeded. |
| `scripts/inject-config.sh` | Reads `/shared/client.toml`, patches the endpoint to `$SERVER_IP:$SERVER_PORT`, base64url-encodes it, and sends the `prrr://import?config=<encoded>` deep link via `adb am start`. |
| `scripts/run-tests.sh` | Test-runner entrypoint. Installs the APK (`adb install -r /shared/app-debug.apk`, errors and exits `1` if missing), runs the lifecycle (`M-E2E-0x`) cases, and — when `MOBILE_E2E_PHASE=2` — the real-transport (`M-E2E-1x`) cases. Aggregates results. |
| `scripts/setup-virtual-camera.sh` | Manages the `v4l2loopback` virtual webcam (start / stop / status) for camera-based QR scanning. |
| `scripts/virtual-camera-feed.py` | Renders QR codes as cycling video frames and pipes them into the virtual camera via `ffmpeg`. |
| `scripts/generate-test-qr.py` | Generates QR PNG images from the config TOML for the virtual-camera feed. |

---

## Environment Variables

All defaults below come from [`specs/mobile/SPEC.md`](../../specs/mobile/SPEC.md) (compose
service environment) and [`specs/mobile/ROADMAP.md`](../../specs/mobile/ROADMAP.md)
(orchestration and camera steps).

### Orchestration (`run-mobile-e2e.sh`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `MOBILE_E2E_BOOT_TIMEOUT` | `180` | Seconds to wait for the emulator to finish booting before failing. |
| `MOBILE_E2E_LOG_LEVEL` | `debug` | Log verbosity for the harness / server. |
| `MOBILE_E2E_SKIP_BUILD` | `0` | Set to `1` to reuse pre-built container images and skip the build step. |
| `MOBILE_E2E_PHASE` | `1` | `1` = lifecycle tests only; `2` = also run the real-transport tunnel tests (`make mobile-e2e-full` sets `2`). |
| `MOBILE_E2E_VCAM` | `0` | Set to `1` to enable the virtual-camera pipeline (launches the emulator with `-camera-back webcam0` and starts the QR feed). Requires the `v4l2loopback` kernel module on a KVM host. |
| `MOBILE_E2E_VCAM_ROTATION` | *(unset)* | Rotation applied to the rendered QR video frames; passed through to the test-runner / camera feed. |

### Emulator wait (`scripts/wait-for-emulator.sh`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `EMU_BOOT_TIMEOUT` | `180` | Seconds to poll `sys.boot_completed` before exiting non-zero. |
| `ADB_HOST` | `10.77.77.20` | Emulator host the test-runner talks to over `adb` (`adb -H "$ADB_HOST" ...`). |

### Server container (`prrr-server`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `PRRR_MODE` | `server` | Runs the prrr binary in server mode. |
| `PRRR_LISTEN_ADDR` | `0.0.0.0:8443` | Server listen address (MASQUE on `:8443`). |
| `PRRR_SUBNET` | `10.66.66.0/24` | VPN subnet handed to clients. |
| `PRRR_LOG_LEVEL` | `debug` | Server log level. |

### Emulator container (`android-emu`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `EMULATOR_DEVICE` | `pixel_7` | Emulated device profile. |
| `WEB_VNC` | `true` | Enables the noVNC web console on `:6080` (in-network only). |

### Test-runner container (`test-runner`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `ADB_HOST` | `10.77.77.20` | Emulator IP for `adb connect 10.77.77.20:5555`. |
| `SERVER_IP` | `10.77.77.10` | Server IP injected into the patched `client.toml` endpoint. |
| `SERVER_PORT` | `8443` | Server port injected into the patched endpoint. |
| `MOBILE_E2E_PHASE` | `1` | Gates the real-transport (`M-E2E-1x`) test block. |
| `MOBILE_E2E_VCAM` | `0` | Enables the camera-scan case (`M-E2E-09`); skips gracefully when `0`. |
| `MOBILE_E2E_VCAM_ROTATION` | *(unset)* | Rotation hint for the camera feed. |

---

## Test Cases

### Lifecycle stage — `MOBILE_E2E_PHASE=1` (stub transport, always run)

These run with the stub `VpnConnection` (a simulated connection); no real network traffic.

| ID | Verifies | Method |
|----|----------|--------|
| `M-E2E-01` | Config import via deep link | `adb am start` the `prrr://import` link, then grep `logcat` for `Configuration saved successfully`. |
| `M-E2E-02` | `VpnService` starts on connect | `adb shell dumpsys activity services \| grep PrrrVpnService`. |
| `M-E2E-03` | UI shows the **Connected** state | `adb shell uiautomator dump` + `adb pull`, grep for `Connected`. |
| `M-E2E-04` | Disconnect returns to idle | Trigger disconnect, verify the service stopped. |
| `M-E2E-05` | Config persists across restart | `am force-stop`, relaunch, verify config loaded from `logcat`. |

(The camera-based QR cases `M-E2E-07`/`M-E2E-08`/`M-E2E-09` exercise the real camera → ML Kit
path; `M-E2E-09` skips gracefully unless the virtual camera is enabled — see below.)

### Real-transport stage — gated behind `MOBILE_E2E_PHASE=2`

These require the real tunnel: the mobile library built with real transport, and a running
server + emulator. Enabled by `make mobile-e2e-full`.

| ID | Verifies | Method |
|----|----------|--------|
| `M-E2E-10` | Tunnel establishment | Connect, verify the TUN device via `VpnService` logs. |
| `M-E2E-11` | Traffic through the tunnel | `adb shell ping -c 3 10.66.66.1` (server VPN IP). |
| `M-E2E-12` | DNS resolution via the tunnel | `adb shell nslookup example.com`. |
| `M-E2E-13` | Reconnect after disconnect | Disconnect, reconnect, verify traffic flows. |
| `M-E2E-14` | MTU compliance | Verify zero datagram drops in server logs. |

---

## Virtual Camera (CI QR scanning)

To exercise the real **camera → ML Kit → ViewModel → Rust FFI** QR-scanning path in CI, set
`MOBILE_E2E_VCAM=1`. The harness then:

1. Loads the **`v4l2loopback`** kernel module to create a virtual webcam (`webcam0`) via
   `scripts/setup-virtual-camera.sh` (start / stop / status).
2. Generates QR PNGs from the config TOML with `scripts/generate-test-qr.py`.
3. Renders those QR images as a cycling multi-frame video and pipes it into the virtual
   camera with `ffmpeg` via `scripts/virtual-camera-feed.py`.
4. Launches the emulator with `-camera-back webcam0`, so the app's camera reads the QR feed.

`MOBILE_E2E_VCAM_ROTATION` rotates the rendered frames when set. The QR camera test case
(`M-E2E-09`) skips gracefully when `MOBILE_E2E_VCAM` is not `1`.

> **Requirement**: The virtual-camera pipeline needs the `v4l2loopback` kernel module loadable
> on the host, and the host must already provide `/dev/kvm` for the emulator. This path is
> intended for a self-hosted / bare-metal KVM CI runner.

---

## Troubleshooting

### Emulator will not boot (KVM missing or no permission)

The emulator requires `/dev/kvm`. If `wait-for-emulator.sh` exits non-zero after
`EMU_BOOT_TIMEOUT` seconds, KVM is the first thing to check:

```bash
ls -l /dev/kvm                    # must exist and be readable/writable
podman info | grep -i kvm         # confirm the device is passed through
```

If `/dev/kvm` is absent (e.g. on a hosted CI runner without nested virtualization), the
emulator cannot run with hardware acceleration. Raising `MOBILE_E2E_BOOT_TIMEOUT` /
`EMU_BOOT_TIMEOUT` only masks a slow boot — it does not substitute for KVM.

### `adb connect` failures

The test-runner reaches the emulator at `adb connect 10.77.77.20:5555`. If `adb devices`
shows nothing connected:

```bash
podman logs prrr-mobile-emu       # is the emulator up and adb listening on :5555?
podman exec prrr-mobile-runner adb -H 10.77.77.20 devices
```

Confirm both containers are on `prrr-mobile-e2e` and that `ADB_HOST` matches the emulator IP
(`10.77.77.20`).

### APK missing

`run-tests.sh` installs `/shared/app-debug.apk`; if it is absent the script prints a clear
error and exits `1`. Build it and ensure it lands in the shared volume:

```bash
make android-debug
# then confirm it is in the shared volume
podman run --rm -v prrr-mobile-shared:/shared docker.io/library/ubuntu:24.04 ls -l /shared
```

### Server-ready timeout

The orchestrator waits for `/shared/server-ready`. If it never appears, inspect the server:

```bash
podman logs prrr-mobile-server
podman run --rm -v prrr-mobile-shared:/shared docker.io/library/ubuntu:24.04 \
  ls -l /shared/server-ready /shared/client.toml
```

A missing `client.toml` means config injection will also fail downstream.

### Podman rootless networking

The harness assigns fixed IPs on the `10.77.77.0/24` bridge. Under rootless Podman:

- The network must support a custom bridge with `ipam` static addresses; the
  `netavark` backend handles this. Verify the network exists:
  ```bash
  podman network ls | grep prrr-mobile-e2e
  podman network inspect prrr-mobile-e2e
  ```
- Container-to-container traffic stays inside the bridge — no ports are published to the host
  (no `-p`, no `--network=host`), so the emulator and server are only reachable from inside
  the network (e.g. via `podman exec`).
- If a previous run left a stale network or volume, the IP allocation can clash. Clean up:
  ```bash
  make mobile-e2e-clean
  # or manually:
  podman-compose -f deploy/mobile/podman-compose.yml down -v
  podman network rm prrr-mobile-e2e 2>/dev/null || true
  ```

### Inspecting the emulator screen

`budtmo/docker-android` serves noVNC on `:6080` (enabled by `WEB_VNC=true`), but it is not
published to the host by default. To watch a run, attach via `podman exec` or temporarily map
the port.
