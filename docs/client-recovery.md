# Verify a recovered client without changing the host connection

Use a private copy of the existing identity and server settings. Never run an
experimental routing hook in the host network namespace. A network namespace
alone is insufficient: the hook can still reach the host's NetworkManager and
systemd-resolved through the system D-Bus socket.

The recovery procedure uses `pasta` to create a user/network namespace, followed
by `unshare` for private mount/PID namespaces. Bind the underlay to the physical
Wi-Fi interface using both `-i` and `--outbound-if4`. This verifies that prrr can
connect independently of an existing OpenVPN default route.

Inside the private mount namespace:

1. Check that the network and mount namespace identifiers differ from the host.
2. Make mounts private, mount fresh read-only sysfs for the namespace, and
   overlay `/run` with tmpfs. Verify that host-only network devices and the
   system D-Bus socket are absent before starting the client or its hook.
   An inherited sysfs mount exposes the host network-device list even when
   netlink and `/proc/net` describe the private namespace.
   For these IPv4-only probes, disable IPv6 in the private network namespace
   before creating the TUN; leave the host's IPv6 settings alone.
3. Supply a private resolver file and NSS configuration using `hosts: files dns`.
   The host's `resolve` NSS module cannot contact systemd-resolved after `/run`
   is hidden. The resulting DNS failure belongs to the test fixture.
4. Keep config, logs, downloaded media and application state in a private task
   directory. Mount private Codex state over its normal state directory and
   use a fresh browser profile. Clear proxy environment variables.
5. Start the candidate binary with the matching repository route hook. Use
   `all_traffic = true` and `resources = []` to test primary IPv4 routing.
6. Assert that unmarked internet traffic selects the TUN, marked transport
   traffic selects the physical underlay, and the external exit IP is the
   configured server's IP. A successful HTTP response without this exit check
   does not prove that the application used prrr.
7. Stop the private client, destroy the namespaces, and compare host routes,
   rules, addressing, resolver settings and service state with saved snapshots.

Do not install packages globally, stop OpenVPN, activate the host prrr service,
reload NetworkManager or change host routes/DNS as part of these tests.

## Recovery changes

The hybrid Noise IK/ML-KEM handshake produces an 1184-byte first message.
MASQUE adds two bytes, and QUIC adds its own headers. Quinn's default initial
1200-byte UDP packet budget cannot carry that message. A connection can work
only if path MTU discovery increases the budget before the send, making startup
intermittent. The transport now starts with 1232 bytes, the IPv6 minimum MTU
minus IPv6/UDP headers; Quinn's minimum-MTU fallback remains at its default.
The regression exchanges the actual hybrid message over real QUIC with MTU
discovery disabled. Inner tunnel MTU stays at 1100 bytes.

The service's MASQUE transport bounds the complete QUIC/CONNECT-UDP/hybrid
connection attempt to 15 seconds and interrupts it on cancellation. A silent
peer or unanswered handshake therefore returns an error to the existing
reconnect/backoff loop instead of keeping the service in setup indefinitely.

The installed route hook also needs the address-repair, scoped NetworkManager
exclusion and DNS-liveness gate already present in the repository. Replacing
only `~/.cargo/bin/prrr` does not update the systemd service, whose binary and
hook are under `/usr/local/bin`.

For a primary IPv4 connection, exact hostname resources do not cover rotating
video subdomains or Telegram's direct datacenter sockets. Use the full IPv4
configuration from [Configuration](configuration.md#primary-internet-connection).

## Validation evidence

The task's private harness is `/tmp/prrr-client-recovery/live-isolated.sh` and
its adjacent Python probes. It executes real DNS, exit-IP, web, media, Telegram
MTProto and authenticated Codex requests. Its namespace checks fail before any
route mutation if the isolation boundaries are absent. The live logs distinguish
transport failures from application HTTP errors and browser consent dialogs.

The matched recovery artifacts and test evidence are staged under
`target/client-recovery/`. The client config contains the existing private
identity and must retain mode `0600`; the enclosing directory is private.
The staging operation does not install or activate the host service.
The bundle's `README.md` lists the matched files and their eventual destinations.
Enabling the existing host service before replacing its stale files would still
use the broken deployment.

The final isolated browser test records playback beyond ten seconds and decoded
320×240 frames, with HTTP 200 media from Googlevideo. Full MP4 downloads and
ffmpeg decoding, Telegram Web/MTProto, an authenticated Codex agent and repeated
DNS probes also pass. The standalone yt-dlp YouTube download returns HTTP 403;
its extractor reports missing proof-of-origin tokens. That download is not
represented as successful.

Host IPv4 routes/addressing, policy rules and resolver settings match the saved
baseline, and the service remains inactive. OpenVPN's device was recreated
during the session, changing its index and IPv6 link-local address; the recovery
work issued no host VPN control commands. The retained comparison reports the
raw differences rather than claiming identical full snapshots.

See [BUG-client-primary-connection-recovery](../specs/bugs/BUG-client-primary-connection-recovery.md)
for measured application results and deployment limitations, and
[BUG-client-network-dependency-audit](../specs/bugs/BUG-client-network-dependency-audit.md)
for the patched dependency and PEM-parser audit.

## Activating the client on the host

Everything above deliberately leaves the host connection untouched. Activation is
a separate, ordered step, because the client that is being tested is the one that
will own the default path — a wrong order can remove the connection the
verification runs on.

1. `make install-system`. This is the only install path that updates the files the
   systemd service actually runs: `/usr/local/bin/prrr`, `/usr/local/bin/prrr-route`,
   the unit file and the `prrr*` NetworkManager exclusion. Enabling the service
   before this step keeps running the previously installed artifacts, which is how
   a fixed build can appear "still broken" in production.
2. Select the routing mode in `/etc/prrr/client.toml`: `all_traffic = true` with
   `resources = []` for a primary connection, or an explicit `resources` list for a
   split tunnel. Keep the file mode `0600` (it carries the private key).
3. `sudo systemctl start prrr-client`, then verify the data plane rather than the
   process. Four checks prove it; a running unit proves nothing:
   - `ip -4 addr show prrr0` still lists the configured tunnel address;
   - `ip -4 rule` lists the `not fwmark` rule and the `suppress_prefixlength 0`
     rule that make the policy table reachable;
   - `resolvectl status` shows the tunnel link as the DNS owner (or the host
     resolver in charge while the DNS gate is closed);
   - an external request reports the server's exit address, for example
     `curl -s https://api.ipify.org`.
4. `sudo systemctl enable prrr-client` only after those checks pass, so a boot
   cannot inherit a configuration that never carried traffic.

Rollback is `sudo systemctl stop prrr-client`: the hook's `down` path removes the
policy rules, the tunnel default route, the pinned `/32` host routes and the
resolver advertisement, which leaves the host's own default route in the `main`
table. If the client is killed before it runs `down`, replay the same commands
`deploy/client/prrr-route` issues in `do_down` (`ip -4 rule del …`,
`ip -4 route del default dev prrr0 table <fwmark>`, `resolvectl revert prrr0`).

On the development host the service was started and enabled by the operator with
the artifacts that were already installed, in split resource mode, and reported
working traffic. The recovery artifacts (this `make install-system` plus the
primary-IPv4 configuration) therefore still need to be deployed there; a
privileged install on that machine requires an interactive sudo prompt, which a
non-interactive agent session cannot answer.
