# Recover a connection

Diagnose the packet path before changing keys or repeatedly restarting a service. The running process, encrypted session, routes, and DNS advertisement are separate states.

## Start with the deployed executable

```sh
systemctl cat prrr-client
/usr/local/bin/prrr --version
/usr/local/bin/prrr client --config /etc/prrr/client.toml doctor
journalctl -u prrr-client -n 100
```

The service runs `/usr/local/bin/prrr`. Rebuilding a different copy in `~/.cargo/bin` does not update it. Use `make install-system` from the intended checkout to deploy the current binary and routing hook.

## Locate the failing boundary

| Observation | Check next |
| --- | --- |
| Certificate or server-name failure | Actual DNS name, trusted certificate chain, and transport endpoint; do not make disabling verification a permanent fix. |
| Session connects but no packets return | TUN address, policy rules, server forwarding/NAT, and MTU. |
| Only some names fail | Routing mode, resolved resource `/32` routes, and the DNS responder subset. |
| Route changes disappear | The deployed hook and NetworkManager's handling of `prrr*`. |
| Reconnect repeats | Transport reachability, authorization, logs, and whether the data plane works after the handshake. |

```sh
ip -4 addr show prrr0
ip -4 rule
ip -4 route show table 51820
resolvectl status
```

Use your configured fwmark/table instead of 51820 if you changed it. Inspect `/run/prrr/env` locally when comparing hook state; review identifiers and endpoints before sharing diagnostics.

## Understand automatic recovery

The [routing animation](../explanation/mechanics.md#routing-and-recovery) shows the sequence:

- Outbound progress with no inbound progress for three 5-second checks triggers the black-hole detector; an idle tunnel alone does not trigger it.
- DNS probes run every 15 seconds, with a 2-second timeout per IPv4 responder. Only responding configured servers are advertised; pinned routes remain so probes still measure the tunnel path.
- A DNS verdict that is not refreshed expires after a 45-second lease. The host resolver takes over instead of trusting a stale verdict indefinitely.
- Resource DNS refresh runs independently with a 20-second budget. A stalled lookup must not stop the packet pump or watchdogs.
- Reconnect uses bounded exponential backoff, negotiates fresh session keys, and reuses the TUN device. Routes are withdrawn while the tunnel is down.

Those intervals are implementation defaults, not a guarantee that every failure is detected within one fixed duration. This behavior favors restoring the host network; it is not a traffic-blocking kill switch.

## Restore the ordinary host path

```sh
sudo systemctl stop prrr-client
ip -4 rule
resolvectl status
```

Normal teardown runs the routing hook's down action. If a process was killed before cleanup, inspect the actual installed rules and the `do_down` action in `/usr/local/bin/prrr-route` before removing anything. Avoid deleting unrelated rules or resolver configuration.
