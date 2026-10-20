/* Source-accurate illustrated explainers. No credentials or real network traffic. */
(() => {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  const STEP_MS = 4800;
  const PORTRAIT_BELOW_PX = 800;
  let instance = 0;

  const flows = {
    handshake: {
      title: "Two messages, a fresh encrypted session", label: "IDENTITY & HYBRID HANDSHAKE",
      steps: [
        ["Pinned identities", "The client starts with its Noise private key and the server's Noise and ML-KEM public keys. The server's registry must authorize that client identity.", ["client", "server"], null],
        ["Outer transport", "HARP establishes HTTPS over TCP, using WebSocket, HTTP/2 streaming, or polling. MASQUE establishes QUIC and HTTP/3 CONNECT-UDP over UDP. Port 443 is the illustrated deployment.", ["client", "server"], "outer"],
        ["Noise message one", "HybridInitiator encapsulates to the server's ML-KEM-768 public key. It places the KEM ciphertext inside the first Noise IK message payload and sends message one through the outer transport.", ["client", "server"], "message-one"],
        ["Authorize client", "The server processes Noise message one, decapsulates its KEM payload, and authenticates the revealed Noise static identity against the client registry. A key exchange alone does not grant a tunnel.", ["server"], null],
        ["Noise message two", "The server returns the second Noise IK message. The client verifies it against the pinned server identity and completes the Noise transcript.", ["server", "client"], "message-two"],
        ["Derive session keys", "HKDF-SHA256 uses the Noise handshake hash as salt and the ML-KEM shared secret as input. Identity-bound info derives 96 bytes: tx_key, rx_key, and header_key. The packet channel consumes the first two.", ["client", "server"], null],
        ["Tunnel ready", "The client installs routes after connection and creates an EncryptedChannel from the directional session keys. The server reverses send and receive keys. Application IP packets can now enter the tunnel.", ["client", "server"], "ready"],
      ],
    },
    packets: {
      title: "Follow one packet there and back", label: "INSIDE THE ENCRYPTED TUNNEL",
      steps: [
        ["Application to TUN", "The host's routing policy sends a selected application IP packet to the TUN device. Traffic excluded by that policy follows the host's ordinary routes.", ["application", "tun"], "capture"],
        ["Seal the packet", "EncryptedChannel seals the IP packet with ChaCha20-Poly1305. Its wire form is an 8-byte big-endian counter, encrypted payload, and a 16-byte authentication tag. The counter is also authenticated as AAD.", ["tun"], null],
        ["Wrap the ciphertext", "HARP adds a 4-byte version/type/reserved/length header before HTTP carriage. MASQUE wraps the same inner ciphertext in an HTTP Datagram with quarter-stream ID and context ID zero. These are alternative configured transports.", ["tun"], null],
        ["Cross the network", "The encrypted packet crosses HARP over TCP or MASQUE over UDP. Outer TLS/QUIC protects transport; inner ChaCha20-Poly1305 protects the tunnel payload. Address, timing, and size metadata remain observable.", ["tun", "relay"], "outbound"],
        ["Verify and forward", "The server checks the receive counter against its replay window and verifies AEAD before writing the recovered IP packet to its client TUN. Host forwarding and NAT then carry it toward the destination.", ["relay", "destination"], "forward"],
        ["Destination replies", "The destination sends a reply through the server. The server encrypts that return IP packet with the opposite-direction key and an independent counter before transport back to the client.", ["destination", "relay", "tun"], "reply"],
        ["Open the return packet", "The client checks the return counter and AEAD tag, then writes the accepted IP packet to its TUN device. The host delivers the reply to the application.", ["tun", "application"], "deliver"],
        ["Reject a replay", "A duplicate counter or a packet older than the 2,048-packet sliding window is rejected. Tampered ciphertext fails AEAD. Rejected traffic does not reach the application's IP path.", ["relay"], "replay"],
      ],
    },
    routing: {
      title: "Choose a route, survive a broken path", label: "POLICY, DNS & RECOVERY",
      steps: [
        ["Select a policy", "Linux routing can select resource destinations, explicit allowed IP prefixes, or all traffic. The route hook applies that policy after connection. Automatic local-LAN exclusions are controlled separately by full_tunnel.", ["policy"], null],
        ["Route a resource", "Configured resource hostnames resolve to IPv4 addresses installed in the policy table. A background refresher updates those routes while the packet pump keeps running; recent answers are retained for continuity.", ["policy", "tunnel"], "resource"],
        ["Preserve bypasses", "Transport sockets carry a firewall mark so the server connection uses the host route rather than looping into its own TUN. By default, detected local RFC1918 LAN prefixes are also excluded; full_tunnel disables automatic LAN exclusions.", ["policy", "internet"], "bypass"],
        ["Gate tunnel DNS", "Independent probes check pinned tunnel resolvers. Only responding resolvers are advertised; when none answer or the verdict expires, the hook withdraws tunnel DNS and retains the host's resolver. This is DNS availability handling, not a kill switch.", ["policy", "tunnel"], "dns"],
        ["Detect a black hole", "The watchdog compares tunnel traffic counters. Repeated outbound progress without inbound answers triggers reconnection even when the transport reports no socket error. DNS probes and resource refresh do not block the packet pump.", ["tunnel"], null],
        ["Back off and reconnect", "On failure the client removes tunnel routes, waits with exponential backoff and jitter, and attempts a new connection and hybrid handshake. Host routes apply while tunnel routes are down; this is not fail-closed traffic blocking.", ["tunnel", "internet"], "retry"],
        ["Restore the session", "A successful connection resets backoff, installs routes again, and starts a packet pipeline with fresh session keys. The existing client TUN persists, so its interface and client IP survive reconnection.", ["policy", "tunnel"], "restored"],
      ],
    },
  };

  function html(tag, className, value) {
    const node = document.createElement(tag);
    node.className = className;
    if (value !== undefined) node.textContent = value;
    return node;
  }

  function svg(tag, attrs, parent) {
    const node = document.createElementNS(NS, tag);
    for (const [name, value] of Object.entries(attrs || {})) node.setAttribute(name, String(value));
    if (parent) parent.append(node);
    return node;
  }

  function text(parent, x, y, value, className = "", attrs = {}) {
    const node = svg("text", {x, y, class: className, ...attrs}, parent);
    node.textContent = value;
    return node;
  }

  function rect(parent, x, y, width, height, className, radius = 10, attrs = {}) {
    return svg("rect", {x, y, width, height, rx: radius, class: className, ...attrs}, parent);
  }

  function group(parent, x = 0, y = 0, attrs = {}) {
    return svg("g", {transform: "translate(" + x + " " + y + ")", ...attrs}, parent);
  }

  function path(parent, d, className, attrs = {}) {
    return svg("path", {d, class: className, ...attrs}, parent);
  }

  function icon(parent, kind, x, y, size = 28, className = "") {
    const node = group(parent, x, y, {class: "sy-icon " + className, transform: "translate(" + x + " " + y + ") scale(" + size / 32 + ")"});
    const shapes = {
      terminal: ["M3 5h26v20H3z", "M10 30h12M16 25v5", "M8 11l4 4-4 4m8 0h7"],
      daemon: ["M5 3h22v10H5zM5 19h22v10H5z", "M9 8h1m5 0h8M9 24h1m5 0h8M16 13v6"],
      shield: ["M16 2l12 5v9c0 7-12 14-12 14S4 23 4 16V7z", "M10 16l4 4 8-9"],
    };
    for (const d of shapes[kind] || []) path(node, d, "sy-icon__stroke");
    return node;
  }

  function device(parent, type, box, active) {
    const node = group(parent, box.x, box.y, {"data-node": type, "data-active": String(active), class: "sy-device"});
    rect(node, 0, 0, box.w, box.h, "sy-device__body", 12);
    rect(node, 7, 7, box.w - 14, box.h - 14, "sy-device__screen", 7);
    svg("circle", {cx: 20, cy: 20, r: 3, class: "sy-dot sy-pink"}, node);
    svg("circle", {cx: 32, cy: 20, r: 3, class: "sy-dot sy-gold"}, node);
    svg("circle", {cx: 44, cy: 20, r: 3, class: "sy-dot sy-good"}, node);
    path(node, "M10 33H" + (box.w - 10), "sy-device__separator");
    return node;
  }

  function boundary(parent, x, y, width, height, label) {
    rect(parent, x, y, width, height, "sy-boundary", 16);
    text(parent, x + 14, y + 24, label, "sy-svg-kicker");
  }

  function channel(parent, id, route, label, labelX, labelY, visible, active, marker, number) {
    const node = svg("g", {"data-channel": id, "data-visible": String(visible), "data-active": String(active), class: "sy-channel"}, parent);
    const line = path(node, route, "sy-channel__line", {"marker-end": "url(#" + marker + ")"});
    if (active) line.classList.add("sy-channel__line--active");
    rect(node, labelX - 12, labelY - 17, Math.min(260, label.length * 8 + 42), 25, "sy-channel__label-bg", 5);
    text(node, labelX, labelY, number + "  " + label, "sy-svg-small");
    return line;
  }

  function packet(parent, line, label, compact) {
    const node = group(parent, 0, 0, {"data-packet": "", class: "sy-mechanics__packet"});
    const short = compact || line.getTotalLength() < 150;
    rect(node, short ? -24 : -69, -15, short ? 48 : 138, 30, "sy-packet__body", 6);
    if (!short) path(node, "M-59-6l10 7 10-7M-59-6v13h20V-6", "sy-packet__envelope");
    text(node, short ? 0 : 9, 5, label, "sy-packet__text", {"data-message": label, "text-anchor": "middle"});
    return {node, line};
  }


  function center(parent, x, y, value, kind = "sy-svg-small") {
    return text(parent, x, y, value, kind, {"text-anchor": "middle"});
  }

  function actor(parent, id, box, heading, rows, active, kind = "terminal") {
    const node = device(parent, id, box, active);
    icon(node, kind, 16, 46, 27, "sy-gold");
    text(node, 53, 65, heading, "sy-svg-body");
    const rowGap = rows.length > 1 ? Math.min(28, (box.h - 18 - 98) / (rows.length - 1)) : 28;
    rows.forEach((row, index) => text(node, 17, 98 + index * rowGap, row, "sy-svg-small" + (index === rows.length - 1 ? " sy-gold" : "")));
    return node;
  }

  function message(parent, x, y, width, heading, rows, part = "explanation") {
    const node = group(parent, x, y, {"data-part": part});
    rect(node, 0, 0, width, 50 + rows.length * 27, "sy-device__screen", 9);
    text(node, 16, 28, heading, "sy-svg-kicker");
    rows.forEach((row, index) => text(node, 16, 58 + index * 27, row, "sy-svg-small"));
    return node;
  }

  function connection(parent, id, route, label, x, y, active, marker, number) {
    return channel(parent, id, route, label, x, y, active, active, marker, number);
  }

  function handshakeScene(scene, step, compact, flow, marker) {
    const a = compact ? {x: 54, y: 55, w: 312, h: 190} : {x: 38, y: 68, w: 268, h: 230};
    const b = compact ? {x: 54, y: 400, w: 312, h: 215} : {x: 654, y: 68, w: 268, h: 230};
    const focus = flow.steps[step][2];
    boundary(scene, compact ? 35 : 20, 12, compact ? 350 : 304, compact ? 252 : 306, "CLIENT · LOCAL KEY FILE");
    boundary(scene, compact ? 35 : 636, compact ? 358 : 12, compact ? 350 : 304, compact ? 275 : 306, "SERVER · LOCAL KEY FILES");
    const clientRows = [
      ["Noise private key", "Pinned server Noise key", "Pinned server KEM key"],
      ["TLS / QUIC negotiation", "Validate server certificate", "Outer channel established"],
      ["ML-KEM-768 encapsulate", "Noise IK: e, es, s, ss", "Send protected KEM payload"],
      ["Message one sent", "Waiting for server response", "Identity must be allowed"],
      ["Read Noise: e, ee, se", "Verify pinned server", "Noise transcript complete"],
      ["HKDF-SHA256", "tx_key / rx_key", "Directional keys ready"],
      ["Routes installed", "EncryptedChannel ready", "Application traffic starts"],
    ];
    const serverRows = [
      ["Noise + ML-KEM private keys", "Client identity registry", "Private material stays local"],
      ["HTTPS or HTTP/3 endpoint", "TLS / QUIC established", "No IP tunnel yet"],
      ["Read Noise message one", "ML-KEM decapsulation", "Recover client static key"],
      ["Registry identity lookup", "Authorized client accepted", "Unknown identity rejected"],
      ["Write Noise message two", "Fresh ephemeral exchange", "Return protected response"],
      ["Same transcript + KEM secret", "Same identity-bound HKDF", "Reverse tx / rx direction"],
      ["Per-client TUN pipeline", "AEAD + replay window", "Tunnel ready"],
    ];
    actor(scene, "client", a, "prrr client", clientRows[step], focus.includes("client"));
    actor(scene, "server", b, "prrr server", serverRows[step], focus.includes("server"), "daemon");
    if (!compact) {
      icon(scene, "shield", 451, 83, 56, "sy-gold");
      center(scene, 480, 163, "OUTER CHANNEL", "sy-svg-kicker");
      center(scene, 480, 188, "TLS / QUIC", "sy-svg-body");
      center(scene, 480, 270, "Untrusted network", "sy-svg-small sy-muted");
    }
    const active = flow.steps[step][3];
    const reverse = active === "message-two";
    const route = compact
      ? reverse ? "M284 400V245" : "M136 245V400"
      : reverse ? "M654 231H306" : "M306 224H654";
    const labels = {outer: "Outer transport", "message-one": "Noise message 1", "message-two": "Noise message 2", ready: "Encrypted IP packet"};
    let moving = null;
    for (const id of Object.keys(labels)) {
      const line = connection(scene, id, route, labels[id], compact ? 164 : 373, compact ? 319 : 210, active === id, marker, step + 1);
      if (active === id) moving = {line, label: id === "message-one" ? "IK1" : id === "message-two" ? "IK2" : id === "ready" ? "IP" : "TLS"};
    }
    const x = compact ? 25 : 38;
    const y = compact ? 658 : 351;
    const width = compact ? 370 : 884;
    if (step === 2 || step === 3) {
      message(scene, x, y, width, "MESSAGE ONE · HYBRID EXCHANGE", compact ? ["Noise_IK_25519_ChaChaPoly_BLAKE2s", "Protected payload: ML-KEM-768 ciphertext", "KEM ciphertext: 1,088 B", "Static identity + fresh ephemeral exchange"] : ["Noise_IK_25519_ChaChaPoly_BLAKE2s · X25519 static + ephemeral exchange", "Noise payload contains the 1,088-byte ML-KEM-768 ciphertext.", "Noise verifies possession of identity keys; the registry separately authorizes the client."], "hybrid");
    } else if (step === 5 || step === 6) {
      message(scene, x, y, width, "KEY SCHEDULE · NOT RAW NOISE TRANSPORT", compact ? ["HKDF-SHA256 → 96 bytes", "salt = Noise handshake hash", "input = ML-KEM shared secret", "info binds both static public keys", "tx_key 32 B · rx_key 32 B · header 32 B", "Packet channel uses tx_key and rx_key"] : ["HKDF-SHA256(salt = Noise handshake hash, input = ML-KEM shared secret)", "Info: \"PhantomVPN v1\" + initiator static public key + responder static public key", "96 bytes → tx_key (32 B) · rx_key (32 B) · header_key (32 B)", "EncryptedChannel consumes the directional keys; a derived header key does not imply header encryption."], "key-schedule");
    } else {
      message(scene, x, y, width, "TWO LAYERS · DISTINCT JOBS", compact ? ["Outer TLS / QUIC: transport protection", "Inner Noise IK: authenticated key exchange", "ML-KEM-768: hybrid shared-secret input", "Inner AEAD: application IP encryption", "Port 443 shown; endpoints are configurable"] : ["Outer TLS / QUIC protects carriage. Noise IK authenticates the inner key exchange.", "ML-KEM-768 contributes the hybrid secret; ChaCha20-Poly1305 protects IP packets.", "Pinned keys are configured inputs. The animation never reads your files or contacts a server."], "layers");
    }
    return moving;
  }

  function packetAnatomy(scene, x, y, width, compact, step) {
    const g = group(scene, x, y, {"data-part": "wire-packet"});
    text(g, 0, 0, "INNER PACKET · CHACHA20-POLY1305", "sy-svg-kicker");
    const parts = compact ? [
      [0, 20, width, "counter · 8 B", "nonce", "sy-frame__version"],
      [0, 66, width, "encrypted IP payload", "ciphertext", "sy-frame__nonce"],
      [0, 112, width, "tag · 16 B", "tag", "sy-frame__mac"],
    ] : [
      [0, 20, width * .23, "counter · 8 B", "nonce", "sy-frame__version"],
      [width * .23 + 5, 20, width * .5 - 10, "encrypted IP payload", "ciphertext", "sy-frame__nonce"],
      [width * .73, 20, width * .27, "tag · 16 B", "tag", "sy-frame__mac"],
    ];
    for (const [px, py, pw, label, part, kind] of parts) {
      rect(g, px, py, pw, 38, kind, 5, {"data-part": part});
      center(g, px + pw / 2, py + 25, label, "sy-svg-body");
    }
    const noteY = compact ? 179 : 88;
    text(g, 0, noteY, step === 7 ? "Replay rejected · duplicate counter 42" : "Example counter: 42 · AAD = 8 counter bytes", "sy-svg-small sy-gold");
    text(g, 0, noteY + 27, compact ? "Nonce: 4 zero bytes + epoch-local counter" : "AEAD nonce = 4 zero bytes + epoch-local 64-bit counter; counter values here are examples.", "sy-svg-small sy-muted");
    return g;
  }

  function transportAnatomy(scene, x, y, width, compact) {
    const g = group(scene, x, y, {"data-part": "transport"});
    rect(g, 0, 0, width, compact ? 212 : 131, "sy-device__screen", 9);
    text(g, 16, 28, compact ? "HARP · 4-BYTE HEADER" : "HARP · 4-BYTE HEADER BEFORE CIPHERTEXT", "sy-svg-kicker");
    const columns = [["v1 / DATA", "sy-frame__version"], ["zero · 1 B", "sy-frame__nonce"], ["len · 2 B", "sy-frame__mac"]];
    const unit = (width - 32) / 3;
    columns.forEach(([label, kind], index) => {
      rect(g, 16 + index * unit, 42, unit - 4, 33, kind, 4, {"data-part": "harp-header"});
      center(g, 14 + (index + .5) * unit, 64, label, "sy-svg-small");
    });
    const rows = compact ? [
      "HARP · TCP/443 · outer TLS",
      "WebSocket / HTTP/2 streaming / polling",
      "MASQUE · UDP/443 · outer QUIC",
      "HTTP Datagram: stream ID + context 0",
      "Visible metadata: address / timing / size",
    ] : ["HARP · TCP/443 · outer TLS → WebSocket / H2 / polling; MASQUE · UDP/443 · outer QUIC → HTTP Datagrams.", "MASQUE: quarter-stream ID + context 0 + inner ciphertext. Address / timing / size metadata remain visible."];
    rows.forEach((row, index) => text(g, 16, 101 + index * 25, row, "sy-svg-small"));
  }

  function packetsScene(scene, step, compact, flow, marker) {
    const boxes = compact ? {
      application: {x: 50, y: 45, w: 320, h: 130}, tun: {x: 50, y: 257, w: 320, h: 157},
      relay: {x: 50, y: 509, w: 320, h: 157}, destination: {x: 50, y: 752, w: 320, h: 130},
    } : {
      application: {x: 20, y: 94, w: 184, h: 182}, tun: {x: 265, y: 94, w: 200, h: 182},
      relay: {x: 542, y: 94, w: 200, h: 182}, destination: {x: 797, y: 94, w: 143, h: 182},
    };
    const focus = flow.steps[step][2];
    boundary(scene, compact ? 31 : 6, compact ? 15 : 50, compact ? 358 : 474, compact ? 417 : 246, "CLIENT HOST · ROUTING + AEAD");
    actor(scene, "application", boxes.application, compact ? "Application" : "App", compact ? [step >= 6 ? "Reply delivered" : "Selected IP packet"] : ["IP packet", step >= 6 ? "Reply received" : "Route lookup", "Example flow"], focus.includes("application"));
    actor(scene, "tun", boxes.tun, "Client TUN", compact ? [step === 1 ? "Seal with tx_key" : step >= 6 ? "Open with rx_key" : "EncryptedChannel", "Counter + AEAD tag", "Packet pump"] : ["EncryptedChannel", step >= 6 ? "rx_key → plaintext" : "tx_key → ciphertext", "Independent counters"], focus.includes("tun"), "shield");
    actor(scene, "relay", boxes.relay, "prrr server", compact ? [step === 7 ? "Replay rejected" : "Check counter + AEAD", "Server TUN → host routing", "IP forwarding / NAT"] : [step === 7 ? "Replay rejected" : "Replay + AEAD checks", "Per-client TUN", "Host forwarding / NAT"], focus.includes("relay"), "daemon");
    actor(scene, "destination", boxes.destination, compact ? "Destination" : "Website", compact ? [step >= 5 ? "Return IP packet" : "Application endpoint"] : ["Destination", step >= 5 ? "IP reply" : "IP request", "Own TLS if used"], focus.includes("destination"));
    const specs = compact ? [
      ["capture", "M170 175V257", "Selected IP", 188, 218, "IP"],
      ["outbound", "M170 414V509", "Inner ciphertext", 188, 463, "AEAD"],
      ["forward", "M170 666V752", "Recovered IP", 188, 711, "IP"],
      ["reply", "M370 587H399V335H370", "Return ciphertext", 183, 463, "RX"],
      ["deliver", "M50 336H21V110H50", "Accepted reply", 55, 227, "IP"],
      ["replay", "M170 414V509", "Duplicate counter", 188, 463, "42"],
    ] : [
      ["capture", "M204 181H265", "IP", 218, 158, "IP"],
      ["outbound", "M465 181H542", "Ciphertext", 464, 158, "AEAD"],
      ["forward", "M742 181H797", "IP", 755, 158, "IP"],
      ["reply", "M642 276V320H365V276", "Opposite-direction key + counter", 437, 346, "RX"],
      ["deliver", "M265 241H204", "IP reply", 211, 303, "IP"],
      ["replay", "M465 181H542", "Replay", 466, 158, "42"],
    ];
    let moving = null;
    if (step === 5) {
      channel(scene, "destination-reply", compact ? "M210 752V666" : "M797 241H742", "IP reply", compact ? 229 : 751, compact ? 711 : 303, true, false, marker, 1);
    }
    for (const [id, route, label, x, y, payload] of specs) {
      const active = flow.steps[step][3] === id;
      const line = connection(scene, id, route, label, x, y, active, marker, step + 1);
      if (active) moving = {line, label: payload};
    }
    const x = compact ? 25 : 27;
    const y = compact ? 924 : 386;
    const width = compact ? 370 : 906;
    packetAnatomy(scene, x, y, width, compact, step);
    const detailY = compact ? 1157 : 526;
    if (step === 2 || step === 3) {
      transportAnatomy(scene, x, detailY, width, compact);
    } else {
      message(scene, x, detailY, width, step === 7 ? "RECEIVER CHECKS" : "DIRECTION MATTERS", compact ? [step === 7 ? "2,048-packet sliding replay window" : "Client tx_key = server receive key", step === 7 ? "Duplicate / stale counter: drop" : "Server send key = client rx_key", step === 7 ? "Invalid AEAD tag: drop" : "Separate counters in both directions", "Rekey threshold: 2³² packets by default", "The website is outside the inner tunnel"] : [step === 7 ? "Duplicate / stale counter → rejected by the 2,048-packet replay window. Invalid tag → rejected by AEAD." : "The two directions use different keys and counters; server send = client receive.", "Default rekey threshold: 2³² packets. Automatic rekey derives another directional key.", "The prrr server terminates inner tunnel encryption; application TLS, when used, is a separate layer."], "receiver");
    }
    return moving;
  }

  function routingScene(scene, step, compact, flow, marker) {
    const boxes = compact ? {
      policy: {x: 50, y: 48, w: 320, h: 213}, tunnel: {x: 50, y: 371, w: 320, h: 185}, internet: {x: 50, y: 677, w: 320, h: 158},
    } : {
      policy: {x: 25, y: 58, w: 260, h: 242}, tunnel: {x: 407, y: 58, w: 230, h: 242}, internet: {x: 744, y: 58, w: 190, h: 242},
    };
    const focus = flow.steps[step][2];
    const policyRows = [
      ["resources: hostname / IPv4", "allowed_ips: explicit prefixes", "all_traffic: full selection", "full_tunnel: LAN bypass off"],
      ["Resolve resource hostname", "Update policy-table /32 routes", "Refresh without pausing packets", "Retain recent DNS answers"],
      ["Mark server transport sockets", "Bypass own tunnel", "Local LAN exception by default", "full_tunnel: LAN bypass off"],
      ["Probe all pinned DNS targets", "No responding tunnel resolver", "Withdraw tunnel DNS", "Host DNS retained"],
      ["Policy still installed", "Outbound progress observed", "No inbound progress", "Watchdog strikes accumulate"],
      ["Route hook: down", "Tunnel policy removed", "Host routes apply", "No traffic-blocking kill switch"],
      ["Route hook: up", "Policy reinstalled", "Resource refresh resumes", "Fresh session keys"],
    ];
    const tunnelRows = [
      ["TUN + encrypted channel", "Configured transport", "Not every packet is selected"],
      ["Matching resource → TUN", "Encrypted IP packet", "Host routing handles rest"],
      ["Server socket fwmark", "No recursive tunnel route", "TUN handles selected traffic"],
      ["DNS health gate closed", "Host DNS retained", "Data pump keeps running"],
      ["Sent packets ↑", "Inbound answers = 0", "Strike limit → reconnect"],
      ["Exponential backoff + jitter", "New hybrid handshake", "Same TUN device"],
      ["Same TUN device", "Same client IP", "Fresh session keys"],
    ];
    actor(scene, "policy", boxes.policy, "Linux routing policy", policyRows[step], focus.includes("policy"));
    actor(scene, "tunnel", boxes.tunnel, "prrr tunnel", tunnelRows[step], focus.includes("tunnel"), "shield");
    actor(scene, "internet", boxes.internet, compact ? "Host route / internet" : "Host route", compact ? ["Server connection / LAN bypass", step === 5 ? "Host routes apply on failure" : "Ordinary network path"] : ["Server socket", "LAN exception", "Host resolver"], focus.includes("internet"));
    const specs = compact ? [
      ["resource", "M160 261V371", "Matched IP → TUN", 180, 322, "IP"],
      ["bypass", "M370 178H399V756H370", "Server / LAN bypass", 55, 624, "HOST"],
      ["dns", "M160 371V261", "Withdraw DNS", 180, 322, "DNS"],
      ["retry", "M160 556V677", "Retry transport", 180, 624, "RETRY"],
      ["restored", "M160 261V371", "Routes restored", 180, 322, "IP"],
    ] : [
      ["resource", "M285 162H407", "Selected IP", 297, 137, "IP"],
      ["bypass", "M155 58V22H839V58", "Server / LAN bypass", 409, 44, "HOST"],
      ["dns", "M407 238H285", "Withdraw DNS", 289, 270, "DNS"],
      ["retry", "M637 162H744", "Reconnect", 640, 137, "RETRY"],
      ["restored", "M285 162H407", "Routes up", 297, 137, "IP"],
    ];
    let moving = null;
    for (const [id, route, label, x, y, payload] of specs) {
      const active = flow.steps[step][3] === id;
      const line = connection(scene, id, route, label, x, y, active, marker, step + 1);
      if (active) moving = {line, label: payload};
    }
    const x = compact ? 25 : 25;
    const y = compact ? 878 : 345;
    const width = compact ? 370 : 909;
    if (step === 3) {
      message(scene, x, y, width, "DNS HEALTH IS MEASURED SEPARATELY", compact ? ["Probe each pinned tunnel resolver", "Any answer → advertise responding servers", "No answers → withdraw tunnel DNS", "Stale verdict → withdraw tunnel DNS", "Keep the host resolver available", "Recovery reopens the gate", "DNS gate is not a privacy kill switch"] : ["One silent DNS target does not suppress another responding resolver.", "No answers, an expired verdict, or a dead prober withdraws tunnel DNS advertisement.", "Host DNS remains available; a later healthy verdict can reopen the gate.", "This protects DNS availability. It does not promise fail-closed traffic or DNS-leak prevention."], "dns-gate");
    } else if (step >= 4) {
      message(scene, x, y, width, "RECOVERY STATE MACHINE", compact ? ["Connected → watchdog or transport failure", "Routes down → jittered backoff", "Connect → fresh hybrid handshake", "Connected → routes up", "TUN interface and client IP persist", "Failed retry doubles the delay to its cap", "Host routes apply during downtime"] : ["Connected → failure detected → routes down → jittered exponential backoff → connect → routes up", "Each successful reconnection starts a new hybrid handshake and a new EncryptedChannel.", "The client retains its TUN and IP. Host routing applies while the tunnel policy is removed.", "A watchdog observes traffic counters, not application correctness or end-to-end website health."], "recovery");
    } else {
      message(scene, x, y, width, "POLICY CONTROLS HAVE DIFFERENT JOBS", compact ? ["resources → resolved destination addresses", "allowed_ips → explicit network prefixes", "all_traffic → select general traffic", "full_tunnel → disable automatic LAN bypass", "fwmark → keep server transport outside TUN", "Excluded traffic uses the host route", "Examples illustrate Linux route hooks"] : ["resources selects resolved destinations; allowed_ips selects explicit prefixes; all_traffic selects general traffic.", "full_tunnel disables automatic LAN exclusions. It is separate from all_traffic.", "Firewall marks keep the server transport on the host path and prevent a routing loop.", "The Linux route-hook policy shown here is distinct from platform-specific Android VPN routing."], "policy");
    }
    return moving;
  }

  function drawScene(root, flow, step, compact, uid) {
    const heights = {handshake: compact ? 932 : 578, packets: compact ? 1408 : 691, routing: compact ? 1156 : 554};
    const height = heights[root.dataset.flow];
    const canvas = svg("svg", {class: "sy-scene", "data-layout": compact ? "portrait" : "landscape", viewBox: "0 0 " + (compact ? 420 : 960) + " " + height, role: "img", "aria-labelledby": uid + "-title " + uid + "-desc"});
    svg("title", {id: uid + "-title"}, canvas).textContent = flow.title + ": " + flow.steps[step][0];
    svg("desc", {id: uid + "-desc"}, canvas).textContent = flow.steps[step][1] + " Labeled paths connect illustrated hosts. All packet counters are examples, not live traffic.";
    const defs = svg("defs", {}, canvas);
    const pattern = svg("pattern", {id: uid + "-grid", width: 24, height: 24, patternUnits: "userSpaceOnUse"}, defs);
    svg("circle", {cx: 1, cy: 1, r: .8, class: "sy-grid-dot"}, pattern);
    rect(canvas, 0, 0, compact ? 420 : 960, height, "", 0, {fill: "url(#" + uid + "-grid)"});
    const marker = svg("marker", {id: uid + "-arrow", viewBox: "0 0 10 10", refX: 8, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse"}, defs);
    path(marker, "M0 0L10 5L0 10z", "sy-arrowhead");
    const renderer = {handshake: handshakeScene, packets: packetsScene, routing: routingScene}[root.dataset.flow];
    const moving = renderer(canvas, step, compact, flow, uid + "-arrow");
    const packetState = moving ? packet(canvas, moving.line, moving.label, compact) : null;
    return {canvas, packetState};
  }
  function mount(root) {
    const flow = flows[root.dataset.flow];
    if (!flow || root.children.length) return;
    const uid = "prrr-story-" + ++instance;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
    let step = 0;
    let playing = false;
    let elapsed = 0;
    let lastTime = null;
    let frameId = null;
    let speed = 1;
    let compact = root.clientWidth < PORTRAIT_BELOW_PX;
    let packetState = null;
    root.setAttribute("role", "group");
    root.setAttribute("aria-label", flow.title + " animated explanation");

    const top = html("div", "sy-mechanics__top");
    const kicker = html("span", "sy-story-label", flow.label);
    const sample = html("span", "sy-story-sample", "Animation · example values");
    top.append(kicker, sample);
    const title = html("p", "sy-mechanics__title", flow.title);
    const screen = html("div", "sy-mechanics__screen");
    const progress = html("div", "sy-mechanics__progress");
    progress.setAttribute("aria-hidden", "true");
    const progressFill = html("span", "");
    progress.append(progressFill);
    const chapters = html("div", "sy-chapters");
    chapters.setAttribute("aria-label", "Explanation chapters");
    const chapterButtons = flow.steps.map((entry, index) => {
      const button = html("button", "sy-chapter");
      button.type = "button";
      const number = html("span", "sy-chapter__number", String(index + 1).padStart(2, "0"));
      button.append(number, html("span", "", entry[0]));
      button.addEventListener("click", () => seek(index));
      chapters.append(button);
      return button;
    });
    const stage = html("div", "sy-mechanics__stage");
    stage.setAttribute("aria-live", "polite");
    stage.setAttribute("aria-atomic", "true");
    const counter = html("div", "sy-mechanics__counter");
    const heading = html("strong", "");
    const description = html("p", "");
    stage.append(counter, heading, description);
    const controls = html("div", "sy-mechanics__controls");
    const play = html("button", "sy-play", "Play");
    const previous = html("button", "", "Previous step");
    const next = html("button", "", "Next step");
    const restart = html("button", "", "Restart");
    for (const button of [play, previous, next, restart]) button.type = "button";
    const speedLabel = html("label", "sy-speed", "Playback speed");
    const speedInput = html("select", "");
    speedInput.setAttribute("aria-label", "Playback speed");
    for (const value of ["0.75", "1", "1.5"]) {
      const option = html("option", "", value + "×");
      option.value = value;
      option.selected = value === "1";
      speedInput.append(option);
    }
    speedLabel.append(speedInput);
    controls.append(play, previous, next, restart, speedLabel);
    const note = html("p", "sy-mechanics__motion-note");
    root.append(top, title, screen, progress, chapters, stage, controls, note);

    function pose(fraction) {
      const progress = (step + (reduced.matches ? 1 : fraction)) / flow.steps.length;
      progressFill.style.transform = "scaleX(" + progress + ")";
      if (!packetState) return;
      const {node, line} = packetState;
      const phase = reduced.matches ? 1 : Math.min(1, Math.max(0, (fraction - .08) / .65));
      const length = line.getTotalLength();
      const point = line.getPointAtLength(length * phase);
      node.setAttribute("transform", "translate(" + point.x + " " + point.y + ")");
      node.style.opacity = reduced.matches ? "0" : String(phase > .92 ? (1 - phase) / .08 : 1);
      line.style.strokeDasharray = String(length);
      line.style.strokeDashoffset = String(length * (1 - phase));
    }

    function pause() {
      playing = false;
      window.cancelAnimationFrame(frameId);
      lastTime = null;
      root.dataset.playing = "false";
      play.textContent = "Play";
      play.setAttribute("aria-pressed", "false");
    }

    function render() {
      root.dataset.step = String(step);
      root.dataset.motion = reduced.matches ? "reduced" : "full";
      const {canvas, packetState: moving} = drawScene(root, flow, step, compact, uid);
      screen.replaceChildren(canvas);
      packetState = moving;
      counter.textContent = "Step " + (step + 1) + " of " + flow.steps.length;
      heading.textContent = flow.steps[step][0];
      description.textContent = flow.steps[step][1];
      chapterButtons.forEach((button, index) => {
        button.dataset.complete = String(index < step);
        if (index === step) button.setAttribute("aria-current", "step");
        else button.removeAttribute("aria-current");
      });
      previous.disabled = step === 0;
      next.disabled = step === flow.steps.length - 1;
      play.disabled = next.disabled && !playing && elapsed >= STEP_MS;
      note.textContent = reduced.matches
        ? "Reduced motion: diagrams stay still. Play advances captions; chapters and step controls work at your pace."
        : "Follow the messages, pause to inspect, or choose any chapter. Illustrated traffic only; no network connection.";
      pose(playing ? elapsed / STEP_MS : 1);
    }

    function seek(index) {
      pause();
      step = index;
      elapsed = step === flow.steps.length - 1 ? STEP_MS : 0;
      render();
    }

    function tick(now) {
      if (!playing) return;
      if (lastTime !== null) elapsed += (now - lastTime) * speed;
      lastTime = now;
      if (elapsed >= STEP_MS) {
        if (step === flow.steps.length - 1) {
          elapsed = STEP_MS;
          pause();
          render();
          return;
        }
        elapsed %= STEP_MS;
        step += 1;
        render();
      }
      pose(elapsed / STEP_MS);
      frameId = window.requestAnimationFrame(tick);
    }

    play.addEventListener("click", () => {
      if (playing) return pause();
      playing = true;
      root.dataset.playing = "true";
      play.textContent = "Pause";
      play.setAttribute("aria-pressed", "true");
      lastTime = null;
      pose(elapsed / STEP_MS);
      frameId = window.requestAnimationFrame(tick);
    });
    previous.addEventListener("click", () => {
      seek(Math.max(0, step - 1));
      if (previous.disabled) next.focus();
    });
    next.addEventListener("click", () => {
      seek(Math.min(flow.steps.length - 1, step + 1));
      if (next.disabled) restart.focus();
    });
    restart.addEventListener("click", () => seek(0));
    speedInput.addEventListener("change", () => { speed = Number(speedInput.value); });
    document.addEventListener("visibilitychange", () => { if (document.hidden) pause(); });
    reduced.addEventListener("change", () => { pause(); render(); });
    new ResizeObserver(() => {
      const narrow = root.clientWidth < PORTRAIT_BELOW_PX;
      if (compact !== narrow) { compact = narrow; render(); }
    }).observe(root);
    pause();
    render();
  }

  function initialize() {
    document.querySelectorAll(".sy-mechanics[data-flow]").forEach(mount);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initialize);
  else initialize();
})();
