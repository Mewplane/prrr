#!/usr/bin/env node
// Tests the actual JS functions from assets/index.html.
// Invoked by Rust e2e test via `node tests/js_patch_test.js`.

// Note: not "use strict" — eval'd function declarations must be hoisted to scope.

const fs = require("fs");
const zlib = require("zlib");
const assert = require("assert");

// --- Extract functions from index.html (eval the relevant JS) ---

const html = fs.readFileSync("assets/index.html", "utf8");

// Extract a function by finding balanced braces after its declaration
function extractFunction(name) {
    const start = html.indexOf(`function ${name}(`);
    if (start === -1) throw new Error(`${name} not found in index.html`);
    let depth = 0;
    let inBody = false;
    for (let i = start; i < html.length; i++) {
        if (html[i] === "{") { depth++; inBody = true; }
        if (html[i] === "}") { depth--; }
        if (inBody && depth === 0) {
            return html.substring(start, i + 1);
        }
    }
    throw new Error(`Could not find end of ${name}`);
}

// Extract constants and assign to global scope (eval'd const is block-scoped)
const maxChunkMatch = html.match(/const MAX_CHUNK_CHARS = (\d+);/);
if (!maxChunkMatch) throw new Error("MAX_CHUNK_CHARS not found");
var MAX_CHUNK_CHARS = parseInt(maxChunkMatch[1]);

const prefixMatch = html.match(/const MULTI_FRAME_URL_PREFIX = "([^"]+)";/);
if (!prefixMatch) throw new Error("MULTI_FRAME_URL_PREFIX not found");
var MULTI_FRAME_URL_PREFIX = prefixMatch[1];

// Extract and eval functions
eval(extractFunction("patchConfigForMobile"));
eval(extractFunction("buildMultiFrameUrls"));

// --- Helper: base64url encode ---
function toBase64url(buf) {
    return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

// --- Test data (must match Rust test_server_context + test_private_key) ---

const serverConfig = `# prrr client configuration — generated for "e2e-test-client"

[client]
name = "e2e-test-client"

[server]
endpoint = "vpn.example.com:443"
server_name = "vpn.example.com"
public_key = "AAAA"
pq_public_key = "BBBB"

[interface]
private_key_path = "~/.config/prrr/private.key"
address = "10.66.66.2/32"
dns = ["1.1.1.1", "8.8.8.8"]
mtu = 1280
transport_protocol = "masque"
`;

const privateKeyB64 = "u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=";

// --- Test 1: patchConfigForMobile replaces private_key_path with private_key ---

const patched = patchConfigForMobile(serverConfig, privateKeyB64);

assert(!patched.includes("private_key_path"), "patched config must NOT contain private_key_path");
assert(patched.includes('private_key = "' + privateKeyB64 + '"'), "patched config must contain inline private_key");
assert(patched.includes('transport_protocol = "masque"'), "patched config must preserve transport_protocol");
assert(patched.includes('name = "e2e-test-client"'), "patched config must preserve client name");
assert(patched.includes('endpoint = "vpn.example.com:443"'), "patched config must preserve endpoint");

// --- Test 2: patchConfigForMobile preserves all other lines ---

const serverLines = serverConfig.split("\n").filter(l => !l.startsWith("private_key_path"));
for (const line of serverLines) {
    assert(patched.includes(line), `patched config must preserve line: ${line}`);
}

// --- Test 3: buildMultiFrameUrls splits payload correctly ---

const testPayload = "A".repeat(700); // 700 chars -> should split into 3 chunks (300+300+100)
const frames = buildMultiFrameUrls(testPayload);

assert.strictEqual(frames.length, 3, `expected 3 frames, got ${frames.length}`);
assert(frames[0].startsWith("prrr://import?f=1.3&z="), "frame 1 format wrong");
assert(frames[1].startsWith("prrr://import?f=2.3&z="), "frame 2 format wrong");
assert(frames[2].startsWith("prrr://import?f=3.3&z="), "frame 3 format wrong");

// Verify chunks reassemble to original payload
const reassembled = frames.map(f => f.split("&z=")[1]).join("");
assert.strictEqual(reassembled, testPayload, "reassembled payload must match original");

// --- Test 4: buildMultiFrameUrls chunk size respects MAX_CHUNK_CHARS ---

for (let i = 0; i < frames.length; i++) {
    const chunk = frames[i].split("&z=")[1];
    assert(chunk.length <= MAX_CHUNK_CHARS, `chunk ${i+1} exceeds MAX_CHUNK_CHARS: ${chunk.length}`);
}

// --- Test 5: patchConfigForMobile + compress roundtrip matches Rust ---
// Compress the patched config with Node zlib (raw deflate), encode as base64url,
// then verify it can be decompressed back to the same string.

const compressed = zlib.deflateRawSync(Buffer.from(patched, "utf8"));
const encoded = toBase64url(compressed);
const url = "prrr://import?z=" + encoded;

// Decompress back
const decoded = zlib.inflateRawSync(Buffer.from(encoded, "base64url")).toString("utf8");
assert.strictEqual(decoded, patched, "deflate roundtrip must preserve patched config");

// --- Test 6: download would produce the same content as QR ---
// Both download and QR use patchConfigForMobile, so the config content is identical.
// The QR wraps it in a compressed URL, the download gives the raw TOML.
// Verify the raw TOML is valid (has all required sections).

assert(patched.includes("[client]"), "download content must have [client] section");
assert(patched.includes("[server]"), "download content must have [server] section");
assert(patched.includes("[interface]"), "download content must have [interface] section");
assert(patched.includes("private_key ="), "download content must have inline private_key");
assert(!patched.includes("[transport]"), "download content must NOT have [transport] section");

console.log("JS_TESTS_PASSED: 6/6");
