#!/usr/bin/env python3
"""Check documented CLI workflows without root, VPN connections, or existing credentials.

FRD: specs/frds/FRD-illustrated-documentation.md
Build `cargo build --locked --bin prrr`, then run with Python 3.11 or newer.
Generated client credentials remain in a private temporary directory and are
deleted at exit. No server or VPN session is started.
"""

import argparse
import base64
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]
CLIENT_NAME = "docs-client"
SERVER_NAME = "vpn.example.net"
SERVER_PORT = 1443
KEY_BYTES = 32
KEM_PUBLIC_KEY_BYTES = 1184
DEFAULT_MTU = 1100
TOML_FENCE = re.compile(r"^```toml[^\n]*\n(.*?)^```\s*$", re.MULTILINE | re.DOTALL)


def check_toml_examples():
    """Parse canonical site examples; legacy documents are not published."""
    pages = [ROOT / "docs/index.md"]
    for section in ("tutorials", "how-to", "reference", "explanation", "contributing"):
        pages.extend(sorted((ROOT / "docs" / section).rglob("*.md")))
    count = 0
    for page in pages:
        if not page.exists():
            continue
        for index, match in enumerate(TOML_FENCE.finditer(page.read_text()), 1):
            try:
                tomllib.loads(match.group(1))
            except tomllib.TOMLDecodeError as error:
                raise AssertionError(f"Invalid TOML example {page.relative_to(ROOT)} #{index}") from error
            count += 1
    return count


def check_cli(binary):
    """Exercise provisioning, import, routing edits, sharing and revocation."""
    with tempfile.TemporaryDirectory(prefix="prrr-docs-") as temporary:
        fixture = Path(temporary)
        env = {key: value for key, value in os.environ.items() if not key.startswith("PRRR_")}
        env.update(HOME=str(fixture), RUST_LOG="error")

        def run(*arguments):
            result = subprocess.run(
                [str(binary), *map(str, arguments)], cwd=fixture, env=env,
                capture_output=True, text=True, timeout=30, check=False,
            )
            # Never include captured config output in failure messages.
            assert result.returncode == 0, f"CLI failed ({result.returncode}): {' '.join(map(str, arguments))}"
            return result.stdout

        helps = [(), ("server",), ("server", "client"), ("client",),
                 ("client", "route"), ("sharing",)]
        for command in helps:
            assert "Usage:" in run(*command, "--help"), f"Missing help for {command}"
        for command in ("add", "list", "remove", "export"):
            assert "Usage:" in run("server", "client", command, "--help")
        for command in ("add", "list", "remove"):
            assert "Usage:" in run("client", "route", command, "--help")
        for command in ("enable", "disable", "status"):
            assert "Usage:" in run("sharing", command, "--help")
        assert "Usage:" in run("client", "import", "--help")

        data = fixture / "data"
        data.mkdir()
        server_config = fixture / "server.toml"
        basic_config = (
            f'[server]\ndata_dir = "{data.as_posix()}"\n'
            f'[crypto]\nidentity_key_path = "{fixture.as_posix()}/identity.key"\n'
            f'pq_key_path = "{fixture.as_posix()}/pq.key"\n'
        )
        server_config.write_text(basic_config + '\n[[transports]]\nname = "harp"\nenabled = true\n')
        server = ("server", "--config", server_config, "--server-name", SERVER_NAME,
                  "--listen", f"127.0.0.1:{SERVER_PORT}", "client")

        generated_text = run(*server, "add", CLIENT_NAME)
        generated = tomllib.loads(generated_text)
        assert generated["server"]["endpoint"] == f"{SERVER_NAME}:{SERVER_PORT}"
        assert generated["server"]["server_name"] == SERVER_NAME
        for section, field, length in (
            ("interface", "private_key", KEY_BYTES),
            ("server", "public_key", KEY_BYTES),
            ("server", "pq_public_key", KEM_PUBLIC_KEY_BYTES),
        ):
            assert len(base64.b64decode(generated[section][field], validate=True)) == length, field
        assert generated["interface"]["mtu"] == DEFAULT_MTU
        assert generated["interface"]["transport_protocol"] == "harp"
        assert CLIENT_NAME in run(*server, "list")

        private_config = fixture / "client.toml"
        private_config.write_text(generated_text)
        private_config.chmod(0o600)
        run("client", "import", private_config)
        imported_path = fixture / ".config/prrr/client.toml"
        assert imported_path.read_text() == generated_text, "Import changed the generated config"

        client = ("client", "--config", imported_path, "route")
        run(*client, "add", "docs.example.net")
        run(*client, "add", "192.0.2.10")
        assert set(run(*client, "list").splitlines()) == {"docs.example.net", "192.0.2.10"}
        run(*client, "add", "docs.example.net")
        assert run(*client, "list").count("docs.example.net") == 1, "Duplicate route was stored"
        run(*client, "remove", "docs.example.net")
        assert run(*client, "list").strip() == "192.0.2.10"
        assert tomllib.loads(imported_path.read_text())["interface"]["private_key"] == generated["interface"]["private_key"]

        exported = tomllib.loads(run(*server, "export", CLIENT_NAME))
        assert "private_key" not in exported.get("interface", {}), "Export unexpectedly contains a private key"
        assert exported["server"]["public_key"] == generated["server"]["public_key"]
        run(*server, "remove", CLIENT_NAME)
        assert CLIENT_NAME not in run(*server, "list"), "Revoked client remains active"

        # Capture the existing fallback explicitly so docs cannot silently
        # assume a generated client uses the server's implicit HARP default.
        server_config.write_text(basic_config)
        fallback = tomllib.loads(run(*server, "add", "fallback-client"))
        assert fallback["interface"]["transport_protocol"] == "masque"

        assert "disabled" in run("sharing", "status")
        run("sharing", "enable")
        assert "enabled" in run("sharing", "status")
        run("sharing", "disable")
        assert "disabled" in run("sharing", "status")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/prrr")
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"Missing {binary}; run cargo build --locked --bin prrr first")
    toml_count = check_toml_examples()
    check_cli(binary)
    print(f"Documentation examples passed: {toml_count} TOML fences; real CLI help, provisioning, import, "
          "route edits, public export, revocation, transport fallback and sharing state. "
          "No VPN connection or system routing change.")


if __name__ == "__main__":
    main()
