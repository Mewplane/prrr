# Contributing to prrr

Thank you for your interest in contributing to prrr. This document covers development setup, coding standards, and the process for submitting changes.

## Development Setup

### Prerequisites

- Rust 1.85+ (edition 2024)
- Git
- `shellcheck` (for linting installation scripts)
- `cargo-audit` (for dependency auditing)

### Building

```bash
git clone https://github.com/prrr-vpn/prrr.git
cd prrr
cargo build --release
```

### Running Tests

```bash
make test          # All tests
make testv         # All tests with stdout output
make lint          # Clippy + format check + cargo audit
make bench         # Performance benchmarks
make shellcheck    # Lint installation scripts
```

All tests run without root privileges using `MockTun` (a channel-based TUN device simulator).

### Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build release binary |
| `make test` | Run all tests |
| `make testv` | Run tests with verbose output |
| `make lint` | Clippy, format check, cargo audit |
| `make fmt` | Auto-format code |
| `make bench` | Run benchmarks |
| `make shellcheck` | Lint shell scripts |
| `make clean` | Clean build artifacts |

## Code Standards

### Non-Negotiable Rules

- **No clippy warnings.** `cargo clippy -- -D warnings` must pass.
- **No dead code.** If it is unused, delete it.
- **No unsafe code.** `#![deny(unsafe_code)]` is enforced project-wide.
- **No `#[allow(...)]` attributes.** Fix the issue instead of suppressing the warning.
- **No `.unwrap()` in production code.** Use typed error handling with `thiserror` or `anyhow`.
- **Tests come first.** Write tests alongside or before implementation, never after.

### Style

- Rust edition 2024 with standard formatting (`cargo fmt`).
- Doc comments on all public items.
- Error types use `thiserror` with descriptive messages.
- Structured logging via `tracing` (not `println!`).
- Constants for all string/numeric literals in production code.

### Architecture

- Clean architecture: domain logic first, adapters second, frameworks last.
- Traits at module boundaries only. Concrete types internally.
- Small modules with clear responsibilities.
- Dependency injection, no globals.

## Test Expectations

### Coverage

- Critical paths (crypto, handshake, transport): 90%+
- Overall: 85%+
- New code: 90%+

### Test Types

- **Unit tests** in `mod tests` blocks within source files
- **Integration tests** in `tests/` directory
- **Benchmarks** in `benches/` directory

### Test Patterns

- Test behavior, not implementation details.
- Use `MockTun` and `MockTunFactory` for tunnel tests.
- Parameterized tests with `test-case` when testing variations.
- Test names read like requirements (e.g., `unauthorized_client_receives_decoy`).

## Submitting Changes

### Before Submitting

1. Run `make test` -- all tests pass
2. Run `make lint` -- zero warnings
3. Run `cargo fmt --check` -- code is formatted
4. Update documentation in `docs/` if the change affects user-facing behavior
5. Update `AGENTS.md` if contracts or conventions changed

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): subject (imperative, 72 chars max)

Body: explain why, not what.
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`

Scopes match module names: `crypto`, `handshake`, `transport`, `tunnel`, `server`, `client`, `registry`, `web`, `obfuscation`, `messaging`, `metrics`, `diagnostics`, `cli`, `config`, `distribution`

Examples:

```
feat(registry): add per-client traffic counters

Track bytes_sent and bytes_received using AtomicU64 counters
in TunnelPipeline, persisted to SQLite on disconnect.
```

```
fix(server): install crypto provider before QUIC operations

rustls CryptoProvider was only initialized in test code.
Production main() crashed on startup without ring provider.
```

### Feature Development

For non-trivial features, follow the project's development workflow:

1. Create a Feature Requirements Document at `specs/frds/FRD-<id>.md`
2. Write tests first (micro-TDD: one failing test -> minimal code -> reflect -> repeat)
3. Implement the minimum code to pass tests
4. Run `make lint` until clean
5. Update `docs/` with usage notes and examples
6. Add traceability links between FRD, implementation files, and roadmap

## Project Structure

```
src/                   # Library and binary source
  main.rs              # Binary entry point
  lib.rs               # Library root
  *.rs                 # Core modules
  crypto/              # Cryptographic primitives
  handshake/           # Noise IK + hybrid handshake
  transport/           # QUIC, MASQUE, encrypted channels
  tunnel/              # TUN device, pipeline
  obfuscation/         # TLS mimicry, padding, probe resistance
  messaging/           # Whisper messaging
  web/                 # REST API, auth, SPA frontend
tests/                 # Integration tests
benches/               # Performance benchmarks
specs/                 # Specifications
  frds/                # Feature requirements documents
  production/          # Production roadmap
docs/                  # User-facing documentation
scripts/               # Installation scripts
deploy/                # Deployment (Terraform)
assets/                # Embedded frontend
```

## Reporting Issues

Open an issue on GitHub with:

- Steps to reproduce
- Expected behavior
- Actual behavior
- Platform and Rust version
- Relevant logs (`--log-level debug`)

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
