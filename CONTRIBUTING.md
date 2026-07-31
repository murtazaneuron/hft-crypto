# Contributing to hft-crypto

> **mAI (🧠)** · Technology Lead: Murtaza Ali Imtiaz  
> This repository is published under a restricted proprietary licence for
> portfolio and reference purposes. See [LICENSE-PBS](./LICENSE-PBS) for permitted use.

---

## Development environment

### Prerequisites

| Tool | Version | Install |
|---|---|---|
| Rust stable toolchain | ≥ 1.93.1 (MSRV) | `rustup update stable` |
| `rustfmt` | (with toolchain) | `rustup component add rustfmt` |
| `clippy` | (with toolchain) | `rustup component add clippy` |

### Setup

```text
git clone https://github.com/murtazaai/hft-crypto
cd hft-crypto
cp .env.example .env
# Edit .env: set ANTHROPIC_API_KEY=sk-ant-... (only needed for ai-agent feature)
```

---

## Workflow

### Build

```text
cargo build                          # debug
cargo build --release                # optimised (use for benchmarks)
cargo build --features ai-agent      # include Rig AI agent module
```

### Run

```text
# Full demo (dry-run): ECDSA + Ed25519 + all 7 exchanges
cargo run

# Crypto primitives only
cargo run -- crypto

# 7-exchange signed requests only
cargo run -- exchanges

# Help
cargo run -- --help
```

### Examples

```text
cargo run --example crypto_demo
cargo run --example exchange_demo
cargo run --example agent_demo --features ai-agent   # requires ANTHROPIC_API_KEY
```

### Tests (no API key required)

```text
cargo test                                        # all deterministic tests
cargo test --test crypto_tests                    # crypto primitives only
cargo test --test exchange_auth_tests             # all 7 exchanges
```

### Live provider tests (API key required)

```text
ANTHROPIC_API_KEY=sk-ant-... \
    cargo test --test providers --features ai-agent -- --ignored --test-threads=1
```

Use `--test-threads=1` to avoid concurrent API calls hitting rate limits.

### Format, lint, docs

```text
cargo fmt --all                                   # format
cargo fmt --all -- --check                        # CI format check
cargo clippy --all-targets -- -D warnings         # lint (CI mode)
cargo clippy --all-targets --features ai-agent -- -D warnings
cargo doc --open                                  # browse API docs locally
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo doc # CI docs check
```

---

## Code style

- **Edition**: Rust 2024
- **Max line width**: 100 characters (enforced by `rustfmt.toml`)
- **Imports**: `use rig_core::client::{CompletionClient, ProviderClient}` - both traits are
  required to call `.agent()` on any rig-core ≥ 0.36 Anthropic client
- **Doc comments**: `//!` for module-level docs; `///` for items; never `///` or `/** */`
  on macro invocation sites (triggers `unused_doc_comments`)
- **Error handling**: always `anyhow::Result`; propagate with `?`; no `unwrap` in library code
- **Version pins**: use `^` (semver-compatible) for all dependencies; never `=` exact pins
  in production code

---

## Adding a new exchange adapter

1. Add any required SDK crate to `Cargo.toml`
2. Create `src/exchange/<exchange>.rs` implementing the `ExchangeAuth` trait
3. Declare `pub mod <exchange>;` in `src/exchange/mod.rs`
4. Add fixture helper and tests in `tests/exchange_auth_tests.rs`
5. Add the exchange to `demo_exchanges()` in `examples/exchange_demo.rs`
6. Document the signing scheme in the module-level `//!` doc comment (see existing files)
7. Update `docs/architecture.md` and `README.md` exchange table

---

## CI

The CI pipeline (`.github/workflows/ci.yml`) runs on every push and pull request:

1. `rustfmt --check` - enforces code style
2. `clippy -D warnings` - enforces lint rules (default + ai-agent features)
3. `cargo build --release` - ensures the release binary compiles
4. `cargo test --workspace` - runs all deterministic tests
5. `cargo doc` - ensures documentation compiles without warnings
6. MSRV check against Rust 1.93.1
