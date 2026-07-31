# Changelog

All notable changes to `hft-crypto` are documented here.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.3.1] - 2026-05-29

### Fixed
- **Fix 6** - `examples/agent_demo.rs`: `HftAgent::new()` returns `Result<Self>` — added `.expect(...)` unwrap. Removed broken `.expect("").await` chain that called `.expect` on a `Future` instead of the `Result` (compile error with `ai-agent` feature).
- **Fix 7** - `tests/providers/anthropic.rs`: same `HftAgent::new()` `Result` unwrap missing in all three `#[ignore]` live-provider tests (compile error with `ai-agent` feature).
- **Fix 8** - `src/exchange/bybit.rs`: `from_env` doctest used wrong module path `exchange::BybitAuth` (no re-export at that level); corrected to `exchange::bybit::BybitAuth`. Removed orphan inline comment in `from_env` body.
- **Fix 9** - `src/exchange/coinbase.rs`, `kraken.rs`, `bybit.rs`: removed duplicate/orphan impl-level doc blocks that mirrored struct-level docs verbatim; cleaned up `new`/`from_env` doc comments.
- **Fix 10** - `src/exchange/auth.rs`: removed `std::env::set_var` from runnable doctest on `HmacCredentials::from_env`; changed to `no_run`. `set_var` in multithreaded doctests is unsound in Rust 2024 and fails `cargo doc -D warnings` in CI.

---

## [0.3.0] - 2026-05-29

### Changed
- `Cargo.toml` - license changed from proprietary `LicensePBS` to `MIT OR Apache-2.0` (valid SPDX) for crates.io publication
- `README.md` - updated license badge and License section to reflect dual MIT/Apache-2.0 licensing

### Added
- `LICENSE-MIT` - MIT license text
- `LICENSE-APACHE` - Apache License 2.0 text
- `tests/providers/mod.rs` - module file making `tests/providers/anthropic.rs` discoverable by the test harness

### Fixed
- `src/exchange/binance.rs` - removed triplicated copy-paste doc comments on `BinanceAuth::new` and `from_env`; impl-level doc block removed (duplicated struct-level doc)
- `src/exchange/okx.rs` - removed redundant impl-level doc block on `OkxCredentials` and `OkxAuth`; cleaned up inline comments inside function parameter lists (non-standard Rust style)
- `src/exchange/kucoin.rs` - same doc comment cleanup as okx.rs; removed duplicate `# Panics` sections and inline parameter comments
- `.zed/settings.json` - removed `"git"` block (global-only Zed setting; rejected by schema at project level per Zed docs); moved note directing to `~/.config/zed/settings.json`

---

## [0.2.0] - 2026-05-16

### Added
- `rustfmt.toml` - code-style rules (100 cols, Rust 2024 edition, crate-level imports)
- `.clippy.toml` - Clippy config with MSRV 1.93.1 and complexity thresholds
- `.env.example` - template for all 7 exchange API keys + Anthropic key
- `LICENSE-PBS` - mAI (🧠) proprietary licence
- `CHANGELOG.md` - this file
- `CONTRIBUTING.md` - contribution guide with full workflow
- `FILE_STRUCTURE.md` - annotated repository map
- `BUG-FIXES.md` - root-cause analysis of resolved issues
- `docs/architecture.md` - system architecture deep-dive with ASCII diagram
- `docs/dsa_math.md` - detailed ECDSA and Ed25519 mathematical commentary
- `examples/crypto_demo.rs` - standalone ECDSA + Ed25519 + HMAC demo
- `examples/exchange_demo.rs` - 7-exchange signed request demo
- `examples/agent_demo.rs` - Rig AI agent demo (requires `ai-agent` feature)
- `tests/providers/anthropic.rs` - live Anthropic integration tests (`#[ignore]`)
- `.zed/tasks.json` / `debug.json` - Zed IDE task and debug config

### Changed
- `Cargo.toml` - upgraded to **Rust 2024 edition**; added `rust-version = "1.93.1"` (MSRV),
  `[package.metadata.docs.rs]`, and `[lints]` tables; relaxed `=` exact version pins to
  `^` (semver-compatible) for all deps; bumped `thiserror` to `^2`; added `dotenvy ^0.15`;
  added `[profile.release]` with LTO + single-codegen-unit (mirrors rig upstream)
- `.github/workflows/ci.yml` - added MSRV check step, `cargo doc` validation, `--workspace`
  flag on test, improved cache key, added `ai-agent` feature build step
- `.gitignore` - consolidated with focused, Rust-only ignore rules matching rig-hft

### Fixed
- **Fix 1** - `src/agent/hft_agent.rs`: removed `Arc<anthropic::Client>` wrapper.
  `Client::from_env()` in rig-core 0.37 returns a bare `Client`; wrapping in `Arc` produced
  `Arc<Client>` on which `.agent()` could not be resolved. Removed `use std::sync::Arc`.
- **Fix 2** - `src/agent/hft_agent.rs`: added `rig::client::{CompletionClient, ProviderClient}`
  to the `use` import. Both traits must be in scope for `.agent()` to resolve in rig-core ≥ 0.36.

---

## [0.1.0] - 2025-01-01

Initial release:

- ECDSA (secp256k1) forward-engineering from FIPS 186-5
- Ed25519 (Curve25519) forward-engineering from RFC 8032
- HMAC-SHA256 / HMAC-SHA512 implementations validated against NIST RFC 4231 §4.2 vectors
- 7-exchange REST API authentication: Binance, Kraken, OKX, Bybit, Coinbase, KuCoin, Hyperliquid
- `ExchangeAuth` trait for uniform sign/verify interface
- Rig (ARC) `HftAgent` integration behind `ai-agent` feature flag
- 52 passing unit + integration tests
- GitHub Actions CI: fmt → clippy → build → test
