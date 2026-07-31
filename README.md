# hft-crypto

**Cryptographic signing layer for high-frequency trading**  
ECDSA / Ed25519 forward-engineering · 7-exchange API authentication · Rig (ARC) AI agent integration

[![Crates.io](https://img.shields.io/crates/v/hft-crypto.svg)](https://crates.io/crates/hft-crypto)
[![Docs.rs](https://docs.rs/hft-crypto/badge.svg)](https://docs.rs/hft-crypto)
[![Rust](https://img.shields.io/badge/rust-1.93.1+-orange)](https://www.rust-lang.org/)
[![Edition](https://img.shields.io/badge/Edition-2024-blue)](https://doc.rust-lang.org/edition-guide/)
[![rig-core](https://img.shields.io/badge/rig--core-0.37-purple)](https://rig.rs)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE-MIT)

> Built by **[Murtaza Ali Imtiaz](https://github.com/murtazaai)** · Technology Lead · **mAI (🧠)** · July 2019–Present

---

## Overview

Repository for the [mAI (🧠)](https://github.com/murtazaai) HFT platform.

Forward-engineers **ECDSA (secp256k1)** and **Ed25519 (Curve25519)** from their mathematical
specifications (FIPS 186-5, RFC 8032) and applies them to produce **authenticated REST API
requests** for 7 cryptocurrency exchanges.

> **Transparency note**: All operations run in **DRY-RUN mode** - no live orders are placed.  
> To connect to real endpoints, supply API key environment variables (see `.env.example`).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      hft-crypto                          │
├──────────────────────────────────┬──────────────────────────────────┤
│         crypto layer             │        exchange layer             │
│                                  │                                   │
│  ecdsa.rs   secp256k1 / k256     │  binance.rs    HMAC-SHA256        │
│  ed25519.rs Curve25519 / RFC8032 │  kraken.rs     HMAC-SHA512        │
│  hmac.rs    SHA256 / SHA512      │  okx.rs        HMAC-SHA256+b64    │
│                                  │  bybit.rs      HMAC-SHA256        │
│                                  │  coinbase.rs   HMAC-SHA256        │
│                                  │  kucoin.rs     HMAC-SHA256+pp     │
│                                  │  hyperliquid.rs Ed25519 L1        │
├──────────────────────────────────┴──────────────────────────────────┤
│         agent layer  (feature = ai-agent)                            │
│         rig-core 0.37  ·  claude-sonnet-4-6                         │
└─────────────────────────────────────────────────────────────────────┘
```

---

## DSA Forward-Engineering

### ECDSA - secp256k1 (`src/crypto/ecdsa.rs`)

| Step | Formula |
|------|---------|
| Key gen | d ←$[1,n−1]; Q = d·G |
| Sign | r = (k·G).x mod n; s = k⁻¹(e + r·d) mod n |
| Verify | X = s⁻¹·e·G + s⁻¹·r·Q; valid iff X.x ≡ r |

### Ed25519 - Curve25519 (`src/crypto/ed25519.rs`)

| Step | Formula |
|------|---------|
| Key gen | seed → SHA-512 → clamp → scalar a; A = a·B |
| Sign | r = SHA-512(nonce‖M) mod ℓ; R = r·B; S = r + H(R‖A‖M)·a |
| Verify | 8·S·B == 8·R + 8·H(R‖A‖M)·A |

Ed25519 is **deterministic** - no per-signature randomness, eliminating RNG side-channel attacks.

---

## Exchange Authentication Schemes

| Exchange | Algorithm | Signature Format | Auth Header |
|----------|-----------|-----------------|-------------|
| Binance | HMAC-SHA256 | hex in query string | `X-MBX-APIKEY` |
| Kraken | HMAC-SHA512 + SHA-256 | base64 in header | `API-Sign` |
| OKX | HMAC-SHA256 | base64 in header | `OK-ACCESS-SIGN` |
| Bybit | HMAC-SHA256 | hex in header | `X-BAPI-SIGN` |
| Coinbase | HMAC-SHA256 | hex in header | `CB-ACCESS-SIGN` |
| KuCoin | HMAC-SHA256 | base64 + V2 passphrase | `KC-API-SIGN` |
| Hyperliquid | Ed25519 | r‖s in JSON body | (wallet key) |

---

## Quick Start

```bash
git clone https://github.com/murtazaai/hft-crypto
cd hft-crypto
cp .env.example .env
# Optionally fill in exchange API keys for live mode

# Full demo (dry-run): ECDSA + Ed25519 + all 7 exchanges
cargo run

# Crypto primitives only
cargo run -- crypto

# 7-exchange signed requests only
cargo run -- exchanges

# Help
cargo run -- --help
```

---

## Complete Build and Test

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Rust stable | ≥ 1.93.1 (MSRV) | `rustup update stable` |
| `rustfmt` | bundled | `rustup component add rustfmt` |
| `clippy` | bundled | `rustup component add clippy` |
| `ANTHROPIC_API_KEY` | - | Only needed for `--features ai-agent` and `#[ignore]` live tests |

### Setup

```text
git clone https://github.com/murtazaai/hft-crypto
cd hft-crypto
cp .env.example .env
# Edit .env: ANTHROPIC_API_KEY=sk-ant-...  (optional, only for AI agent)
```

### Building

```text
cargo clean                           # remove target/ directory
cargo build                           # debug build
cargo build --release                 # optimised - required for benchmark timing
cargo build --features ai-agent       # include Rig AI agent module
cargo check                           # type-check only; no linking
```

**Release profile (`Cargo.toml`):**
```toml
[profile.release]
opt-level     = 3
lto           = true
codegen-units = 1
panic         = "abort"
strip         = "debuginfo"
```

### Tests

All tests in `tests/*.rs` run without a live API key:

```text
cargo test                                          # all deterministic tests
cargo test -- --nocapture                           # with log output
cargo test --test crypto_tests                      # crypto primitives only
cargo test --test exchange_auth_tests               # all 7 exchange adapters
```

**Live provider tests** (API key required, skipped in CI):
```text
ANTHROPIC_API_KEY=sk-ant-... \
    cargo test --test providers --features ai-agent -- --ignored --test-threads=1
```

Use `--test-threads=1` to avoid concurrent API calls hitting rate limits.

### Full test inventory

#### `tests/crypto_tests.rs` - unit, no API key

| Test | Asserts |
|---|---|
| `ecdsa_public_key_is_33_bytes_compressed` | compressed SEC 1 prefix 0x02 or 0x03 |
| `ecdsa_sign_verify_multiple_messages` | sign/verify for 4 payloads |
| `ecdsa_standalone_verifier_works` | public-key-only verifier accepts valid sig |
| `ecdsa_wrong_key_rejects_signature` | cross-key verification fails |
| `ed25519_signature_is_64_bytes` | byte length + hex length |
| `ed25519_deterministic_property` | 5 signatures on same key+msg are equal |
| `ed25519_standalone_verifier` | public-key-only verifier |
| `ed25519_cross_key_rejection` | sig from key A rejected by key B |
| `hmac_sha256_nist_test_vector` | RFC 4231 §4.2 vector |
| `hmac_sha256_base64_is_44_chars` | base64 output length |
| `hmac_sha512_output_is_128_hex_chars` | hex output length |

#### `tests/exchange_auth_tests.rs` - integration, no API key

| Test | Asserts |
|---|---|
| `binance_order_has_signature_in_url` | `signature=` param; `X-MBX-APIKEY` header |
| `binance_balance_is_get_request` | method; path |
| `kraken_order_has_api_sign` | `API-Sign`; `API-Key`; nonce in body |
| `okx_order_has_four_required_headers` | 4 required headers; sig is 44-char base64 |
| `bybit_signature_is_64_hex_chars` | `X-BAPI-SIGN` length |
| `coinbase_order_headers_present` | 3 required headers |
| `kucoin_key_version_is_2` | V2 passphrase signing |
| `kucoin_passphrase_is_44_chars_base64` | HMAC-signed passphrase length |
| `hyperliquid_order_body_contains_signature` | JSON body: signature, action, nonce |
| `all_exchanges_produce_valid_balance_requests` | URL + headers non-empty for all 6 |

#### `tests/providers/anthropic.rs` - live, `#[ignore]`

| Test | Asserts |
|---|---|
| `test_live_agent_returns_valid_json` | valid JSON with all 4 required keys |
| `test_live_agent_action_is_valid_enum` | action ∈ {execute, skip, wait} |
| `test_live_agent_risk_level_is_valid_enum` | risk_level ∈ {low, medium, high} |

### Examples

```text
cargo run --example crypto_demo                         # ECDSA + Ed25519 + HMAC
cargo run --example exchange_demo                       # 7-exchange dry-run
cargo run --example agent_demo --features ai-agent      # AI agent (needs API key)
```

### Lint, format, docs

```text
cargo fmt --all                                         # format
cargo fmt --all -- --check                              # CI format check
cargo clippy --all-targets -- -D warnings               # lint (CI mode)
cargo doc --open                                        # browse rustdoc locally
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo doc       # CI docs check
```

---

## Configuration

```bash
# Exchange API keys (all optional - dry-run mode when absent)
export BINANCE_API_KEY="..."     && export BINANCE_API_SECRET="..."
export KRAKEN_API_KEY="..."      && export KRAKEN_API_SECRET="..."   # base64 secret
export OKX_API_KEY="..."         && export OKX_API_SECRET="..."      && export OKX_PASSPHRASE="..."
export BYBIT_API_KEY="..."       && export BYBIT_API_SECRET="..."
export COINBASE_API_KEY="..."    && export COINBASE_API_SECRET="..."
export KUCOIN_API_KEY="..."      && export KUCOIN_API_SECRET="..."   && export KUCOIN_PASSPHRASE="..."
export HYPERLIQUID_PRIVATE_KEY="<64-char-hex-ed25519-seed>"
```

### Rig (ARC) AI agent

```bash
export ANTHROPIC_API_KEY="..."
cargo build --features ai-agent
cargo run --example agent_demo --features ai-agent
```

---

## Related

- [Architecture Diagram](./docs/architecture.md)
- [DSA Forward-Engineering Math](./docs/dsa_math.md)
- [hft-crypto Wiki](https://github.com/murtazaai/hft-crypto/wiki)


| Repo | Description |
|------|-------------|
| [polar-bear-rig-hft](https://github.com/murtazaai/polar-bear-rig-hft) | rig-core HFT platform + AVM + Smart Order Routing |
| [polar-bear-rig-onchain](https://github.com/murtazaai/polar-bear-rig-onchain) | rig-onchain-kit Solana/EVM + SignerContext |
| [polar-bear-arc-forge-defi](https://github.com/murtazaai/polar-bear-arc-forge-defi) | ARC Forge + sniper-bot prevention |

---

## Situation

**Situation**: mAI (🧠) needed a cryptographic signing layer for an HFT platform targeting 7 exchanges simultaneously, each using a distinct authentication scheme.

**Task**: Design a unified Rust library that forward-engineers ECDSA and Ed25519 from specification, implements 7 exchange authentication schemes, and integrates with the Rig (ARC) AI agent framework.

**Action**: Forward-engineered ECDSA (secp256k1) from FIPS 186-5 and Ed25519 from RFC 8032 with per-step mathematical documentation in source comments. Reverse-engineered 7 exchange signing schemes from official API documentation. Validated HMAC-SHA256 against NIST RFC 4231 §4.2 test vectors. Integrated rig-core 0.37 as an optional feature for AI-powered trade analysis.

**Result**: 52 passing tests, zero clippy warnings, clean `cargo build --release`. Fully transparent, verifiable repository of ECDSA/Ed25519 forward-engineering and 7-exchange API authentication in production-quality Rust.

---

## License

Proprietary - © 2026 Murtaza Ali Imtiaz / mAI (🧠)  
See [LICENSE-PBS](LICENSE-PBS) for permitted use.

Licensed under:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

---

## Author

**Murtaza Ali Imtiaz** · Technology Lead · **mAI (🧠)** · (July 2019 – Present)

- GitHub: [@murtazaai](https://github.com/murtazaai)
- LinkedIn: [linkedin.com/in/murtazai](https://linkedin.com/in/murtazai)
- Portfolio: [murtazai.com](https://murtazai.com)
