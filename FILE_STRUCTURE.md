# Repository File Structure

```
hft-crypto/
│
│  ── Root tooling & meta ────────────────────────────────────────────
├── Cargo.toml             Rust 2024 edition; all dependencies; lints; release profile
├── Cargo.lock             Committed (binary crate); delete + regenerate on dep changes
├── rustfmt.toml           Code-style rules (100 cols, 2024 edition, crate-level imports)
├── .clippy.toml           Clippy config (MSRV 1.93.1, complexity thresholds)
├── .gitignore             Focused Rust-only ignore file; secrets never committed
├── .env.example           Template for all 7 exchange API keys + ANTHROPIC_API_KEY
├── LICENSE-PBS            mAI (🧠) proprietary licence
├── README.md              Project overview, architecture, quick-start, test inventory
├── CHANGELOG.md           Version history (Semantic Versioning)
├── CONTRIBUTING.md        Dev setup, workflow, code-style, CI description
├── BUG-FIXES.md           Root-cause analysis of resolved issues (Arc, imports, pins)
├── FILE_STRUCTURE.md      This file
│
│  ── GitHub Actions CI ──────────────────────────────────────────────
├── .github/
│   └── workflows/
│       └── ci.yml         fmt → clippy → build → test → docs → MSRV (1.93.1)
│
│  ── Zed IDE config ─────────────────────────────────────────────────
├── .zed/
│   ├── tasks.json         Cargo build / test / check tasks
│   └── debug.json         CodeLLDB debug launch config
│
│  ── Documentation ──────────────────────────────────────────────────
├── docs/
│   ├── architecture.md    System architecture and layer diagram
│   └── dsa_math.md        ECDSA and Ed25519 forward-engineering mathematical notes
│
│  ── Standalone runnable examples ───────────────────────────────────
│  (cargo run --example <name>; no API key needed unless noted)
├── examples/
│   ├── crypto_demo.rs     ECDSA + Ed25519 + HMAC sign/verify with printed output
│   ├── exchange_demo.rs   Signed request construction for all 7 exchanges (dry-run)
│   └── agent_demo.rs      Rig AI agent trade analysis (--features ai-agent required)
│
│  ── Library source ─────────────────────────────────────────────────
├── src/
│   ├── lib.rs             Crate root; re-exports crypto, exchange, and agent modules
│   ├── main.rs            Binary entry point; CLI arg parsing (clap)
│   │
│   ├── crypto/            Cryptographic primitives
│   │   ├── mod.rs         Module declarations and algorithm summary table
│   │   ├── ecdsa.rs       ECDSA secp256k1 - forward-engineered from FIPS 186-5
│   │   ├── ed25519.rs     Ed25519 Curve25519 - forward-engineered from RFC 8032
│   │   └── hmac.rs        HMAC-SHA256 / HMAC-SHA512 (NIST RFC 4231 test vector)
│   │
│   ├── exchange/          Exchange REST API authentication modules
│   │   ├── mod.rs         pub mod declarations for all 7 exchange modules
│   │   ├── auth.rs        ExchangeAuth trait, SignedRequest, HmacCredentials, timestamps
│   │   ├── binance.rs     HMAC-SHA256; signature in query string
│   │   ├── kraken.rs      HMAC-SHA512 + SHA-256 nonce; base64 secret
│   │   ├── okx.rs         HMAC-SHA256 + ISO-8601 timestamp; base64 signature
│   │   ├── bybit.rs       HMAC-SHA256 + recv-window; prehash = ts+key+window+payload
│   │   ├── coinbase.rs    HMAC-SHA256; prehash = ts+method+path+body
│   │   ├── kucoin.rs      HMAC-SHA256 + base64; V2 passphrase signing
│   │   └── hyperliquid.rs Ed25519 L1 action signing; nonce-based replay protection
│   │
│   └── agent/             Rig (ARC) AI agent integration
│       ├── mod.rs         Module declaration (gated behind ai-agent feature)
│       └── hft_agent.rs   HftAgent wrapping claude-sonnet-4-6; structured JSON output
│
│  ── Integration tests (no API key required) ─────────────────────────
├── tests/
│   ├── crypto_tests.rs         ECDSA, Ed25519, HMAC - NIST vectors included
│   ├── exchange_auth_tests.rs  All 7 exchanges - sign_order + sign_balance_query
│   │
│   └── providers/              Live provider tests - gated behind #[ignore]
│       └── anthropic.rs        Requires ANTHROPIC_API_KEY + --features ai-agent
```

---

## Key design decisions

| Decision | Rationale |
|---|---|
| Lib + bin targets | Integration tests are external crates; lib exposes `hft_crypto::` |
| Rust 2024 edition | Matches the rig upstream repository and MSRV 1.93.1 |
| `ExchangeAuth` trait | Uniform interface across all 7 exchanges; swap adapters without changing callers |
| `HmacCredentials` | Shared credential container for the 5 HMAC-based exchanges |
| `KuCoinCredentials` / `OkxCredentials` | Separate structs for exchanges requiring a passphrase |
| `Ed25519Signer` for Hyperliquid | On-chain account = wallet key; no API secret needed |
| `ai-agent` feature flag | Keeps rig-core out of the dependency graph for deployments that don't need AI |
| `#[ignore]` on live tests | Prevents CI failures when `ANTHROPIC_API_KEY` is absent |
| `^` semver pins | Avoids resolver conflicts from over-constraining transitive deps |
| `strip = "debuginfo"` in release | Reduces binary size; mirrors rig release profile |
