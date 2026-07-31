# hft-crypto

## SYSTEM ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      hft-crypto                              │
│     Cryptographic Signing Layer for High-Frequency Trading              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
          ┌─────────────────────────▼─────────────────────────┐
          │           CLI Entry Point  (main.rs)              │
          │   [crypto | exchanges | all]                      │
          └──────────┬─────────────────────────┬──────────────┘
                     │                         │
     ┌───────────────▼────────────┐  ┌─────────▼──────────────────────┐
     │     crypto/                │  │     exchange/                  │
     │                            │  │                                │
     │  ecdsa.rs                  │  │  auth.rs  ← ExchangeAuth trait │
     │  secp256k1 / FIPS 186-5    │  │           ← SignedRequest      │
     │  EcdsaSigner               │  │           ← HmacCredentials    │
     │  EcdsaVerifier             │  │                                │
     │                            │  │  binance.rs   HMAC-SHA256      │
     │  ed25519.rs                │  │  kraken.rs    HMAC-SHA512      │
     │  Curve25519 / RFC 8032     │  │  okx.rs       HMAC-SHA256+b64  │
     │  Ed25519Signer             │  │  bybit.rs     HMAC-SHA256      │
     │  Ed25519Verifier           │  │  coinbase.rs  HMAC-SHA256      │
     │                            │  │  kucoin.rs    HMAC-SHA256+pp   │
     │  hmac.rs                   │  │  hyperliquid  Ed25519 L1       │
     │  HMAC-SHA256 / SHA512      │  └────────────────────────────────┘
     │  NIST RFC 4231 tested      │
     └────────────────────────────┘
                     │
          ┌──────────▼────────────────────────────────────────┐
          │       agent/   (feature = ai-agent)               │
          │                                                   │
          │   hft_agent.rs                                    │
          │   HftAgent  →  rig-core 0.37                      │
          │                claude-sonnet-4-6                  │
          │   analyse_trade() → structured JSON decision      │
          └───────────────────────────────────────────────────┘
```

---

## Layer descriptions

### `crypto/` - Forward-engineered primitives

All three modules implement their algorithms from specification, with step-by-step
mathematical commentary in the module-level `//!` doc block.

| Module | Specification | Output |
|---|---|---|
| `ecdsa.rs` | FIPS 186-5, SEC 1 v2.0 | 64-byte DER-normalised (r,s) signature |
| `ed25519.rs` | RFC 8032 | 64-byte deterministic (R‖S) signature |
| `hmac.rs` | RFC 2104 | 32-byte (SHA-256) or 64-byte (SHA-512) MAC |

### `exchange/` - Authentication adapters

Each file adapts the common `ExchangeAuth` trait to a specific exchange's signing scheme.
All adapters produce a `SignedRequest` containing the full URL, authentication headers, and
optional body - ready for dispatch without further modification.

The `auth.rs` module provides shared infrastructure: timestamp utilities, `HmacCredentials`,
and the `ExchangeAuth` trait definition.

### `agent/` - AI-powered trade analysis (optional)

Gated behind the `ai-agent` feature flag to keep the default build lean. `HftAgent` wraps
a rig-core 0.37 `claude-sonnet-4-6` agent configured with a preamble that enforces structured
JSON output (`action`, `reason`, `risk_level`, `exchange`).
