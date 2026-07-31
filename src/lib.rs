//! # hft-crypto
//!
//! Cryptographic signing layer for high-frequency trading.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    hft-crypto                    │
//! ├─────────────────────────────────────────────────────────────┤
//! │  crypto::ecdsa      ECDSA / secp256k1  (k256 crate)        │
//! │  crypto::ed25519    Ed25519 / Twisted Edwards               │
//! ├─────────────────────────────────────────────────────────────┤
//! │  exchange::binance  HMAC-SHA256 REST + WebSocket auth       │
//! │  exchange::kraken   HMAC-SHA512 + nonce                     │
//! │  exchange::okx      HMAC-SHA256 + ISO-8601 timestamp        │
//! │  exchange::bybit    HMAC-SHA256 + recv-window               │
//! │  exchange::coinbase HMAC-SHA256 (Advanced Trade API)        │
//! │  exchange::kucoin   HMAC-SHA256 + base64 + passphrase       │
//! │  exchange::hyperliquid  Ed25519 L1 action signing           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  agent::hft_agent   rig-core AI agent (feature = ai-agent) │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```rust,no_run
//! use hft_crypto::crypto::ecdsa::EcdsaSigner;
//! use hft_crypto::exchange::binance::BinanceAuth;
//!
//! let signer = EcdsaSigner::generate();
//! let pubkey_hex = signer.verifying_key_hex();
//! println!("Public key: {pubkey_hex}");
//! ```

pub mod crypto;
pub mod exchange;

#[cfg(feature = "ai-agent")]
pub mod agent;
