//! Cryptographic primitives for exchange API authentication.
//!
//! ## Algorithms
//!
//! | Algorithm | Curve / Scheme | Used by |
//! |-----------|---------------|---------|
//! | ECDSA     | secp256k1     | Binance, Kraken, OKX, Bybit, Coinbase, KuCoin |
//! | Ed25519   | Curve25519    | Hyperliquid |
//! | HMAC-SHA256 | HMAC        | Most exchange REST APIs |
//! | HMAC-SHA512 | HMAC        | Kraken |

pub mod ecdsa;
pub mod ed25519;
pub mod hmac;
