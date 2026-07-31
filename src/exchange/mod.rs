//! Exchange API authentication modules.
//!
//! Each sub-module implements the exact signing scheme required by one exchange.
//! All methods operate on **dry-run** parameters - no live orders are placed
//! without an explicit `--live` CLI flag.

pub mod auth;
pub mod binance;
pub mod bybit;
pub mod coinbase;
pub mod hyperliquid;
pub mod kraken;
pub mod kucoin;
pub mod okx;
