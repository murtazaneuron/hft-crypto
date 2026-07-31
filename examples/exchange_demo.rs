//! # 7-Exchange Signed Request Demo
//!
//! Constructs and displays authenticated REST API requests for all 7 supported
//! exchanges using dry-run credentials.  No live orders are placed.
//!
//! ```text
//! cargo run --example exchange_demo
//! ```
//!
//! To test against real endpoints, set exchange API key environment variables
//! (see `.env.example`) and ensure `DRY_RUN=false`.

use anyhow::Result;
use hft_crypto::{
    crypto::ed25519::Ed25519Signer,
    exchange::{
        auth::{ExchangeAuth, HmacCredentials},
        binance::BinanceAuth,
        bybit::BybitAuth,
        coinbase::CoinbaseAuth,
        hyperliquid::HyperliquidAuth,
        kraken::KrakenAuth,
        kucoin::{KuCoinAuth, KuCoinCredentials},
        okx::{OkxAuth, OkxCredentials},
    },
};

fn main() -> Result<()> {
    // Load .env if present (non-fatal if absent)
    let _ = dotenvy::dotenv();

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║       7-EXCHANGE SIGNED REQUEST DEMO  ·  DRY-RUN MODE           ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!("  ⚠  DRY-RUN: credentials are placeholders. No live orders placed.");
    println!();

    let symbol = "BTCUSDT";
    let side = "BUY";
    let qty = 0.001_f64;
    let price = Some(65_000.0_f64);

    // 1 - Binance (HMAC-SHA256)
    BinanceAuth::new(HmacCredentials::new("BN_KEY", "BN_SECRET"))
        .sign_order(symbol, side, qty, price)?
        .display();

    // 2 - Kraken (HMAC-SHA512 + SHA-256 + base64-decoded secret)
    KrakenAuth::new(HmacCredentials::new("KR_KEY", "S2Vya2VuU2VjcmV0"))
        .sign_order("XBTUSD", "buy", qty, price)?
        .display();

    // 3 - OKX (HMAC-SHA256 + ISO-8601 timestamp + passphrase)
    OkxAuth::new(OkxCredentials::new("OKX_KEY", "OKX_SECRET", "OKX_PASS"))
        .sign_order("BTC-USDT", "buy", qty, price)?
        .display();

    // 4 - Bybit V5 (HMAC-SHA256 + recv-window prehash)
    BybitAuth::new(HmacCredentials::new("BB_KEY", "BB_SECRET"))
        .sign_order("BTCUSDT", "Buy", qty, price)?
        .display();

    // 5 - Coinbase Advanced Trade (HMAC-SHA256, seconds timestamp)
    CoinbaseAuth::new(HmacCredentials::new("CB_KEY", "CB_SECRET"))
        .sign_order("BTC-USD", "BUY", qty, price)?
        .display();

    // 6 - KuCoin V2 (HMAC-SHA256 + base64 + signed passphrase)
    KuCoinAuth::new(KuCoinCredentials::new("KC_KEY", "KC_SECRET", "KC_PASS"))
        .sign_order("BTC-USDT", "buy", qty, price)?
        .display();

    // 7 - Hyperliquid L1 (Ed25519 - wallet key IS the account)
    HyperliquidAuth::new(Ed25519Signer::generate())
        .sign_order_request("BTC", "buy", qty, price)?
        .display();

    println!();
    println!("✓  All 7 exchange signed requests generated successfully.");
    println!("   To test against real endpoints, set exchange API key env vars.");

    // ── Balance queries (all HMAC-based exchanges) ─────────────────────────
    println!();
    println!("── Balance queries (dry-run) ───────────────────────────────────────");

    for req in [
        BinanceAuth::new(HmacCredentials::new("BN_KEY", "BN_SECRET")).sign_balance_query()?,
        KrakenAuth::new(HmacCredentials::new("KR_KEY", "S2Vya2VuU2VjcmV0")).sign_balance_query()?,
        OkxAuth::new(OkxCredentials::new("OKX_KEY", "OKX_SECRET", "OKX_PASS"))
            .sign_balance_query()?,
        BybitAuth::new(HmacCredentials::new("BB_KEY", "BB_SECRET")).sign_balance_query()?,
        CoinbaseAuth::new(HmacCredentials::new("CB_KEY", "CB_SECRET")).sign_balance_query()?,
        KuCoinAuth::new(KuCoinCredentials::new("KC_KEY", "KC_SECRET", "KC_PASS"))
            .sign_balance_query()?,
    ] {
        println!("  {} - {} - {}", req.exchange, req.method, req.description);
    }

    Ok(())
}
