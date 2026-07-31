//! # hft-crypto CLI
//!
//! ```
//! USAGE:
//!   hft-crypto <COMMAND>
//!
//! COMMANDS:
//!   demo-crypto      Show ECDSA and Ed25519 sign/verify demo
//!   demo-exchanges   Show signed request headers for all 7 exchanges
//!   demo-all         Run both demos (default)
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand};
use hft_crypto::{
    crypto::{
        ecdsa::EcdsaSigner,
        ed25519::Ed25519Signer,
        hmac::{hmac_sha256_hex, hmac_sha512_hex},
    },
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
use tracing::info;

#[derive(Parser)]
#[command(
    name = "hft-crypto",
    version,
    about = "Cryptographic signing layer for HFT across 7 exchanges",
    long_about = "Demonstrates ECDSA/Ed25519 forward-engineering and exchange API authentication.\n\
                  All operations run in DRY-RUN mode by default - no live orders are placed."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Demonstrate ECDSA (secp256k1) and Ed25519 signing
    Crypto,
    /// Show signed request headers for all 7 exchanges
    Exchanges,
    /// Run both demos (default)
    All,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hft_crypto=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::All) {
        Commands::Crypto => demo_crypto()?,
        Commands::Exchanges => demo_exchanges()?,
        Commands::All => {
            demo_crypto()?;
            println!();
            demo_exchanges()?;
        }
    }

    Ok(())
}

// ── Crypto demo ────────────────────────────────────────────────────────────────

fn demo_crypto() -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║          CRYPTOGRAPHIC PRIMITIVES - FORWARD-ENGINEERING         ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");

    // ── ECDSA secp256k1 ────────────────────────────────────────────────────
    println!("\n── ECDSA / secp256k1 (Binance · Kraken · OKX · Bybit · Coinbase · KuCoin) ──");
    let ecdsa = EcdsaSigner::generate();
    println!("  Private key (32 B): {}…", &ecdsa.private_key_hex()[..16]);
    println!(
        "  Public key  (33 B, compressed): {}",
        ecdsa.verifying_key_hex()
    );

    let msg = b"BTC/USDT BUY 0.001 @ 65000 [testnet]";
    let sig = ecdsa.sign(msg);
    println!("  Message    : {}", String::from_utf8_lossy(msg));
    println!("  Signature  : {}…", &sig.signature_hex[..32]);
    let ok = ecdsa.verify(msg, &sig.signature_hex)?;
    println!("  Verify ✓   : {ok}");
    info!("ECDSA sign/verify complete");

    // ── Ed25519 ────────────────────────────────────────────────────────────
    println!("\n── Ed25519 / Curve25519 (Hyperliquid · Solana-style) ──────────────");
    let ed = Ed25519Signer::generate();
    println!("  Private seed (32 B): {}…", &ed.private_key_hex()[..16]);
    println!("  Public key  (32 B) : {}", ed.verifying_key_hex());

    let msg2 = b"ETH/USDC SELL 1.5 @ 3200 [hyperliquid-testnet]";
    let sig2 = ed.sign(msg2);
    println!("  Message    : {}", String::from_utf8_lossy(msg2));
    println!("  Signature  : {}…", &sig2.signature_hex[..32]);
    let ok2 = ed.verify(msg2, &sig2.signature_hex)?;
    println!("  Verify ✓   : {ok2}");
    println!(
        "  Deterministic (same msg → same sig): {}",
        ed.sign(msg2).signature_hex == sig2.signature_hex
    );
    info!("Ed25519 sign/verify complete");

    // ── HMAC-SHA256 ────────────────────────────────────────────────────────
    println!("\n── HMAC-SHA256 (REST API authentication) ──────────────────────────");
    let key = b"exchange-api-secret-key";
    let payload = b"timestamp=1700000000000&symbol=BTCUSDT&side=BUY&quantity=0.001";
    let mac = hmac_sha256_hex(key, payload)?;
    println!("  Key        : {}", String::from_utf8_lossy(key));
    println!("  Payload    : {}", String::from_utf8_lossy(payload));
    println!("  HMAC-SHA256: {mac}");

    // ── HMAC-SHA512 (Kraken) ───────────────────────────────────────────────
    println!("\n── HMAC-SHA512 (Kraken nonce-based auth) ──────────────────────────");
    let kraken_key = b"kraken-api-secret-bytes";
    let kraken_msg = b"1700000000000000/0/private/Balance";
    let mac512 = hmac_sha512_hex(kraken_key, kraken_msg)?;
    println!("  HMAC-SHA512 (first 64 chars): {}…", &mac512[..64]);

    Ok(())
}

// ── Exchange demo ──────────────────────────────────────────────────────────────

fn demo_exchanges() -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║       7-EXCHANGE SIGNED REQUEST DEMO  ·  DRY-RUN MODE           ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!("  ⚠  DRY-RUN: credentials are placeholders. No live orders placed.");
    println!();

    let symbol = "BTCUSDT";
    let side = "BUY";
    let qty = 0.001_f64;
    let price = Some(65_000.0_f64);

    // 1. Binance
    let binance = BinanceAuth::new(HmacCredentials::new("BN_KEY", "BN_SECRET"));
    binance.sign_order(symbol, side, qty, price)?.display();

    // 2. Kraken (base64-decode safe test secret)
    let kraken = KrakenAuth::new(HmacCredentials::new("KR_KEY", "S2Vya2VuU2VjcmV0"));
    kraken.sign_order("XBTUSD", "buy", qty, price)?.display();

    // 3. OKX
    let okx = OkxAuth::new(OkxCredentials::new("OKX_KEY", "OKX_SECRET", "OKX_PASS"));
    okx.sign_order("BTC-USDT", "buy", qty, price)?.display();

    // 4. Bybit
    let bybit = BybitAuth::new(HmacCredentials::new("BB_KEY", "BB_SECRET"));
    bybit.sign_order("BTCUSDT", "Buy", qty, price)?.display();

    // 5. Coinbase
    let coinbase = CoinbaseAuth::new(HmacCredentials::new("CB_KEY", "CB_SECRET"));
    coinbase.sign_order("BTC-USD", "BUY", qty, price)?.display();

    // 6. KuCoin
    let kucoin = KuCoinAuth::new(KuCoinCredentials::new("KC_KEY", "KC_SECRET", "KC_PASS"));
    kucoin.sign_order("BTC-USDT", "buy", qty, price)?.display();

    // 7. Hyperliquid (Ed25519)
    let hl = HyperliquidAuth::new(Ed25519Signer::generate());
    hl.sign_order_request("BTC", "buy", qty, price)?.display();

    println!();
    println!("✓  All 7 exchange signed requests generated successfully.");
    println!("   To test against real endpoints, set exchange API key env vars.");
    info!("7-exchange demo complete");

    Ok(())
}
