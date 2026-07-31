//! Integration tests - exchange authentication

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

fn binance() -> BinanceAuth {
    BinanceAuth::new(HmacCredentials::new("test-key", "test-secret"))
}
fn kraken() -> KrakenAuth {
    KrakenAuth::new(HmacCredentials::new("test-key", "dGVzdC1zZWNyZXQ="))
}
fn okx() -> OkxAuth {
    OkxAuth::new(OkxCredentials::new("key", "secret", "pass"))
}
fn bybit() -> BybitAuth {
    BybitAuth::new(HmacCredentials::new("test-key", "test-secret"))
}
fn coinbase() -> CoinbaseAuth {
    CoinbaseAuth::new(HmacCredentials::new("test-key", "test-secret"))
}
fn kucoin() -> KuCoinAuth {
    KuCoinAuth::new(KuCoinCredentials::new("key", "secret", "pass"))
}
fn hyperliquid() -> HyperliquidAuth {
    HyperliquidAuth::new(Ed25519Signer::generate())
}

// ── Binance ───────────────────────────────────────────────────────────────────
#[test]
fn binance_order_has_signature_in_url() {
    let req = binance()
        .sign_order("BTCUSDT", "BUY", 0.001, Some(65000.0))
        .unwrap();
    assert!(req.url.contains("signature="));
    assert!(req.url.contains("symbol=BTCUSDT"));
    assert!(req.headers.contains_key("X-MBX-APIKEY"));
    assert_eq!(req.method, "POST");
}

#[test]
fn binance_balance_is_get_request() {
    let req = binance().sign_balance_query().unwrap();
    assert_eq!(req.method, "GET");
    assert!(req.url.contains("/api/v3/account"));
}

// ── Kraken ────────────────────────────────────────────────────────────────────
#[test]
fn kraken_order_has_api_sign() {
    let req = kraken()
        .sign_order("XBTUSD", "buy", 0.001, Some(65000.0))
        .unwrap();
    assert!(req.headers.contains_key("API-Sign"));
    assert!(req.headers.contains_key("API-Key"));
    let body = req.body.unwrap();
    assert!(body.contains("nonce="));
    assert!(body.contains("ordertype="));
}

// ── OKX ───────────────────────────────────────────────────────────────────────
#[test]
fn okx_order_has_four_required_headers() {
    let req = okx()
        .sign_order("BTC-USDT", "buy", 0.001, Some(65000.0))
        .unwrap();
    for h in &[
        "OK-ACCESS-KEY",
        "OK-ACCESS-SIGN",
        "OK-ACCESS-TIMESTAMP",
        "OK-ACCESS-PASSPHRASE",
    ] {
        assert!(req.headers.contains_key(*h), "missing OKX header: {h}");
    }
    // signature is base64 of 32 bytes = 44 chars
    assert_eq!(req.headers["OK-ACCESS-SIGN"].len(), 44);
}

// ── Bybit ─────────────────────────────────────────────────────────────────────
#[test]
fn bybit_signature_is_64_hex_chars() {
    let req = bybit()
        .sign_order("BTCUSDT", "Buy", 0.001, Some(65000.0))
        .unwrap();
    let sig = req.headers.get("X-BAPI-SIGN").unwrap();
    assert_eq!(sig.len(), 64, "Bybit HMAC-SHA256 hex must be 64 chars");
}

// ── Coinbase ──────────────────────────────────────────────────────────────────
#[test]
fn coinbase_order_headers_present() {
    let req = coinbase()
        .sign_order("BTC-USD", "BUY", 0.001, Some(65000.0))
        .unwrap();
    assert!(req.headers.contains_key("CB-ACCESS-KEY"));
    assert!(req.headers.contains_key("CB-ACCESS-SIGN"));
    assert!(req.headers.contains_key("CB-ACCESS-TIMESTAMP"));
}

// ── KuCoin ────────────────────────────────────────────────────────────────────
#[test]
fn kucoin_key_version_is_2() {
    let req = kucoin()
        .sign_order("BTC-USDT", "buy", 0.001, Some(65000.0))
        .unwrap();
    assert_eq!(req.headers["KC-API-KEY-VERSION"], "2");
}

#[test]
fn kucoin_passphrase_is_44_chars_base64() {
    let req = kucoin().sign_balance_query().unwrap();
    let pp = req.headers.get("KC-API-PASSPHRASE").unwrap();
    assert_eq!(pp.len(), 44);
}

// ── Hyperliquid ───────────────────────────────────────────────────────────────
#[test]
fn hyperliquid_order_body_contains_signature() {
    let req = hyperliquid()
        .sign_order_request("BTC", "buy", 0.001, Some(65000.0))
        .unwrap();
    let body = req.body.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json.get("signature").is_some());
    assert!(json.get("action").is_some());
    assert!(json.get("nonce").is_some());
}

// ── All exchanges - balance queries ───────────────────────────────────────────
#[test]
fn all_exchanges_produce_valid_balance_requests() {
    let requests = vec![
        binance().sign_balance_query().unwrap(),
        kraken().sign_balance_query().unwrap(),
        okx().sign_balance_query().unwrap(),
        bybit().sign_balance_query().unwrap(),
        coinbase().sign_balance_query().unwrap(),
        kucoin().sign_balance_query().unwrap(),
    ];
    for req in requests {
        assert!(
            !req.url.is_empty(),
            "URL must not be empty for {}",
            req.exchange
        );
        assert!(
            !req.headers.is_empty(),
            "Headers must not be empty for {}",
            req.exchange
        );
    }
}
