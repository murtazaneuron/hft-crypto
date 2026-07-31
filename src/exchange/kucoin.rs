//! # `KuCoin` REST API Authentication
//!
//! ## Signing scheme (HMAC-SHA256 + base64 - with passphrase signing in V2)
//!
//! ```text
//! timestamp   = milliseconds since Unix epoch (string)
//! prehash     = timestamp + method + endpoint + body
//! signature   = base64( HMAC-SHA256(apiSecret, prehash) )
//! passphrase  = base64( HMAC-SHA256(apiSecret, passphrase_plaintext) )
//! ```
//!
//! ## Required headers
//! - `KC-API-KEY`            : API key
//! - `KC-API-SIGN`           : base64 HMAC-SHA256 signature
//! - `KC-API-TIMESTAMP`      : ms timestamp string
//! - `KC-API-PASSPHRASE`     : HMAC-signed (V2) or plain (V1) passphrase
//! - `KC-API-KEY-VERSION`    : "2" (V2 passphrase signing)
//!
//! ## Reference
//! - '<https://docs.kucoin.com/#authentication>'

use std::collections::HashMap;

use anyhow::Result;

/// Represents the `KuCoin` API credentials: key, secret, and passphrase.
///
/// V2 passphrase signing is used: the passphrase is itself HMAC-SHA256 signed with the API
/// secret.
use crate::{
    crypto::hmac::hmac_sha256_base64,
    exchange::auth::{ExchangeAuth, SignedRequest, timestamp_ms},
};

/// The base URL for the `KuCoin` API.
const BASE_URL: &str = "https://api.kucoin.com";

/// `KuCoin` API credentials: key, secret, and passphrase.
///
/// V2 passphrase signing is used: the passphrase is itself HMAC-SHA256 signed with the API secret.
pub struct KuCoinCredentials {
    /// The `KuCoin` API key.
    pub api_key: String,
    /// The `KuCoin` API secret.
    pub api_secret: String,
    /// The `KuCoin` passphrase.
    pub passphrase: String,
}

/// `KuCoin` API credentials: key, secret, and passphrase.
///
/// V2 passphrase signing is used: the passphrase is itself HMAC-SHA256 signed with the API secret.
impl KuCoinCredentials {
    /// Construct with explicit credentials.
    pub fn new(
        api_key: impl Into<String>,
        api_secret: impl Into<String>,
        passphrase: impl Into<String>,
    ) -> Self {
        Self {
            api_key: api_key.into(),
            api_secret: api_secret.into(),
            passphrase: passphrase.into(),
        }
    }

    /// Load credentials from `KUCOIN_API_KEY`, `KUCOIN_API_SECRET`, `KUCOIN_PASSPHRASE`
    /// environment variables. Falls back to dry-run placeholder values when vars are absent.
    ///
    /// # Returns
    ///
    /// A `KuCoinCredentials` struct with the loaded credentials.
    pub fn from_env() -> Self {
        Self::new(
            std::env::var("KUCOIN_API_KEY").unwrap_or_else(|_| "DRY_RUN_KEY".into()),
            std::env::var("KUCOIN_API_SECRET").unwrap_or_else(|_| "dry-run-secret".into()),
            std::env::var("KUCOIN_PASSPHRASE").unwrap_or_else(|_| "dry-run-passphrase".into()),
        )
    }
}

/// `KuCoin` authentication: HMAC-SHA256 with base64 encoding and V2 passphrase signing.
///
/// V2 passphrase: the passphrase is itself HMAC-SHA256 signed with the API secret,
/// then base64-encoded, before being sent as `KC-API-PASSPHRASE`.
pub struct KuCoinAuth {
    creds: KuCoinCredentials,
}

impl KuCoinAuth {
    /// Construct with explicit credentials.
    ///
    /// # Example
    ///
    /// ```
    /// use hft_crypto::exchange::kucoin::{KuCoinAuth, KuCoinCredentials};
    /// let auth = KuCoinAuth::new(KuCoinCredentials::new("api_key", "api_secret", "passphrase"));
    /// ```
    pub fn new(creds: KuCoinCredentials) -> Self {
        Self { creds }
    }

    fn sign(&self, timestamp: u64, method: &str, endpoint: &str, body: &str) -> Result<String> {
        let prehash = format!("{timestamp}{method}{endpoint}{body}");
        hmac_sha256_base64(self.creds.api_secret.as_bytes(), prehash.as_bytes())
    }

    /// V2: passphrase is itself HMAC-SHA256 signed with the API secret.
    fn signed_passphrase(&self) -> Result<String> {
        hmac_sha256_base64(
            self.creds.api_secret.as_bytes(),
            self.creds.passphrase.as_bytes(),
        )
    }

    fn auth_headers(
        &self,
        timestamp: u64,
        method: &str,
        endpoint: &str,
        body: &str,
    ) -> Result<HashMap<String, String>> {
        let sig = self.sign(timestamp, method, endpoint, body)?;
        let pp = self.signed_passphrase()?;
        let mut headers = HashMap::new();
        headers.insert("KC-API-KEY".to_string(), self.creds.api_key.clone());
        headers.insert("KC-API-SIGN".to_string(), sig);
        headers.insert("KC-API-TIMESTAMP".to_string(), timestamp.to_string());
        headers.insert("KC-API-PASSPHRASE".to_string(), pp);
        headers.insert("KC-API-KEY-VERSION".to_string(), "2".to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        Ok(headers)
    }
}

impl ExchangeAuth for KuCoinAuth {
    fn exchange_name(&self) -> &'static str {
        "KuCoin"
    }

    fn sign_order(
        &self,
        symbol: &str,
        side: &str,
        quantity: f64,
        price: Option<f64>,
    ) -> Result<SignedRequest> {
        let ts = timestamp_ms();
        let endpoint = "/api/v1/orders";
        let order_type = if price.is_some() { "limit" } else { "market" };

        let mut body_map = serde_json::json!({
            "clientOid": format!("pbhft-{ts}"),
            "symbol": symbol.to_uppercase(),
            "side": side.to_lowercase(),
            "type": order_type,
            "size": format!("{quantity:.8}"),
        });
        if let Some(p) = price {
            body_map["price"] = serde_json::json!(format!("{p:.2}"));
        }
        let body_str = body_map.to_string();
        let headers = self.auth_headers(ts, "POST", endpoint, &body_str)?;

        Ok(SignedRequest {
            method: "POST".to_string(),
            url: format!("{BASE_URL}{endpoint}"),
            headers,
            body: Some(body_str),
            exchange: self.exchange_name().to_string(),
            description: format!("{side} {quantity} {symbol}"),
        })
    }

    fn sign_balance_query(&self) -> Result<SignedRequest> {
        let ts = timestamp_ms();
        let endpoint = "/api/v1/accounts";
        let headers = self.auth_headers(ts, "GET", endpoint, "")?;

        Ok(SignedRequest {
            method: "GET".to_string(),
            url: format!("{BASE_URL}{endpoint}"),
            headers,
            body: None,
            exchange: self.exchange_name().to_string(),
            description: "accounts query".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dry_run() -> KuCoinAuth {
        KuCoinAuth::new(KuCoinCredentials::new("key", "secret", "pass"))
    }

    #[test]
    fn sign_order_kucoin_headers() {
        let auth = dry_run();
        let req = auth
            .sign_order("BTC-USDT", "buy", 0.001, Some(65000.0))
            .unwrap();
        for h in &[
            "KC-API-KEY",
            "KC-API-SIGN",
            "KC-API-TIMESTAMP",
            "KC-API-PASSPHRASE",
            "KC-API-KEY-VERSION",
        ] {
            assert!(req.headers.contains_key(*h), "missing: {h}");
        }
        assert_eq!(req.headers["KC-API-KEY-VERSION"], "2");
    }
}
