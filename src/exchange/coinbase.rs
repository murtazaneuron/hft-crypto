//! # Coinbase Advanced Trade REST API Authentication
//!
//! ## Signing scheme (HMAC-SHA256)
//!
//! ```text
//! timestamp   = Unix seconds (string)
//! prehash     = timestamp + method + requestPath + body
//! signature   = HMAC-SHA256(apiSecret, prehash) → hex
//! ```
//!
//! ## Required headers
//! - `CB-ACCESS-KEY`        : API key
//! - `CB-ACCESS-SIGN`       : hex HMAC-SHA256 signature
//! - `CB-ACCESS-TIMESTAMP`  : Unix seconds string
//!
//! ## Reference
//! - [`https://docs.cdp.coinbase.com/advanced-trade/docs/rest-api-auth`](https://docs.cdp.coinbase.com/advanced-trade/docs/rest-api-auth)

use std::collections::HashMap;

use anyhow::Result;

use crate::{
    crypto::hmac::hmac_sha256_hex,
    exchange::auth::{ExchangeAuth, HmacCredentials, SignedRequest, timestamp_s},
};

const BASE_URL: &str = "https://api.coinbase.com";

/// Authenticates with the Coinbase Advanced Trade REST API using HMAC-SHA256.
///
/// # Example
///
/// ```rust,no_run
/// use hft_crypto::exchange::coinbase::CoinbaseAuth;
///
/// let auth = CoinbaseAuth::from_env().unwrap();
/// ```
pub struct CoinbaseAuth {
    creds: HmacCredentials,
}

impl CoinbaseAuth {
    /// Construct with explicit HMAC credentials.
    pub fn new(creds: HmacCredentials) -> Self {
        Self { creds }
    }

    /// Construct from `COINBASE_API_KEY` / `COINBASE_API_SECRET` environment variables.
    /// Falls back to dry-run placeholder values when env vars are absent.
    pub fn from_env() -> Result<Self> {
        Ok(Self::new(HmacCredentials::from_env(
            "COINBASE_API_KEY",
            "COINBASE_API_SECRET",
        )?))
    }

    fn sign(&self, timestamp: u64, method: &str, path: &str, body: &str) -> Result<String> {
        let prehash = format!("{timestamp}{method}{path}{body}");
        hmac_sha256_hex(self.creds.api_secret.as_bytes(), prehash.as_bytes())
    }

    fn auth_headers(
        &self,
        timestamp: u64,
        method: &str,
        path: &str,
        body: &str,
    ) -> Result<HashMap<String, String>> {
        let sig = self.sign(timestamp, method, path, body)?;
        let mut headers = HashMap::new();
        headers.insert("CB-ACCESS-KEY".to_string(), self.creds.api_key.clone());
        headers.insert("CB-ACCESS-SIGN".to_string(), sig);
        headers.insert("CB-ACCESS-TIMESTAMP".to_string(), timestamp.to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        Ok(headers)
    }
}

impl ExchangeAuth for CoinbaseAuth {
    fn exchange_name(&self) -> &'static str {
        "Coinbase"
    }

    fn sign_order(
        &self,
        symbol: &str,
        side: &str,
        quantity: f64,
        price: Option<f64>,
    ) -> Result<SignedRequest> {
        let ts = timestamp_s();
        let path = "/api/v3/brokerage/orders";
        let order_type = if price.is_some() { "LIMIT" } else { "MARKET" };

        let mut body = serde_json::json!({
            "client_order_id": format!("pbhft-{ts}"),
            "product_id": symbol.to_uppercase(),
            "side": side.to_uppercase(),
            "order_configuration": {
                order_type.to_lowercase(): {
                    "base_size": format!("{quantity:.8}"),
                }
            }
        });
        if let Some(p) = price {
            body["order_configuration"][order_type.to_lowercase()]["limit_price"] =
                serde_json::json!(format!("{p:.2}"));
        }
        let body_str = body.to_string();

        let headers = self.auth_headers(ts, "POST", path, &body_str)?;

        Ok(SignedRequest {
            method: "POST".to_string(),
            url: format!("{BASE_URL}{path}"),
            headers,
            body: Some(body_str),
            exchange: self.exchange_name().to_string(),
            description: format!("{side} {quantity} {symbol}"),
        })
    }

    fn sign_balance_query(&self) -> Result<SignedRequest> {
        let ts = timestamp_s();
        let path = "/api/v3/brokerage/accounts";
        let headers = self.auth_headers(ts, "GET", path, "")?;

        Ok(SignedRequest {
            method: "GET".to_string(),
            url: format!("{BASE_URL}{path}"),
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

    fn dry_run() -> CoinbaseAuth {
        CoinbaseAuth::new(HmacCredentials::new("test-key", "test-secret"))
    }

    #[test]
    fn sign_order_has_coinbase_headers() {
        let auth = dry_run();
        let req = auth
            .sign_order("BTC-USD", "BUY", 0.001, Some(65000.0))
            .unwrap();
        assert!(req.headers.contains_key("CB-ACCESS-KEY"));
        assert!(req.headers.contains_key("CB-ACCESS-SIGN"));
        assert!(req.headers.contains_key("CB-ACCESS-TIMESTAMP"));
        assert_eq!(req.method, "POST");
    }
}
