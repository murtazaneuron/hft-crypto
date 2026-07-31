//! # Bybit REST API Authentication (V5 unified)
//!
//! ## Signing scheme (HMAC-SHA256)
//!
//! ```text
//! timestamp   = milliseconds since Unix epoch
//! recv_window = allowed clock skew window (default 5000 ms)
//! prehash     = timestamp + api_key + recv_window + queryString_or_body
//! signature   = HMAC-SHA256(apiSecret, prehash)  → hex
//! ```
//!
//! ## Required headers
//! - `X-BAPI-API-KEY`       : API key
//! - `X-BAPI-SIGN`          : hex HMAC-SHA256 signature
//! - `X-BAPI-TIMESTAMP`     : milliseconds timestamp
//! - `X-BAPI-RECV-WINDOW`   : recv window (milliseconds)
//!
//! ## Reference
//! - [`https://bybit-exchange.github.io/docs/v5/guide`](https://bybit-exchange.github.io/docs/v5/guide)

use std::collections::HashMap;

use anyhow::Result;

use crate::{
    crypto::hmac::hmac_sha256_hex,
    exchange::auth::{ExchangeAuth, HmacCredentials, SignedRequest, timestamp_ms},
};

const BASE_URL: &str = "https://api.bybit.com";
const RECV_WINDOW: &str = "5000";

/// Authenticates with the Bybit API using an API key and secret.
///
/// # Example
///
/// ```rust,no_run
/// use hft_crypto::exchange::bybit::BybitAuth;
///
/// let auth = BybitAuth::from_env().unwrap();
/// ```
pub struct BybitAuth {
    /// The credentials for the Bybit API.
    creds: HmacCredentials,
}

impl BybitAuth {
    /// Construct with explicit HMAC credentials.
    pub fn new(creds: HmacCredentials) -> Self {
        Self { creds }
    }

    /// Creates a new `BybitAuth` instance from environment variables.
    ///
    /// # Returns
    ///
    /// A new `BybitAuth` instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variables are not set.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use hft_crypto::exchange::bybit::BybitAuth;
    ///
    /// let auth = BybitAuth::from_env().unwrap();
    /// ```
    pub fn from_env() -> Result<Self> {
        Ok(Self::new(HmacCredentials::from_env(
            "BYBIT_API_KEY",
            "BYBIT_API_SECRET",
        )?))
    }

    fn sign(&self, timestamp: u64, payload: &str) -> Result<String> {
        let prehash = format!(
            "{}{}{}{payload}",
            timestamp, self.creds.api_key, RECV_WINDOW
        );
        hmac_sha256_hex(self.creds.api_secret.as_bytes(), prehash.as_bytes())
    }

    fn auth_headers(&self, timestamp: u64, payload: &str) -> Result<HashMap<String, String>> {
        let sig = self.sign(timestamp, payload)?;
        let mut headers = HashMap::new();
        headers.insert("X-BAPI-API-KEY".to_string(), self.creds.api_key.clone());
        headers.insert("X-BAPI-SIGN".to_string(), sig);
        headers.insert("X-BAPI-TIMESTAMP".to_string(), timestamp.to_string());
        headers.insert("X-BAPI-RECV-WINDOW".to_string(), RECV_WINDOW.to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        Ok(headers)
    }
}

impl ExchangeAuth for BybitAuth {
    fn exchange_name(&self) -> &'static str {
        "Bybit"
    }

    fn sign_order(
        &self,
        symbol: &str,
        side: &str,
        quantity: f64,
        price: Option<f64>,
    ) -> Result<SignedRequest> {
        let ts = timestamp_ms();
        let order_type = if price.is_some() { "Limit" } else { "Market" };

        let mut body = serde_json::json!({
            "category": "spot",
            "symbol": symbol.to_uppercase(),
            "side": if side.eq_ignore_ascii_case("buy") { "Buy" } else { "Sell" },
            "orderType": order_type,
            "qty": format!("{quantity:.8}"),
        });
        if let Some(p) = price {
            body["price"] = serde_json::json!(format!("{p:.2}"));
        }
        let body_str = body.to_string();

        let headers = self.auth_headers(ts, &body_str)?;

        Ok(SignedRequest {
            method: "POST".to_string(),
            url: format!("{BASE_URL}/v5/order/create"),
            headers,
            body: Some(body_str),
            exchange: self.exchange_name().to_string(),
            description: format!("{side} {quantity} {symbol}"),
        })
    }

    fn sign_balance_query(&self) -> Result<SignedRequest> {
        let ts = timestamp_ms();
        let qs = "accountType=UNIFIED";
        let headers = self.auth_headers(ts, qs)?;

        Ok(SignedRequest {
            method: "GET".to_string(),
            url: format!("{BASE_URL}/v5/account/wallet-balance?{qs}"),
            headers,
            body: None,
            exchange: self.exchange_name().to_string(),
            description: "wallet balance query".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dry_run() -> BybitAuth {
        BybitAuth::new(HmacCredentials::new("test-key", "test-secret"))
    }

    #[test]
    fn sign_order_headers_present() {
        let auth = dry_run();
        let req = auth
            .sign_order("BTCUSDT", "Buy", 0.001, Some(65000.0))
            .unwrap();
        for h in &[
            "X-BAPI-API-KEY",
            "X-BAPI-SIGN",
            "X-BAPI-TIMESTAMP",
            "X-BAPI-RECV-WINDOW",
        ] {
            assert!(req.headers.contains_key(*h), "missing header: {h}");
        }
    }

    #[test]
    fn signature_is_hex_64_chars() {
        let auth = dry_run();
        let req = auth.sign_balance_query().unwrap();
        let sig = req.headers.get("X-BAPI-SIGN").unwrap();
        assert_eq!(sig.len(), 64);
    }
}
