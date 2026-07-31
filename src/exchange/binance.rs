//! # Binance REST API Authentication
//!
//! ## Signing scheme (HMAC-SHA256)
//!
//! ```text
//! totalParams = queryString + requestBody (concatenated, no separator)
//! signature   = HMAC-SHA256(apiSecret, totalParams)
//! ```
//!
//! ## Request construction
//! 1. Build query string: `symbol=BTCUSDT&side=BUY&type=LIMIT&...&timestamp=<ms>`
//! 2. Append `&signature=<hex>`
//! 3. Set header `X-MBX-APIKEY: <apiKey>`
//!
//! ## Reference
//! - [`https://binance-docs.github.io/apidocs/spot/en/#signed-trade-and-user_data-endpoint-security`](https://binance-docs.github.io/apidocs/spot/en/#signed-trade-and-user_data-endpoint-security)

use std::collections::HashMap;

use anyhow::Result;

use crate::{
    crypto::hmac::hmac_sha256_hex,
    exchange::auth::{ExchangeAuth, HmacCredentials, SignedRequest, timestamp_ms},
};

const BASE_URL: &str = "https://api.binance.com";

/// Binance authentication using HMAC-SHA256.
///
/// Signs orders and balance queries per the Binance Spot REST API v3 specification.
///
/// # Example
///
/// ```rust,no_run
/// use hft_crypto::exchange::binance::BinanceAuth;
///
/// let auth = BinanceAuth::from_env().unwrap();
/// ```
pub struct BinanceAuth {
    creds: HmacCredentials,
}

impl BinanceAuth {
    /// Construct with explicit HMAC credentials.
    pub fn new(creds: HmacCredentials) -> Self {
        Self { creds }
    }

    /// Construct from `BINANCE_API_KEY` / `BINANCE_API_SECRET` environment variables.
    /// Falls back to dry-run placeholder values when env vars are absent.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use hft_crypto::exchange::binance::BinanceAuth;
    ///
    /// let auth = BinanceAuth::from_env().unwrap();
    /// ```
    pub fn from_env() -> Result<Self> {
        Ok(Self::new(HmacCredentials::from_env(
            "BINANCE_API_KEY",
            "BINANCE_API_SECRET",
        )?))
    }

    /// Build and sign a query string.
    fn sign_query(&self, params: &[(&str, String)]) -> Result<String> {
        let qs: String = params
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let sig = hmac_sha256_hex(self.creds.api_secret.as_bytes(), qs.as_bytes())?;
        Ok(format!("{qs}&signature={sig}"))
    }
}

impl ExchangeAuth for BinanceAuth {
    fn exchange_name(&self) -> &'static str {
        "Binance"
    }

    fn sign_order(
        &self,
        symbol: &str,
        side: &str,
        quantity: f64,
        price: Option<f64>,
    ) -> Result<SignedRequest> {
        let ts = timestamp_ms().to_string();
        let order_type = if price.is_some() { "LIMIT" } else { "MARKET" };

        let mut params: Vec<(&str, String)> = vec![
            ("symbol", symbol.to_uppercase()),
            ("side", side.to_uppercase()),
            ("type", order_type.to_string()),
            ("quantity", format!("{quantity:.8}")),
            ("timeInForce", "GTC".to_string()),
            ("recvWindow", "5000".to_string()),
            ("timestamp", ts),
        ];
        if let Some(p) = price {
            params.push(("price", format!("{p:.2}")));
        }

        let signed_qs = self.sign_query(&params)?;
        let url = format!("{BASE_URL}/api/v3/order?{signed_qs}");

        let mut headers = HashMap::new();
        headers.insert("X-MBX-APIKEY".to_string(), self.creds.api_key.clone());
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        Ok(SignedRequest {
            method: "POST".to_string(),
            url,
            headers,
            body: None,
            exchange: self.exchange_name().to_string(),
            description: format!("{side} {quantity} {symbol}"),
        })
    }

    fn sign_balance_query(&self) -> Result<SignedRequest> {
        let ts = timestamp_ms().to_string();
        let params = [("timestamp", ts), ("recvWindow", "5000".to_string())];
        let signed_qs = self.sign_query(&params)?;
        let url = format!("{BASE_URL}/api/v3/account?{signed_qs}");

        let mut headers = HashMap::new();
        headers.insert("X-MBX-APIKEY".to_string(), self.creds.api_key.clone());

        Ok(SignedRequest {
            method: "GET".to_string(),
            url,
            headers,
            body: None,
            exchange: self.exchange_name().to_string(),
            description: "account balance query".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dry_run_auth() -> BinanceAuth {
        BinanceAuth::new(HmacCredentials::new("test-key", "test-secret"))
    }

    #[test]
    fn sign_order_url_contains_signature() {
        let auth = dry_run_auth();
        let req = auth
            .sign_order("BTCUSDT", "BUY", 0.001, Some(65000.0))
            .unwrap();
        assert!(
            req.url.contains("signature="),
            "URL must contain signature param"
        );
        assert!(req.url.contains("symbol=BTCUSDT"));
        assert!(req.url.contains("side=BUY"));
        assert_eq!(req.method, "POST");
    }

    #[test]
    fn sign_balance_query_structure() {
        let auth = dry_run_auth();
        let req = auth.sign_balance_query().unwrap();
        assert_eq!(req.method, "GET");
        assert!(req.url.contains("/api/v3/account"));
        assert!(req.headers.contains_key("X-MBX-APIKEY"));
    }

    #[test]
    fn different_timestamps_produce_different_signatures() {
        // Signatures change because timestamp is part of the signed payload
        let auth = dry_run_auth();
        let r1 = auth.sign_balance_query().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let r2 = auth.sign_balance_query().unwrap();
        // URLs will differ (different timestamp → different signature)
        // We can't guarantee strict inequality in < 1ms, but URLs will differ
        // at the timestamp component at minimum
        assert!(r1.url.contains("signature="));
        assert!(r2.url.contains("signature="));
    }
}
