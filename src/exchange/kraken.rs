//! # Kraken REST API Authentication
//!
//! ## Signing scheme (HMAC-SHA512 - more complex than most)
//!
//! ```text
//! nonce       = current timestamp in microseconds (monotonically increasing)
//! postData    = nonce=<nonce>&<other params>
//! message     = urlPath + SHA-256(nonce + postData)
//! signature   = HMAC-SHA512(base64_decode(apiSecret), message)
//! ```
//!
//! The key insight: the API secret is base64-decoded before use as the HMAC key.
//! This is unique to Kraken and a common source of bugs when forward-engineering.
//!
//! ## Reference
//! - '<https://docs.kraken.com/api/docs/guides/rest-authentication>'

use std::{collections::HashMap, fmt::Write};

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD as B64};

use crate::{
    crypto::hmac::{hmac_sha256, hmac_sha512},
    exchange::auth::{ExchangeAuth, HmacCredentials, SignedRequest},
};

const BASE_URL: &str = "https://api.kraken.com";

/// Authentication credentials for Kraken L1.
///
/// This struct holds the credentials used to sign requests for Kraken L1.
pub struct KrakenAuth {
    creds: HmacCredentials,
}

impl KrakenAuth {
    /// Construct with explicit HMAC credentials.
    pub fn new(creds: HmacCredentials) -> Self {
        Self { creds }
    }

    /// Construct from `KRAKEN_API_KEY` / `KRAKEN_API_SECRET` environment variables.
    /// Falls back to dry-run placeholder values when env vars are absent.
    pub fn from_env() -> Result<Self> {
        Ok(Self::new(HmacCredentials::from_env(
            "KRAKEN_API_KEY",
            "KRAKEN_API_SECRET",
        )?))
    }

    /// Generate a Kraken nonce: microseconds since Unix epoch.
    fn nonce() -> String {
        let ts = chrono::Utc::now();
        let micros = u64::try_from(ts.timestamp()).unwrap_or(0) * 1_000_000
            + u64::from(ts.timestamp_subsec_micros());
        micros.to_string()
    }

    /// Build the Kraken API signature.
    ///
    /// Steps:
    /// 1. `sha256_hash` = SHA-256(nonce || `post_data`)
    /// 2. `message`     = `url_path_bytes` || `sha256_hash`
    /// 3. `key`         = `base64_decode(api_secret)`
    /// 4. `signature`   = HMAC-SHA512(`key`, `message`)
    /// 5. `return`      = `base64_encode(signature)`
    fn build_signature(&self, url_path: &str, nonce: &str, post_data: &str) -> Result<String> {
        // Step 1: SHA-256(nonce + postData)
        let nonce_data = format!("{nonce}{post_data}");
        let sha256_hash = hmac_sha256(&[], nonce_data.as_bytes())
            // For plain SHA-256 we use a zero-length HMAC key workaround;
            // proper SHA-256 via sha2 directly:
            .unwrap_or_else(|_| {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(nonce_data.as_bytes());
                hasher.finalize().into()
            });

        // Step 2: message = url_path || sha256_hash
        let mut message = url_path.as_bytes().to_vec();
        message.extend_from_slice(&sha256_hash);

        // Step 3: decode the base64 API secret into raw bytes
        let key_bytes = B64
            .decode(&self.creds.api_secret)
            .unwrap_or_else(|_| self.creds.api_secret.as_bytes().to_vec());

        // Step 4: HMAC-SHA512
        let signature = hmac_sha512(&key_bytes, &message)?;

        // Step 5: base64-encode the result
        Ok(B64.encode(signature))
    }
}

impl ExchangeAuth for KrakenAuth {
    fn exchange_name(&self) -> &'static str {
        "Kraken"
    }

    fn sign_order(
        &self,
        symbol: &str,
        side: &str,
        quantity: f64,
        price: Option<f64>,
    ) -> Result<SignedRequest> {
        let nonce = Self::nonce();
        let order_type = if price.is_some() { "limit" } else { "market" };
        let url_path = "/0/private/AddOrder";

        let mut post_data = format!(
            "nonce={nonce}&ordertype={order_type}&type={}&volume={quantity:.8}&pair={symbol}",
            side.to_lowercase(),
        );
        if let Some(p) = price {
            let _ = write!(post_data, "&price={p:.2}");
        }

        let signature = self.build_signature(url_path, &nonce, &post_data)?;

        let mut headers = HashMap::new();
        headers.insert("API-Key".to_string(), self.creds.api_key.clone());
        headers.insert("API-Sign".to_string(), signature);
        headers.insert(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        );

        Ok(SignedRequest {
            method: "POST".to_string(),
            url: format!("{BASE_URL}{url_path}"),
            headers,
            body: Some(post_data),
            exchange: self.exchange_name().to_string(),
            description: format!("{side} {quantity} {symbol}"),
        })
    }

    fn sign_balance_query(&self) -> Result<SignedRequest> {
        let nonce = Self::nonce();
        let url_path = "/0/private/Balance";
        let post_data = format!("nonce={nonce}");
        let signature = self.build_signature(url_path, &nonce, &post_data)?;

        let mut headers = HashMap::new();
        headers.insert("API-Key".to_string(), self.creds.api_key.clone());
        headers.insert("API-Sign".to_string(), signature);
        headers.insert(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        );

        Ok(SignedRequest {
            method: "POST".to_string(),
            url: format!("{BASE_URL}{url_path}"),
            headers,
            body: Some(post_data),
            exchange: self.exchange_name().to_string(),
            description: "balance query".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dry_run() -> KrakenAuth {
        KrakenAuth::new(HmacCredentials::new("test-key", "dGVzdC1zZWNyZXQ=")) // base64("test-secret")
    }

    #[test]
    fn sign_order_has_api_sign_header() {
        let auth = dry_run();
        let req = auth
            .sign_order("XBTUSD", "buy", 0.001, Some(65000.0))
            .unwrap();
        assert!(req.headers.contains_key("API-Sign"));
        assert!(req.headers.contains_key("API-Key"));
        assert_eq!(req.method, "POST");
    }

    #[test]
    fn balance_query_body_contains_nonce() {
        let auth = dry_run();
        let req = auth.sign_balance_query().unwrap();
        let body = req.body.unwrap();
        assert!(body.contains("nonce="));
    }
}
