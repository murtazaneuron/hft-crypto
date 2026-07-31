//! Shared authentication trait and request types used across all exchange modules.

use std::collections::HashMap;

use anyhow::Result;

/// A signed HTTP request ready to be dispatched.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    /// HTTP method (GET, POST, DELETE).
    pub method: String,
    /// Full URL including signed query string (where applicable).
    pub url: String,
    /// HTTP headers carrying authentication material.
    pub headers: HashMap<String, String>,
    /// Optional JSON body for POST requests.
    pub body: Option<String>,
    /// The exchange this request targets.
    pub exchange: String,
    /// Human-readable description of what this request does.
    pub description: String,
}

impl SignedRequest {
    /// Print a formatted summary (safe to log - no secret material).
    pub fn display(&self) {
        println!("┌─ {} ─ {} ──────────────", self.exchange, self.description);
        println!("│  Method : {}", self.method);
        println!("│  URL    : {}", self.url);
        for (k, v) in &self.headers {
            println!("│  Header : {k}: {v}");
        }
        if let Some(body) = &self.body {
            println!("│  Body   : {body}");
        }
        println!("└────────────────────────────────────────────────────────────");
    }
}

/// Credential set for HMAC-based exchanges.
#[derive(Debug, Clone)]
pub struct HmacCredentials {
    /// The API key for the exchange.
    pub api_key: String,
    /// The API secret for the exchange.
    pub api_secret: String,
}

impl HmacCredentials {
    /// Creates a new `HmacCredentials` instance with the given API key and secret.
    ///
    /// # Arguments
    ///
    /// * `api_key` - The API key for the exchange.
    /// * `api_secret` - The API secret for the exchange.
    ///
    /// # Returns
    ///
    /// A new `HmacCredentials` instance.
    pub fn new(api_key: impl Into<String>, api_secret: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            api_secret: api_secret.into(),
        }
    }

    /// Load from environment variables.
    ///
    /// Reads `key_var` and `secret_var` from the process environment.
    /// Falls back to a dry-run placeholder string when a variable is absent —
    /// this method is infallible by design so the binary always starts.
    ///
    /// # Example
    /// ```rust,no_run
    /// use hft_crypto::exchange::auth::HmacCredentials;
    /// // BINANCE_API_KEY / BINANCE_API_SECRET must be set in the environment.
    /// let creds = HmacCredentials::from_env("BINANCE_API_KEY", "BINANCE_API_SECRET").unwrap();
    /// ```
    pub fn from_env(key_var: &str, secret_var: &str) -> Result<Self> {
        let api_key = std::env::var(key_var).unwrap_or_else(|_| format!("DRY_RUN_{key_var}"));
        let api_secret =
            std::env::var(secret_var).unwrap_or_else(|_| format!("dry-run-secret-{secret_var}"));
        Ok(Self::new(api_key, api_secret))
    }
}

/// Returns current UTC timestamp in milliseconds.
///
/// # Example
///
/// ```rust
/// use hft_crypto::exchange::auth::timestamp_ms;
/// let ts = timestamp_ms();
/// ```
/// # Returns
///
/// The current UTC timestamp in milliseconds.
///
/// # Note
///
/// This function uses [`chrono::Utc::now`] to get the current timestamp.
///
/// # Panics
///
/// Panics if the timestamp cannot be converted to `u64`.
pub fn timestamp_ms() -> u64 {
    chrono::Utc::now().timestamp().try_into().unwrap()
}

/// Returns current UTC timestamp in seconds.
///
/// # Example
///
/// ```rust
/// use hft_crypto::exchange::auth::timestamp_s;
/// let ts = timestamp_s();
/// ```
/// # Returns
///
/// The current UTC timestamp in seconds.
///
/// # Note
///
/// This function uses [`chrono::Utc::now`] to get the current timestamp.
///
/// # Panics
///
/// Panics if the timestamp cannot be converted to `u64`.
pub fn timestamp_s() -> u64 {
    chrono::Utc::now().timestamp().try_into().unwrap()
}

/// Returns ISO-8601 UTC timestamp string (OKX format).
pub fn timestamp_iso8601() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// Trait that all exchange authenticators implement.
pub trait ExchangeAuth {
    /// Sign a spot market order request (dry-run by default).
    fn sign_order(
        &self,
        symbol: &str,
        side: &str,
        quantity: f64,
        price: Option<f64>,
    ) -> Result<SignedRequest>;

    /// Sign an account balance query.
    fn sign_balance_query(&self) -> Result<SignedRequest>;

    /// Name of the exchange.
    fn exchange_name(&self) -> &'static str;
}
