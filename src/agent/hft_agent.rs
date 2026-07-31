//! # Rig (ARC) HFT Agent
//!
//! A `rig-core` agent that wraps the cryptographic signing layer
//! and exposes a natural-language interface for trade analysis.
//!
//! ## Required traits
//!
//! Both `CompletionClient` and `ProviderClient` must be in scope for `.agent()`
//! to resolve on `anthropic::Client` in rig-core ≥ 0.36.
//!
//! ## Architecture
//!
//! ```text
//! User prompt
//!     │
//!     ▼
//! HftAgent (rig-core)
//!     │  preamble: "You are a Rust HFT engineer ..."
//!     │  model:    claude-sonnet-4-6
//!     │
//!     ├─► Reasoning: analyse market context
//!     │
//!     └─► Output: structured JSON trade decision
//!             │
//!             ▼
//!     Exchange crypto layer
//!     (signs via ECDSA / Ed25519 / HMAC-SHA256)
//! ```

use anyhow::Result;
use rig_core::{
    client::{CompletionClient, ProviderClient},
    completion::Prompt,
    providers::anthropic,
};

const PREAMBLE: &str = "\
You are a senior Rust HFT engineer at mAI (🧠) specialising in \
Rig (ARC) - the high-performance Rust Inference Gateway for DeFi trading. \
You analyse trade parameters, assess risk, and produce structured decisions. \
You always output a JSON object with keys: \
`action` (\"execute\" | \"skip\" | \"wait\"), \
`reason` (one sentence), \
`risk_level` (\"low\" | \"medium\" | \"high\"), \
`exchange` (exchange name or \"all\"). \
Do not include any text outside the JSON object.";

/// Rig (ARC) HFT agent wrapping claude-sonnet-4-6.
///
/// Requires the `ai-agent` feature and a valid `ANTHROPIC_API_KEY`
/// environment variable (or `.env` file loaded via `dotenvy`).
pub struct HftAgent {
    /// Anthropic client - stored directly, not wrapped in `Arc`.
    ///
    /// `Arc` is unnecessary: the client is consumed by `.agent()...build()` per call.
    /// Wrapping in `Arc` produces `Arc<Client>` on which `.agent()` cannot be resolved.
    client: anthropic::Client,
}

impl HftAgent {
    /// Construct with an Anthropic client (reads `ANTHROPIC_API_KEY` from env).
    ///
    /// Calls `dotenvy::dotenv().ok()` for `.env` file support in development.
    pub fn new() -> Result<Self> {
        let _ = dotenvy::dotenv();
        let client = anthropic::Client::from_env()?;
        Ok(Self { client })
    }

    /// Analyse a proposed trade and return a structured JSON decision.
    ///
    /// # Example
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> anyhow::Result<()> {
    /// use hft_crypto::agent::hft_agent::HftAgent;
    /// let agent = HftAgent::new().expect("Failed to init HftAgent");
    /// let decision = agent.analyse_trade(
    ///     "BTC/USDT", "buy", 0.01, Some(65000.0), "Binance"
    /// ).await?;
    /// println!("{}", decision);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn analyse_trade(
        &self,
        symbol: &str,
        side: &str,
        quantity: f64,
        price: Option<f64>,
        exchange: &str,
    ) -> Result<String> {
        let agent = self
            .client
            .agent("claude-sonnet-4-6")
            .preamble(PREAMBLE)
            .build();

        let price_str = price.map_or_else(|| "market".to_string(), |p| format!("limit @ {p:.2}"));

        let prompt = format!(
            "Proposed trade: {side} {quantity} {symbol} ({price_str}) on {exchange}. \
             Current volatility: medium. Time: off-peak hours. \
             Assess and return your decision JSON."
        );

        let response = agent.prompt(prompt).await?;
        Ok(response)
    }
}

impl Default for HftAgent {
    fn default() -> Self {
        Self::new().expect("Failed to initialize HftAgent: check ANTHROPIC_API_KEY is set")
    }
}
