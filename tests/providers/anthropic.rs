//! Live Anthropic provider tests - require `ANTHROPIC_API_KEY` + `--features ai-agent`.
//!
//! These tests are gated behind `#[ignore]` so they are **skipped in CI** when the
//! API key is absent.  Run them manually with:
//!
//! ```text
//! ANTHROPIC_API_KEY=sk-ant-... \
//!     cargo test --test providers --features ai-agent -- --ignored --test-threads=1
//! ```
//!
//! Use `--test-threads=1` to avoid concurrent API calls hitting rate limits.

#[cfg(feature = "ai-agent")]
mod agent_tests {
    use hft_crypto::agent::hft_agent::HftAgent;

    /// Verify the agent returns valid JSON with the expected keys.
    #[tokio::test]
    #[ignore = "requires ANTHROPIC_API_KEY and --features ai-agent"]
    async fn test_live_agent_returns_valid_json() {
        let agent = HftAgent::new().expect("HftAgent::new failed");
        let response = agent
            .analyse_trade("BTC/USDT", "buy", 0.001, Some(65_000.0), "Binance")
            .await
            .expect("agent call must succeed");

        let parsed: serde_json::Value =
            serde_json::from_str(&response).expect("response must be valid JSON");

        assert!(
            parsed.get("action").is_some(),
            "response must contain `action` key; got: {response}"
        );
        assert!(
            parsed.get("reason").is_some(),
            "response must contain `reason` key"
        );
        assert!(
            parsed.get("risk_level").is_some(),
            "response must contain `risk_level` key"
        );
        assert!(
            parsed.get("exchange").is_some(),
            "response must contain `exchange` key"
        );
    }

    /// Verify the action value is one of the three allowed strings.
    #[tokio::test]
    #[ignore = "requires ANTHROPIC_API_KEY and --features ai-agent"]
    async fn test_live_agent_action_is_valid_enum() {
        let agent = HftAgent::new().expect("HftAgent::new failed");
        let response = agent
            .analyse_trade("ETH/USDC", "sell", 1.5, Some(3_200.0), "Hyperliquid")
            .await
            .expect("agent call must succeed");

        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        let action = parsed["action"].as_str().unwrap_or("");
        assert!(
            ["execute", "skip", "wait"].contains(&action),
            "action must be 'execute', 'skip', or 'wait'; got: '{action}'"
        );
    }

    /// Verify the risk_level value is one of the three allowed strings.
    #[tokio::test]
    #[ignore = "requires ANTHROPIC_API_KEY and --features ai-agent"]
    async fn test_live_agent_risk_level_is_valid_enum() {
        let agent = HftAgent::new().expect("HftAgent::new failed");
        let response = agent
            .analyse_trade("SOL/USDT", "buy", 10.0, None, "OKX")
            .await
            .expect("agent call must succeed");

        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        let risk = parsed["risk_level"].as_str().unwrap_or("");
        assert!(
            ["low", "medium", "high"].contains(&risk),
            "risk_level must be 'low', 'medium', or 'high'; got: '{risk}'"
        );
    }
}
