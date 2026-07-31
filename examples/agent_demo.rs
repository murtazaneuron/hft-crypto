//! # Rig (ARC) HFT Agent Demo
//!
//! Demonstrates the `HftAgent` - a rig-core 0.37 agent wrapping `claude-sonnet-4-6`
//! that analyses proposed trades and returns structured JSON decisions.
//!
//! ## Requirements
//!
//! This example requires the `ai-agent` feature and a valid `ANTHROPIC_API_KEY`:
//!
//! ```text
//! export ANTHROPIC_API_KEY=sk-ant-...
//! cargo run --example agent_demo --features ai-agent
//! ```
//!
//! ## Architecture
//!
//! ```text
//! User trade proposal
//!     │
//!     ▼
//! HftAgent::analyse_trade()
//!     │
//!     ├─ rig-core 0.37 CompletionClient
//!     │  model: claude-sonnet-4-6
//!     │  preamble: structured JSON enforcer
//!     │
//!     └─▶ { action, reason, risk_level, exchange }
//! ```

#[cfg(feature = "ai-agent")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use hft_crypto::agent::hft_agent::HftAgent;

    // Load .env if present (non-fatal if absent)
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hft_crypto=info".parse()?),
        )
        .init();

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║             RIG (ARC) HFT AGENT DEMO - claude-sonnet-4-6        ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    let agent = HftAgent::new().expect("Failed to initialise HftAgent: check ANTHROPIC_API_KEY");

    // Analyse several trade scenarios
    let scenarios = [
        ("BTC/USDT", "buy", 0.01, Some(65_000.0_f64), "Binance"),
        ("ETH/USDC", "sell", 1.5, Some(3_200.0_f64), "Hyperliquid"),
        ("SOL/USDT", "buy", 10.0, None, "OKX"),
    ];

    for (symbol, side, qty, price, exchange) in &scenarios {
        let price_label = price.map_or_else(|| "market".to_string(), |p| format!("limit @ {p:.2}"));

        println!("── Proposal: {side} {qty} {symbol} ({price_label}) on {exchange} ──");

        match agent
            .analyse_trade(symbol, side, *qty, *price, exchange)
            .await
        {
            Ok(response) => {
                // Pretty-print if valid JSON, else print raw
                let display = serde_json::from_str::<serde_json::Value>(&response)
                    .map(|v| serde_json::to_string_pretty(&v).unwrap_or(response.clone()))
                    .unwrap_or(response);
                println!("{display}");
            }
            Err(e) => eprintln!("  ⚠ Agent error: {e}"),
        }
        println!();
    }

    println!("✓  Agent demo complete.");
    Ok(())
}

#[cfg(not(feature = "ai-agent"))]
fn main() {
    eprintln!("This example requires the `ai-agent` feature.");
    eprintln!("Run with: cargo run --example agent_demo --features ai-agent");
    std::process::exit(1);
}
