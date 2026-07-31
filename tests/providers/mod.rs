//! Live provider integration tests.
//!
//! All tests in this module are gated with `#[ignore]` and require both a valid
//! `ANTHROPIC_API_KEY` environment variable **and** the `ai-agent` feature flag.
//!
//! Run manually:
//! ```text
//! ANTHROPIC_API_KEY=sk-ant-... \
//!     cargo test --test providers --features ai-agent -- --ignored --test-threads=1
//! ```

pub mod anthropic;
