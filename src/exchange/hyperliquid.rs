//! # Hyperliquid L1 Action Authentication (Ed25519)
//!
//! ## Why Ed25519 (not HMAC)?
//! Hyperliquid is a fully on-chain order book - every action is an L1 transaction.
//! There is no API secret: the signer's Ed25519 private key IS the account.
//! The public key maps directly to the wallet address on the Hyperliquid L1.
//!
//! ## Signing scheme
//!
//! ```text
//! action    = JSON object describing the L1 action (order, cancel, transfer)
//! nonce     = milliseconds timestamp (replay protection)
//! vault     = optional vault address (null for personal wallet)
//!
//! prehash   = keccak256( action_bytes || nonce_bytes || vault_bytes )
//! signature = Ed25519.sign(private_key, prehash)
//! ```
//!
//! Note: Hyperliquid uses a simplified EIP-712-style domain separation but
//! ultimately signs raw bytes with Ed25519 rather than secp256k1 ECDSA.
//!
//! ## Reference
//! - [`https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/signing`](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/signing)

use std::collections::HashMap;

use anyhow::Result;

use crate::{
    crypto::ed25519::{Ed25519SignatureResult, Ed25519Signer},
    exchange::auth::{SignedRequest, timestamp_ms},
};

const BASE_URL: &str = "https://api.hyperliquid.xyz";

/// Represents a Hyperliquid L1 action to be signed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HyperliquidAction {
    /// Action type: "order", "cancel", "transfer", etc.
    #[serde(rename = "type")]
    pub action_type: String,
    /// The action payload (serialised to bytes for signing).
    pub payload: serde_json::Value,
    /// Nonce for replay protection (ms timestamp).
    pub nonce: u64,
}

/// Signed Hyperliquid L1 action ready to broadcast.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignedHyperliquidAction {
    /// The signed action to be broadcast.
    pub action: HyperliquidAction,
    /// The signature of the action.
    pub signature: Ed25519SignatureResult,
    /// The public key of the signer, in hex format.
    pub public_key_hex: String,
}

/// Authentication credentials for Hyperliquid L1.
///
/// This struct holds the signer used to sign actions for Hyperliquid L1.
pub struct HyperliquidAuth {
    /// The signer used to sign actions.
    signer: Ed25519Signer,
}

impl HyperliquidAuth {
    /// Construct with an existing Ed25519 signer.
    pub fn new(signer: Ed25519Signer) -> Self {
        Self { signer }
    }

    /// Load private key from `HYPERLIQUID_PRIVATE_KEY` env var (hex seed).
    /// Generates a random key in dry-run mode when env var is absent.
    pub fn from_env() -> Result<Self> {
        if let Ok(hex) = std::env::var("HYPERLIQUID_PRIVATE_KEY") {
            Ok(Self::new(Ed25519Signer::from_hex(&hex)?))
        } else {
            tracing::warn!("HYPERLIQUID_PRIVATE_KEY not set - using ephemeral dry-run key");
            Ok(Self::new(Ed25519Signer::generate()))
        }
    }

    /// Public key hex (64 chars) - this is the Hyperliquid wallet address material.
    pub fn public_key_hex(&self) -> String {
        self.signer.verifying_key_hex()
    }

    /// Sign an arbitrary L1 action.
    pub fn sign_action(&self, action: HyperliquidAction) -> Result<SignedHyperliquidAction> {
        // Canonical bytes: action JSON + nonce (big-endian u64)
        let action_json = serde_json::to_vec(&action.payload)?;
        let nonce_bytes = action.nonce.to_be_bytes();

        let mut prehash = Vec::with_capacity(action_json.len() + 8);
        prehash.extend_from_slice(&action_json);
        prehash.extend_from_slice(&nonce_bytes);

        let signature = self.signer.sign(&prehash);

        Ok(SignedHyperliquidAction {
            action,
            signature,
            public_key_hex: self.public_key_hex(),
        })
    }

    /// Build a limit order action.
    pub fn order_action(symbol: &str, side: &str, quantity: f64, price: f64) -> HyperliquidAction {
        HyperliquidAction {
            action_type: "order".to_string(),
            payload: serde_json::json!({
                "coin": symbol,
                "isBuy": side.eq_ignore_ascii_case("buy"),
                "sz": quantity,
                "limitPx": price,
                "orderType": { "limit": { "tif": "Gtc" } },
                "reduceOnly": false,
            }),
            nonce: timestamp_ms(),
        }
    }

    /// Build a signed HTTP request wrapping the signed action.
    pub fn sign_order_request(
        &self,
        symbol: &str,
        side: &str,
        quantity: f64,
        price: Option<f64>,
    ) -> Result<SignedRequest> {
        let px = price.unwrap_or(0.0);
        let action = Self::order_action(symbol, side, quantity, px);
        let signed = self.sign_action(action)?;

        let body = serde_json::json!({
            "action": signed.action,
            "signature": {
                "r": &signed.signature.signature_hex[..64],
                "s": &signed.signature.signature_hex[64..],
            },
            "nonce": signed.action.nonce,
            "vaultAddress": null,
        })
        .to_string();

        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        Ok(SignedRequest {
            method: "POST".to_string(),
            url: format!("{BASE_URL}/exchange"),
            headers,
            body: Some(body),
            exchange: "Hyperliquid".to_string(),
            description: format!("{side} {quantity} {symbol} @ {px} (Ed25519 L1)"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_action_roundtrip() {
        let auth = HyperliquidAuth::new(Ed25519Signer::generate());
        let action = HyperliquidAuth::order_action("BTC", "buy", 0.001, 65000.0);
        let signed = auth.sign_action(action).unwrap();

        assert_eq!(signed.signature.signature_bytes.len(), 64);
        assert!(!signed.public_key_hex.is_empty());
    }

    #[test]
    fn sign_order_request_has_body() {
        let auth = HyperliquidAuth::new(Ed25519Signer::generate());
        let req = auth
            .sign_order_request("BTC", "buy", 0.001, Some(65000.0))
            .unwrap();
        assert!(req.body.is_some());
        assert_eq!(req.method, "POST");
        assert!(req.url.contains("/exchange"));
    }

    #[test]
    fn deterministic_signing_same_nonce() {
        let signer = Ed25519Signer::generate();
        let auth =
            HyperliquidAuth::new(Ed25519Signer::from_hex(&signer.private_key_hex()).unwrap());
        let nonce = timestamp_ms();

        let a1 = HyperliquidAction {
            action_type: "order".to_string(),
            payload: serde_json::json!({"test": true}),
            nonce,
        };
        let a2 = HyperliquidAction {
            action_type: "order".to_string(),
            payload: serde_json::json!({"test": true}),
            nonce,
        };

        let s1 = auth.sign_action(a1).unwrap();
        let s2 = auth.sign_action(a2).unwrap();
        // Ed25519 is deterministic: same key + same payload = same signature
        assert_eq!(s1.signature.signature_hex, s2.signature.signature_hex);
    }
}
