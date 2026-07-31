//! # HMAC - Hash-based Message Authentication Code (RFC 2104)
//!
//! ## Algorithm walkthrough
//!
//! HMAC-SHA256(key, message):
//!   1. If |key| > 64: key = SHA-256(key)
//!   2. If |key| < 64: pad key with 0x00 to 64 bytes
//!   3. `i_key_pad` = key XOR (0x36 repeated × 64)   ← inner padding
//!   4. `o_key_pad` = key XOR (0x5C repeated × 64)   ← outer padding
//!   5. inner  = SHA-256(i_key_pad || message)
//!   6. result = SHA-256(o_key_pad || inner)
//!
//! ## Why HMAC for exchange auth?
//! - No asymmetric key pair needed: both sides share a secret (API secret)
//! - Computationally infeasible to forge without the secret
//! - Standard across Binance, OKX, Bybit, Coinbase, `KuCoin` REST APIs
//! - HMAC-SHA512 variant used by Kraken for extra margin

use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Compute HMAC-SHA256 and return the raw 32-byte digest.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; 32]> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| anyhow!("HMAC-SHA256 key error: {e}"))?;
    mac.update(message);
    let result = mac.finalize().into_bytes();
    Ok(result.into())
}

/// Compute HMAC-SHA256 and return the lowercase hex string (64 chars).
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> Result<String> {
    Ok(hex::encode(hmac_sha256(key, message)?))
}

/// Compute HMAC-SHA256 and return the standard base64 string.
/// Used by `KuCoin` and Coinbase Advanced Trade.
pub fn hmac_sha256_base64(key: &[u8], message: &[u8]) -> Result<String> {
    Ok(B64.encode(hmac_sha256(key, message)?))
}

/// Compute HMAC-SHA512 and return the raw 64-byte digest.
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> Result<[u8; 64]> {
    let mut mac =
        HmacSha512::new_from_slice(key).map_err(|e| anyhow!("HMAC-SHA512 key error: {e}"))?;
    mac.update(message);
    let result = mac.finalize().into_bytes();
    Ok(result.into())
}

/// Compute HMAC-SHA512 and return the lowercase hex string (128 chars).
/// Used by Kraken.
pub fn hmac_sha512_hex(key: &[u8], message: &[u8]) -> Result<String> {
    Ok(hex::encode(hmac_sha512(key, message)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST test vector for HMAC-SHA256
    /// Key  = 0x0b * 20
    /// Data = "Hi There"
    /// Expected hex (from RFC 4231 §4.2):
    ///   b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    #[test]
    fn nist_hmac_sha256_vector() {
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let result = hmac_sha256_hex(&key, data).unwrap();
        assert_eq!(
            result,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_sha256_base64_non_empty() {
        let key = b"test-api-secret";
        let msg = b"timestamp=1700000000000&symbol=BTCUSDT&side=BUY";
        let result = hmac_sha256_base64(key, msg).unwrap();
        assert!(!result.is_empty());
        // base64 of 32 bytes = 44 chars (with padding)
        assert_eq!(result.len(), 44);
    }

    #[test]
    fn different_keys_produce_different_macs() {
        let msg = b"same message";
        let mac1 = hmac_sha256_hex(b"key-one", msg).unwrap();
        let mac2 = hmac_sha256_hex(b"key-two", msg).unwrap();
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn hmac_sha512_length() {
        let result = hmac_sha512_hex(b"kraken-secret", b"nonce+payload").unwrap();
        assert_eq!(result.len(), 128); // 64 bytes × 2 hex chars
    }
}
