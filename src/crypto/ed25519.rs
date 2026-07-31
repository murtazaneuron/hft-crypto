//! # Ed25519 - Forward Engineering (Twisted Edwards / Curve25519)
//!
//! ## Algorithm walkthrough (forward-engineered from RFC 8032)
//!
//! ### Domain parameters (Ed25519)
//! - Prime field:  p = 2²⁵⁵ − 19
//! - Curve:        −x² + y² ≡ 1 + d·x²·y²  (mod p)   ← Twisted Edwards form where d =
//!   −121665/121666 mod p
//! - Base point:   B  (the unique point with y = 4/5 mod p, x > 0)
//! - Order:        ℓ = 2²⁵² + 27742317777372353535851937790883648493
//! - Cofactor:     h = 8
//!
//! ### Key generation
//! 1. Sample 32-byte secret seed  s  (private key)
//! 2. h = SHA-512(s)               → 64 bytes
//! 3. Clamp h\[0..32\]:
//!    - h\[0\]  &= 248               (clear 3 low bits - cofactor 8)
//!    - h\[31\] &= 127               (clear high bit)
//!    - h\[31\] |= 64                (set second-highest bit)
//! 4. a = h\[0..32\] as little-endian integer (private scalar)
//! 5. A = a · B                    (public key - 32-byte compressed point)
//! 6. Nonce prefix = h\[32..64\]     (deterministic nonce material)
//!
//! ### Signing  (message M, private key s, public key A, nonce prefix P)
//! 1. r = SHA-512(P || M) mod ℓ    (deterministic - no random k needed!)
//! 2. R = r · B                    (32-byte compressed point)
//! 3. S = (r + SHA-512(R || A || M) · a) mod ℓ
//! 4. Signature = R || S           (64 bytes total)
//!
//! ### Verification  (M, A, signature = R || S)
//! 1. Check S < ℓ  (malleability guard)
//! 2. k = SHA-512(R || A || M) mod ℓ
//! 3. Valid iff  8·S·B == 8·R + 8·k·A
//!
//! ### Why Ed25519 for HFT?
//! - **Deterministic**: no per-signature randomness → no random-number-generator side-channel
//!   attacks (critical in co-location environments)
//! - **Fast**: ~10× faster signing than ECDSA secp256k1 on the same hardware
//! - **Compact**: 64-byte signatures, 32-byte public keys
//! - **Collision resistant**: signing hash includes the nonce prefix, preventing fault attacks that
//!   break ECDSA when k is reused
//! - Hyperliquid and Solana use Ed25519 as their native signing algorithm

use anyhow::{Result, anyhow};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

/// An Ed25519 signer backed by a 32-byte seed.
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Generate a cryptographically random Ed25519 signing key.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Restore from a 32-byte seed (little-endian scalar before clamping).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    /// Restore from a 32-byte hex-encoded seed.
    ///
    /// # Errors
    /// Returns an error if the hex string is not 64 characters or contains invalid characters.
    ///
    /// # Examples
    /// ```
    /// use hft_crypto::crypto::ed25519::Ed25519Signer;
    ///
    /// let original = Ed25519Signer::generate();
    /// let restored = Ed25519Signer::from_hex(&original.private_key_hex()).unwrap();
    /// assert_eq!(original.verifying_key_hex(), restored.verifying_key_hex());
    /// ```
    ///
    /// # Panics
    /// Panics if the hex string is not 64 characters or contains invalid characters.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| anyhow!("hex decode: {e}"))?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "Ed25519 seed must be exactly 32 bytes, got {}",
                bytes.len()
            ));
        }
        let arr: [u8; 32] = bytes.try_into().unwrap();
        Ok(Self::from_bytes(&arr))
    }

    // ── Serialisation ──────────────────────────────────────────────────────

    /// Raw 32-byte seed.  Keep secret.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Hex-encoded seed (64 chars).
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key_bytes())
    }

    /// Raw 32-byte compressed public key.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Hex-encoded public key (64 chars).
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.verifying_key_bytes())
    }

    // ── Signing ────────────────────────────────────────────────────────────

    /// Sign arbitrary bytes.  Returns a 64-byte signature.
    ///
    /// # Examples
    /// ```
    /// use hft_crypto::crypto::ed25519::Ed25519Signer;
    ///
    /// let signer = Ed25519Signer::generate();
    /// let result = signer.sign(b"hello world");
    /// assert_eq!(result.signature_bytes.len(), 64);
    /// ```
    pub fn sign(&self, message: &[u8]) -> Ed25519SignatureResult {
        let signature: Signature = self.signing_key.sign(message);
        Ed25519SignatureResult {
            signature_bytes: signature.to_bytes().to_vec(),
            signature_hex: hex::encode(signature.to_bytes()),
            message_len: message.len(),
        }
    }

    /// Sign a UTF-8 string.
    pub fn sign_str(&self, message: &str) -> Ed25519SignatureResult {
        self.sign(message.as_bytes())
    }

    // ── Verification ───────────────────────────────────────────────────────

    /// Verify a signature against this key's public component.
    pub fn verify(&self, message: &[u8], signature_hex: &str) -> Result<bool> {
        let sig_bytes = hex::decode(signature_hex).map_err(|e| anyhow!("hex decode: {e}"))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| anyhow!("Ed25519 signature must be 64 bytes"))?;
        let signature = Signature::from_bytes(&sig_arr);
        let vk = self.signing_key.verifying_key();
        Ok(vk.verify(message, &signature).is_ok())
    }
}

/// Standalone Ed25519 verifier - receives only the public key.
pub struct Ed25519Verifier {
    verifying_key: VerifyingKey,
}

impl Ed25519Verifier {
    /// Construct from a 32-byte hex-encoded public key.
    ///
    /// # Errors
    /// Returns an error if the hex is invalid or not exactly 32 bytes.
    ///
    /// # Examples
    /// ```
    /// use hft_crypto::crypto::ed25519::{Ed25519Signer, Ed25519Verifier};
    ///
    /// let signer = Ed25519Signer::generate();
    /// let verifier = Ed25519Verifier::from_hex(&signer.verifying_key_hex()).unwrap();
    /// let result = signer.sign(b"hello");
    /// assert!(verifier.verify(b"hello", &result.signature_hex).unwrap());
    /// ```
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| anyhow!("hex decode: {e}"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("Ed25519 public key must be 32 bytes"))?;
        let verifying_key = VerifyingKey::from_bytes(&arr)
            .map_err(|e| anyhow!("invalid Ed25519 public key: {e}"))?;
        Ok(Self { verifying_key })
    }

    /// Verify a (message, signature) pair.
    pub fn verify(&self, message: &[u8], signature_hex: &str) -> Result<bool> {
        let sig_bytes = hex::decode(signature_hex).map_err(|e| anyhow!("hex decode: {e}"))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| anyhow!("signature must be 64 bytes"))?;
        let signature = Signature::from_bytes(&sig_arr);
        Ok(self.verifying_key.verify(message, &signature).is_ok())
    }
}

/// Result of an Ed25519 signing operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Ed25519SignatureResult {
    /// Raw 64-byte signature (R || S).
    pub signature_bytes: Vec<u8>,
    /// Lowercase hex-encoded signature (128 chars).
    pub signature_hex: String,
    /// Length of the original message in bytes.
    pub message_len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sign_verify_roundtrip() {
        let signer = Ed25519Signer::generate();
        let msg = b"ETH/USDC sell 1.5 @ 3200 hyperliquid-testnet";

        let result = signer.sign(msg);
        assert_eq!(result.signature_bytes.len(), 64);
        assert_eq!(result.signature_hex.len(), 128);

        let valid = signer.verify(msg, &result.signature_hex).unwrap();
        assert!(valid);
    }

    #[test]
    fn deterministic_signatures() {
        let signer = Ed25519Signer::generate();
        let msg = b"determinism test";
        let sig1 = signer.sign(msg);
        let sig2 = signer.sign(msg);
        assert_eq!(sig1.signature_hex, sig2.signature_hex);
    }

    #[test]
    fn tampered_message_fails() {
        let signer = Ed25519Signer::generate();
        let result = signer.sign(b"original");
        let valid = signer.verify(b"tampered", &result.signature_hex).unwrap();
        assert!(!valid);
    }

    #[test]
    fn from_hex_roundtrip() {
        let original = Ed25519Signer::generate();
        let restored = Ed25519Signer::from_hex(&original.private_key_hex()).unwrap();
        assert_eq!(original.verifying_key_hex(), restored.verifying_key_hex());
    }

    #[test]
    fn standalone_verifier() {
        let signer = Ed25519Signer::generate();
        let msg = b"standalone verifier test";
        let result = signer.sign(msg);

        let verifier = Ed25519Verifier::from_hex(&signer.verifying_key_hex()).unwrap();
        assert!(verifier.verify(msg, &result.signature_hex).unwrap());
    }

    #[test]
    fn cross_key_fails() {
        let a = Ed25519Signer::generate();
        let b = Ed25519Signer::generate();
        let result = a.sign(b"signed by A");
        assert!(!b.verify(b"signed by A", &result.signature_hex).unwrap());
    }
}
