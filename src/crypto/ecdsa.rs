//! # ECDSA - Forward Engineering (secp256k1 / k256)
//!
//! ## Algorithm walkthrough (forward-engineered from FIPS 186-5 / SEC 1 v2.0)
//!
//! ### Domain parameters (secp256k1)
//! - Prime field:  p = 2²⁵⁶ − 2³² − 977
//! - Curve:        y² ≡ x³ + 7  (mod p)           ← Weierstrass form
//! - Base point:   G  (compressed, 33 bytes on-chain)
//! - Order:        n  (256-bit prime - number of points in the group)
//! - Cofactor:     h = 1
//!
//! ### Key generation
//! 1. Sample random d ∈ [1, n-1]  (private scalar)
//! 2. Q = d · G                    (public key - point multiplication)
//!
//! ### Signing  (message m, private key d)
//! 1. e = SHA-256(m)               (message hash as integer)
//! 2. Sample ephemeral k ∈ [1, n-1]
//! 3. R = k · G;  r = R.x mod n   (r is the x-coordinate of R)
//! 4. s = k⁻¹ · (e + r·d) mod n  (signature scalar)
//! 5. Signature = (r, s)
//!
//! ### Verification  (message m, public key Q, signature (r, s))
//! 1. e = SHA-256(m)
//! 2. w = s⁻¹ mod n
//! 3. u₁ = e·w mod n;  u₂ = r·w mod n
//! 4. X = u₁·G + u₂·Q
//! 5. Valid iff X.x mod n == r
//!
//! ### Why secp256k1 for HFT?
//! - Bitcoin / Ethereum native curve → all EVM chains share the same key material
//! - 256-bit security at ~128-bit classical security level
//! - ECDSA signatures are 64 bytes (compact DER or raw r||s)
//! - Hardware acceleration via dedicated ASICs in exchange co-location racks

use anyhow::{Result, anyhow};
use k256::{
    EncodedPoint,
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
};
use rand::rngs::OsRng;

/// An ECDSA signer backed by a secp256k1 private key.
///
/// # Security
/// The private key bytes are zeroed on drop via the k256 crate's `ZeroizeOnDrop`.
/// Never serialise the private key to a log file or JSON response.
pub struct EcdsaSigner {
    signing_key: SigningKey,
}

impl EcdsaSigner {
    /// Generate a fresh random signing key (cryptographically secure PRNG).
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        Self { signing_key }
    }

    /// Restore a signer from a 32-byte big-endian private scalar.
    ///
    /// # Errors
    /// Returns an error if the bytes do not represent a valid scalar in [1, n-1].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::from_slice(bytes)
            .map_err(|e| anyhow!("invalid ECDSA private key bytes: {e}"))?;
        Ok(Self { signing_key })
    }

    /// Restore a signer from a lowercase hex-encoded private scalar.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| anyhow!("hex decode error: {e}"))?;
        Self::from_bytes(&bytes)
    }

    // ── Serialisation ──────────────────────────────────────────────────────

    /// Export the private key as 32 raw bytes.
    /// **Never** log or transmit this value.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }

    /// Export the private key as a lowercase hex string (64 chars).
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key_bytes())
    }

    /// Export the compressed 33-byte SEC 1 public key.
    pub fn verifying_key_bytes_compressed(&self) -> Vec<u8> {
        let vk = VerifyingKey::from(&self.signing_key);
        vk.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Export the uncompressed 65-byte SEC 1 public key (04 || x || y).
    pub fn verifying_key_bytes_uncompressed(&self) -> Vec<u8> {
        let vk = VerifyingKey::from(&self.signing_key);
        vk.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Compressed public key as hex (66 chars) - suitable for exchange API key fields.
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.verifying_key_bytes_compressed())
    }

    // ── Signing ────────────────────────────────────────────────────────────

    /// Sign arbitrary bytes.
    ///
    /// Internally: SHA-256 the message, then ECDSA-sign the digest.
    /// Returns a 64-byte DER-normalised (low-s) signature.
    pub fn sign(&self, message: &[u8]) -> EcdsaSignatureResult {
        let signature: Signature = self.signing_key.sign(message);
        EcdsaSignatureResult {
            signature_bytes: signature.to_bytes().to_vec(),
            signature_hex: hex::encode(signature.to_bytes()),
            message_len: message.len(),
        }
    }

    /// Sign a UTF-8 string (convenience wrapper).
    pub fn sign_str(&self, message: &str) -> EcdsaSignatureResult {
        self.sign(message.as_bytes())
    }

    // ── Verification ───────────────────────────────────────────────────────

    /// Verify a (message, signature) pair against this key's public component.
    pub fn verify(&self, message: &[u8], signature_hex: &str) -> Result<bool> {
        let sig_bytes = hex::decode(signature_hex).map_err(|e| anyhow!("hex decode: {e}"))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| anyhow!("invalid signature bytes: {e}"))?;
        let vk = VerifyingKey::from(&self.signing_key);
        Ok(vk.verify(message, &signature).is_ok())
    }
}

/// Standalone public-key verifier - no private key required.
pub struct EcdsaVerifier {
    verifying_key: VerifyingKey,
}

impl EcdsaVerifier {
    /// Construct from a compressed (33-byte) or uncompressed (65-byte) hex public key.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| anyhow!("hex decode: {e}"))?;
        let point =
            EncodedPoint::from_bytes(bytes).map_err(|e| anyhow!("invalid SEC 1 point: {e}"))?;
        let verifying_key = VerifyingKey::from_encoded_point(&point)
            .map_err(|e| anyhow!("point not on curve: {e}"))?;
        Ok(Self { verifying_key })
    }

    /// Verify that `signature_hex` is a valid ECDSA signature over `message`.
    pub fn verify(&self, message: &[u8], signature_hex: &str) -> Result<bool> {
        let sig_bytes = hex::decode(signature_hex).map_err(|e| anyhow!("hex decode: {e}"))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| anyhow!("invalid signature bytes: {e}"))?;
        Ok(self.verifying_key.verify(message, &signature).is_ok())
    }
}

/// Result of an ECDSA signing operation.
#[derive(Debug, Clone)]
pub struct EcdsaSignatureResult {
    /// Raw 64-byte signature (r || s, big-endian).
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
        let signer = EcdsaSigner::generate();
        let msg = b"BTC/USDT buy 0.01 @ 65000 testnet";

        let result = signer.sign(msg);
        assert_eq!(result.signature_bytes.len(), 64);
        assert_eq!(result.signature_hex.len(), 128);

        let valid = signer.verify(msg, &result.signature_hex).unwrap();
        assert!(valid, "signature must verify against its own public key");
    }

    #[test]
    fn wrong_message_fails_verification() {
        let signer = EcdsaSigner::generate();
        let result = signer.sign(b"correct message");
        let valid = signer
            .verify(b"tampered message", &result.signature_hex)
            .unwrap();
        assert!(!valid, "modified message must not verify");
    }

    #[test]
    fn from_hex_roundtrip() {
        let original = EcdsaSigner::generate();
        let hex = original.private_key_hex();

        let restored = EcdsaSigner::from_hex(&hex).unwrap();
        assert_eq!(
            original.verifying_key_hex(),
            restored.verifying_key_hex(),
            "restored key must have same public key"
        );
    }

    #[test]
    fn standalone_verifier() {
        let signer = EcdsaSigner::generate();
        let msg = b"exchange API test payload";
        let result = signer.sign(msg);

        let verifier = EcdsaVerifier::from_hex(&signer.verifying_key_hex()).unwrap();
        let valid = verifier.verify(msg, &result.signature_hex).unwrap();
        assert!(valid);
    }

    #[test]
    fn cross_key_verification_fails() {
        let signer_a = EcdsaSigner::generate();
        let signer_b = EcdsaSigner::generate();

        let result = signer_a.sign(b"signed by A");
        // Verify with B's public key - must fail
        let valid = signer_b
            .verify(b"signed by A", &result.signature_hex)
            .unwrap();
        assert!(!valid, "signature from key A must not verify under key B");
    }
}
