//! Integration tests - cryptographic primitives

use hft_crypto::crypto::{
    ecdsa::{EcdsaSigner, EcdsaVerifier},
    ed25519::{Ed25519Signer, Ed25519Verifier},
    hmac::{hmac_sha256_base64, hmac_sha256_hex, hmac_sha512_hex},
};

#[test]
fn ecdsa_public_key_is_33_bytes_compressed() {
    let signer = EcdsaSigner::generate();
    let pub_bytes = signer.verifying_key_bytes_compressed();
    assert_eq!(pub_bytes.len(), 33);
    assert!(pub_bytes[0] == 0x02 || pub_bytes[0] == 0x03);
}

#[test]
fn ecdsa_sign_verify_multiple_messages() {
    let signer = EcdsaSigner::generate();
    for msg in &[
        b"BTC/USDT BUY 0.001" as &[u8],
        b"ETH/USDC SELL 1.5",
        b"",
        b"a",
    ] {
        let result = signer.sign(msg);
        assert!(signer.verify(msg, &result.signature_hex).unwrap());
    }
}

#[test]
fn ecdsa_standalone_verifier_works() {
    let signer = EcdsaSigner::generate();
    let msg = b"standalone verifier integration test";
    let result = signer.sign(msg);
    let verifier = EcdsaVerifier::from_hex(&signer.verifying_key_hex()).unwrap();
    assert!(verifier.verify(msg, &result.signature_hex).unwrap());
}

#[test]
fn ecdsa_wrong_key_rejects_signature() {
    let signer_a = EcdsaSigner::generate();
    let signer_b = EcdsaSigner::generate();
    let result = signer_a.sign(b"signed by A");
    let verifier_b = EcdsaVerifier::from_hex(&signer_b.verifying_key_hex()).unwrap();
    assert!(
        !verifier_b
            .verify(b"signed by A", &result.signature_hex)
            .unwrap()
    );
}

#[test]
fn ed25519_signature_is_64_bytes() {
    let signer = Ed25519Signer::generate();
    let result = signer.sign(b"test");
    assert_eq!(result.signature_bytes.len(), 64);
    assert_eq!(result.signature_hex.len(), 128);
}

#[test]
fn ed25519_deterministic_property() {
    let signer = Ed25519Signer::generate();
    let msg = b"same message";
    let sigs: Vec<_> = (0..5).map(|_| signer.sign(msg).signature_hex).collect();
    assert!(sigs.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn ed25519_standalone_verifier() {
    let signer = Ed25519Signer::generate();
    let msg = b"ed25519 verifier test";
    let result = signer.sign(msg);
    let verifier = Ed25519Verifier::from_hex(&signer.verifying_key_hex()).unwrap();
    assert!(verifier.verify(msg, &result.signature_hex).unwrap());
}

#[test]
fn ed25519_cross_key_rejection() {
    let a = Ed25519Signer::generate();
    let b = Ed25519Signer::generate();
    let result = a.sign(b"message");
    assert!(!b.verify(b"message", &result.signature_hex).unwrap());
}

/// RFC 4231 §4.2 NIST test vector
#[test]
fn hmac_sha256_nist_test_vector() {
    let key = vec![0x0bu8; 20];
    let result = hmac_sha256_hex(&key, b"Hi There").unwrap();
    assert_eq!(
        result,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn hmac_sha256_base64_is_44_chars() {
    let result = hmac_sha256_base64(b"key", b"message").unwrap();
    assert_eq!(result.len(), 44);
}

#[test]
fn hmac_sha512_output_is_128_hex_chars() {
    let result = hmac_sha512_hex(b"key", b"message").unwrap();
    assert_eq!(result.len(), 128);
}
