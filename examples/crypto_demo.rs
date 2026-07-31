//! # Cryptographic Primitives Demo
//!
//! Demonstrates ECDSA (secp256k1), Ed25519 (Curve25519), and HMAC-SHA256/512
//! forward-engineered from their mathematical specifications.
//!
//! ```text
//! cargo run --example crypto_demo
//! ```

use anyhow::Result;
use hft_crypto::crypto::{
    ecdsa::{EcdsaSigner, EcdsaVerifier},
    ed25519::{Ed25519Signer, Ed25519Verifier},
    hmac::{hmac_sha256_hex, hmac_sha512_hex},
};

fn main() -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║         CRYPTOGRAPHIC PRIMITIVES - FORWARD-ENGINEERING          ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");

    demo_ecdsa()?;
    demo_ed25519()?;
    demo_hmac()?;

    println!("\n✓  All cryptographic demos completed successfully.");
    Ok(())
}

// ── ECDSA secp256k1 ────────────────────────────────────────────────────────────

fn demo_ecdsa() -> Result<()> {
    println!("\n── ECDSA / secp256k1  (FIPS 186-5)  ──────────────────────────────");

    let signer = EcdsaSigner::generate();
    println!("  Private key (32 B): {}…", &signer.private_key_hex()[..16]);
    println!(
        "  Public key  (33 B, compressed): {}",
        signer.verifying_key_hex()
    );

    let msg = b"BTC/USDT BUY 0.001 @ 65000 [testnet]";
    let result = signer.sign(msg);
    println!("  Message    : {}", String::from_utf8_lossy(msg));
    println!("  Signature  : {}…", &result.signature_hex[..32]);

    let ok = signer.verify(msg, &result.signature_hex)?;
    println!("  Verify ✓   : {ok}");

    // Demonstrate hex round-trip
    let restored = EcdsaSigner::from_hex(&signer.private_key_hex())?;
    assert_eq!(signer.verifying_key_hex(), restored.verifying_key_hex());
    println!("  Key round-trip from hex: ✓");

    // Demonstrate standalone verifier (public-key only)
    let verifier = EcdsaVerifier::from_hex(&signer.verifying_key_hex())?;
    assert!(verifier.verify(msg, &result.signature_hex)?);
    println!("  Standalone verifier: ✓");

    // Demonstrate tamper detection
    let tampered = signer.verify(b"tampered message", &result.signature_hex)?;
    println!("  Tampered message rejects: {}", !tampered);

    Ok(())
}

// ── Ed25519 Curve25519 ─────────────────────────────────────────────────────────

fn demo_ed25519() -> Result<()> {
    println!("\n── Ed25519 / Curve25519  (RFC 8032)  ──────────────────────────────");

    let signer = Ed25519Signer::generate();
    println!(
        "  Private seed (32 B): {}…",
        &signer.private_key_hex()[..16]
    );
    println!("  Public key   (32 B): {}", signer.verifying_key_hex());

    let msg = b"ETH/USDC SELL 1.5 @ 3200 [hyperliquid-testnet]";
    let result = signer.sign(msg);
    println!("  Message    : {}", String::from_utf8_lossy(msg));
    println!("  Signature  : {}…", &result.signature_hex[..32]);

    let ok = signer.verify(msg, &result.signature_hex)?;
    println!("  Verify ✓   : {ok}");

    // Determinism: same key + same message always produces the same signature
    let sig2 = signer.sign(msg);
    let deterministic = result.signature_hex == sig2.signature_hex;
    println!("  Deterministic (same msg → same sig): {deterministic}");

    // Standalone verifier
    let verifier = Ed25519Verifier::from_hex(&signer.verifying_key_hex())?;
    assert!(verifier.verify(msg, &result.signature_hex)?);
    println!("  Standalone verifier: ✓");

    Ok(())
}

// ── HMAC ───────────────────────────────────────────────────────────────────────

fn demo_hmac() -> Result<()> {
    println!("\n── HMAC-SHA256  (RFC 2104 / NIST RFC 4231 §4.2 test vector)  ──────");

    // NIST test vector
    let nist_key = vec![0x0bu8; 20];
    let nist_data = b"Hi There";
    let nist_mac = hmac_sha256_hex(&nist_key, nist_data)?;
    let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    println!("  NIST key    : 0x0b × 20");
    println!("  NIST data   : \"Hi There\"");
    println!("  HMAC-SHA256 : {nist_mac}");
    println!(
        "  NIST vector : {}",
        if nist_mac == expected {
            "✓ PASS"
        } else {
            "✗ FAIL"
        }
    );

    // Realistic exchange payload
    let key = b"exchange-api-secret-key";
    let payload = b"timestamp=1700000000000&symbol=BTCUSDT&side=BUY&quantity=0.001";
    let mac = hmac_sha256_hex(key, payload)?;
    println!("\n  Exchange payload HMAC-SHA256:");
    println!("  Key     : {}", String::from_utf8_lossy(key));
    println!("  Payload : {}", String::from_utf8_lossy(payload));
    println!("  MAC     : {mac}");

    // HMAC-SHA512 (Kraken)
    println!("\n── HMAC-SHA512  (Kraken variant)  ─────────────────────────────────");
    let kraken_key = b"kraken-api-secret-bytes";
    let kraken_msg = b"1700000000000000/0/private/Balance";
    let mac512 = hmac_sha512_hex(kraken_key, kraken_msg)?;
    println!("  HMAC-SHA512 (first 64 chars): {}…", &mac512[..64]);

    Ok(())
}
