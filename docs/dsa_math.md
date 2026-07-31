# DSA Forward Engineering - Mathematical Notes

Companion reference to the in-source documentation in `src/crypto/`.

---

## ECDSA - secp256k1 (FIPS 186-5 / SEC 1 v2.0)

### Domain parameters

| Symbol | Value / description |
|--------|---------------------|
| `p` | 2²⁵⁶ − 2³² − 977 (256-bit prime field modulus) |
| `a`, `b` | 0, 7 (Weierstrass form: y² ≡ x³ + 7 mod p) |
| `G` | Base point (33-byte compressed SEC 1 encoding on-chain) |
| `n` | Group order (256-bit prime; number of points) |
| `h` | Cofactor = 1 |

### Key generation

```
d ←$ [1, n−1]          private scalar (CSPRNG)
Q = d·G                public key (point multiplication)
```

### Signing (message `m`, private key `d`)

```
e = SHA-256(m)          message digest as big-endian integer
k ←$ [1, n−1]          ephemeral scalar (new per signature - NEVER reuse)
R = k·G
r = R.x mod n           x-coordinate of ephemeral point
s = k⁻¹ · (e + r·d) mod n
Signature = (r, s)      64 bytes: 32 bytes each, big-endian
```

### Verification (message `m`, public key `Q`, signature `(r,s)`)

```
e = SHA-256(m)
w = s⁻¹ mod n
u₁ = e·w mod n
u₂ = r·w mod n
X = u₁·G + u₂·Q
Valid iff X.x mod n == r
```

### HFT relevance

- **Native EVM curve**: Bitcoin, Ethereum, and all EVM chains use secp256k1, so the same
  key material can sign both on-chain transactions and exchange REST requests.
- **64-byte compact form**: exchanges accept raw `r‖s` (no DER overhead).
- **k-reuse is catastrophic**: reusing `k` across two signatures leaks `d`. The k256 crate
  uses RFC 6979 deterministic `k` generation, eliminating this risk.

---

## Ed25519 - Twisted Edwards / Curve25519 (RFC 8032)

### Domain parameters

| Symbol | Value / description |
|--------|---------------------|
| `p` | 2²⁵⁵ − 19 |
| Curve | −x² + y² ≡ 1 + d·x²·y² mod p (Twisted Edwards) |
| `d` | −121665/121666 mod p |
| `B` | Base point (y = 4/5 mod p, x > 0) |
| `ℓ` | 2²⁵² + 27742317777372353535851937790883648493 |
| `h` | Cofactor = 8 |

### Key generation

```
s  = 32-byte CSPRNG seed        private key
H  = SHA-512(s)                 64 bytes
a  = clamp(H[0..32])            private scalar
   clamp: H[0] &= 248; H[31] &= 127; H[31] |= 64
A  = a·B                        public key (32-byte compressed point)
P  = H[32..64]                  nonce prefix (secret, deterministic)
```

### Signing (message `M`)

```
r = SHA-512(P ‖ M) mod ℓ        deterministic - no random k!
R = r·B                         32-byte compressed point
S = (r + SHA-512(R ‖ A ‖ M) · a) mod ℓ
Signature = R ‖ S               64 bytes total
```

### Verification (message `M`, public key `A`, signature `R‖S`)

```
k = SHA-512(R ‖ A ‖ M) mod ℓ
Valid iff 8·S·B == 8·R + 8·k·A   (cofactor multiplication prevents small-subgroup attacks)
```

### HFT relevance

- **Deterministic**: eliminates RNG side-channel attacks; critical in co-location environments.
- **~10× faster** signing than ECDSA secp256k1 on the same hardware.
- **Compact**: 64-byte signatures, 32-byte public keys.
- **Hyperliquid + Solana**: both use Ed25519 natively; the same key signs both exchange
  REST actions and on-chain transactions.

---

## HMAC - RFC 2104

```
HMAC-SHA256(K, M):
  if |K| > B: K = SHA-256(K)     B = 64 bytes for SHA-256
  if |K| < B: K = K ‖ 0×00..    pad to B bytes
  i_key_pad = K ⊕ (0x36 × B)
  o_key_pad = K ⊕ (0x5C × B)
  inner      = SHA-256(i_key_pad ‖ M)
  result     = SHA-256(o_key_pad ‖ inner)
```

### Exchange usage

| Exchange | Variant | Signature format |
|----------|---------|-----------------|
| Binance | HMAC-SHA256 | hex in query string |
| OKX | HMAC-SHA256 | base64 in header |
| Bybit | HMAC-SHA256 | hex in header |
| Coinbase | HMAC-SHA256 | hex in header |
| KuCoin | HMAC-SHA256 | base64 in header + passphrase |
| Kraken | HMAC-SHA512 | base64 in header |
