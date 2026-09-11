# Hybrid KEM Profiles — `HybridKem-X25519-MLKEM768-v1` and `-v2` (X-Wing)

**Status:** normative for this crate (`pqc-kem`), version 0.3.0. Satisfies gap
item K-5 ("Hybrid construction not specified as a named profile") from
[`docs/gap-analysis/pqc-kem-gap-roadmap.md`](gap-analysis/pqc-kem-gap-roadmap.md)
§3.6/WP5, per the user decision on Open Question Q2 (§5): formalize the
existing v1 combiner as a named profile **and** add X-Wing as a second named
profile (`-v2`), recommended for new deployments. **v1 remains wire-compatible
with what SAGP consumes today** — this document changes no bytes, only names
and publishes them.

Both profiles combine the same two component algorithms — **X25519**
(elliptic-curve Diffie-Hellman, [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) §5)
and **ML-KEM-768** (NIST FIPS 203, Security Level 3) — and produce
identically-sized artifacts (1216-byte public key, 1120-byte ciphertext,
32-byte shared secret). They differ in **combiner** and **byte layout**, and
are **not interoperable with each other** — a v1 ciphertext cannot be
decapsulated by a v2/X-Wing keypair and vice versa (see
[Cross-profile confusion](#cross-profile-confusion) below).

| | Profile ID | Rust type | Combiner | pk layout | ct layout | Recommended for |
|---|---|---|---|---|---|---|
| **v1** | `HybridKem-X25519-MLKEM768-v1` | [`fips203::HybridKemKeypair`](../src/fips203/hybrid.rs) | `HKDF-SHA256` | `x25519(32) ‖ mlkem(1184)` | `x25519(32) ‖ mlkem(1088)` | Existing SAGP deployments (wire-compat) |
| **v2** | `HybridKem-X25519-MLKEM768-v2` | [`fips203::XWingKeypair`](../src/fips203/xwing.rs) | `SHA3-256` (X-Wing) | `mlkem(1184) ‖ x25519(32)` | `mlkem(1088) ‖ x25519(32)` | **New deployments** |

Profile identifier constants live at the crate root:

```rust
pub const HYBRID_PROFILE_V1: &str = "HybridKem-X25519-MLKEM768-v1";
pub const HYBRID_PROFILE_V2: &str = "HybridKem-X25519-MLKEM768-v2";
/// Alias for HYBRID_PROFILE_V1, kept for compatibility with code that
/// already treats this constant as PRIMARY_ALGORITHM's hybrid construction.
pub const HYBRID_PROFILE_ID: &str = HYBRID_PROFILE_V1;
```

and a `HybridProfile` enum in [`src/types.rs`](../src/types.rs):

```rust
pub enum HybridProfile { V1, V2XWing }
impl HybridProfile {
    pub fn id(&self) -> &'static str;   // HYBRID_PROFILE_V1 / HYBRID_PROFILE_V2
    pub fn pk_len(&self) -> usize;      // 1216 for both
    pub fn ct_len(&self) -> usize;      // 1120 for both
    pub fn sk_len(&self) -> usize;      // 96 (v1) / 32 (v2)
}
```

`PRIMARY_ALGORITHM`/`HYBRID_PROFILE_ID` still point at **v1** in this
release, for wire compatibility with existing SAGP deployments.

---

## 1. Profile v1 — `HybridKem-X25519-MLKEM768-v1`

This is exactly the combiner this crate has shipped since 0.1.0
([`src/fips203/hybrid.rs`](../src/fips203/hybrid.rs)), now formally named and
given a canonical byte encoding. **No behavior changes** — `HybridKemKeypair::{generate,
encapsulate, encapsulate_to, decapsulate}` are byte-for-byte/behavior-identical
to prior releases, and the JSON wire format of `HybridPublicKey`/
`HybridKemCiphertext` is unchanged.

### 1.1 Components

- **X25519** (classical): [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
  §5, via the `x25519-dalek` crate (`StaticSecret`/`EphemeralSecret`).
- **ML-KEM-768** (post-quantum): NIST FIPS 203, via the `ml-kem` crate
  (RustCrypto).

### 1.2 Key generation

```text
x25519_sk       = random(32)                      // clamped per RFC 7748 §5
(d, z)          = random(32), random(32)           // FIPS 203 KeyGen seed
(pk_M, sk_M)    = ML-KEM-768.KeyGen_internal(d, z)
pk_X            = X25519(x25519_sk, X25519_BASE)
pk              = concat(pk_X, pk_M)                // 32 + 1184 = 1216 bytes
sk (storage)    = concat(x25519_sk, d, z)           // 32 + 32 + 32 = 96 bytes
```

`ml_kem::DecapsulationKey::from_seed(d ‖ z)` is exactly
`ML-KEM-768.KeyGen_internal(d, z)` — see
[`src/fips203/hybrid.rs`](../src/fips203/hybrid.rs)'s `generate()`.

### 1.3 Encapsulation

```text
x25519_ss  = X25519(ephemeral_sk, recipient_pk_X)
(ct_M, mlkem_ss) = ML-KEM-768.Encaps(recipient_pk_M)
combined   = x25519_ss ‖ mlkem_ss                   // 32 + 32 = 64 bytes
shared_key = HKDF-SHA256(ikm = combined, salt = ∅, info = "pqc-kem-hybrid-v1", L = 32)
ct         = concat(ephemeral_pk_X, ct_M)           // 32 + 1088 = 1120 bytes
```

The exact HKDF call, verified against [`src/fips203/hybrid.rs`](../src/fips203/hybrid.rs):

```rust
let hkdf = Hkdf::<Sha256>::new(None, &combined);   // salt = None
let mut shared_key = [0u8; 32];
hkdf.expand(b"pqc-kem-hybrid-v1", &mut shared_key)
    .map_err(|e| KemError::KeyDerivation(format!("{:?}", e)))?;
```

- `salt = None` — HKDF-Extract uses an all-zero salt (this is `hkdf`'s
  documented behavior for `new(None, ikm)`).
- `info = b"pqc-kem-hybrid-v1"` (18 ASCII bytes, no trailing NUL) — this is
  also exported as [`pqc_kem::HYBRID_KEM_INFO`](../src/lib.rs).
- `L = 32` bytes of output.

### 1.4 Decapsulation

```text
x25519_ss  = X25519(recipient_sk_X, ct_x25519_eph_pk)
mlkem_ss   = ML-KEM-768.Decaps(ct_M, recipient_sk_M)
combined   = x25519_ss ‖ mlkem_ss
shared_key = HKDF-SHA256(combined, info="pqc-kem-hybrid-v1", L=32)
```

Identical combiner logic to encapsulation, run with the recipient's secret
components instead of the sender's ephemeral/randomness inputs.

### 1.5 Byte layouts

| Artifact | Layout | Size |
|---|---|---|
| Public key (`HybridPublicKey`) | `x25519_pk(32) ‖ mlkem_ek(1184)` | 1216 bytes |
| Ciphertext (`HybridKemCiphertext`) | `x25519_eph_pk(32) ‖ mlkem_ct(1088)` | 1120 bytes |
| Secret key (storage only — never on the wire) | `x25519_sk(32) ‖ mlkem_d(32) ‖ mlkem_z(32)` | 96 bytes |
| Shared secret | HKDF-SHA256 output | 32 bytes |

**Note the byte order: X25519 first, ML-KEM second** — the opposite of
X-Wing's `mlkem ‖ x25519` (§2.5 below). This matches
[`src/types.rs`](../src/types.rs)'s existing `HybridPublicKey::new`/
`HybridKemCiphertext::new` construction order (`x25519_pub, mlkem_pub`).

### 1.6 Security note: v1 does **not** bind ciphertext/public key into the KDF

Unlike X-Wing's combiner (§2.4), v1's `HKDF-SHA256(x25519_ss ‖ mlkem_ss, ...)`
does not additionally hash in `ct_X` (the X25519 ephemeral public key) or
`pk_X` (the recipient's X25519 public key). This means v1 does not achieve the
`MAL-BIND-K-PK`/`MAL-BIND-K-CT` binding properties X-Wing's proof
([Barbosa et al., "X-Wing: The Hybrid KEM You've Been Looking For",
IACR ePrint 2024/039](https://eprint.iacr.org/2024/039)) establishes for that
construction. In practice: ML-KEM-768's own Fujisaki–Okamoto ciphertext
binding still covers the post-quantum half of the combined secret (an
attacker cannot produce a different `ct_M` that decapsulates to the same
`mlkem_ss` under a *different* recipient key without breaking ML-KEM), but
`HybridKemKeypair` has not been proven to satisfy the same formal composite
binding X-Wing has. This is the primary security-engineering reason v1 is
not the profile recommended for **new** deployments — see §2 for X-Wing,
which is.

### 1.7 Rust API (v1)

```rust
impl HybridPublicKey {
    pub const BYTES: usize = 1216;
    pub fn to_bytes(&self) -> KemResult<Vec<u8>>;
    pub fn from_bytes(bytes: &[u8]) -> KemResult<Self>;
}
impl HybridKemCiphertext {
    pub const BYTES: usize = 1120;
    pub fn to_bytes(&self) -> KemResult<Vec<u8>>;
    pub fn from_bytes(bytes: &[u8]) -> KemResult<Self>;
}
impl HybridKemKeypair {
    pub fn to_secret_bytes(&self) -> KemResult<KemSecretKey>;   // 96 B, zeroizing
    pub fn from_secret_bytes(bytes: &[u8]) -> KemResult<Self>;
}
#[cfg(feature = "kat")]
impl HybridKemKeypair {
    pub fn from_secrets(x25519_sk: &[u8; 32], d: &[u8; 32], z: &[u8; 32]) -> Self;
    pub fn encapsulate_deterministic(
        recipient_public_key: &HybridPublicKey,
        eph_x25519_sk: &[u8; 32],
        m: &[u8; 32],
    ) -> KemResult<(HybridKemCiphertext, SharedSecret)>;
}
```

All `to_bytes`/`from_bytes` methods are length-checked and return
[`KemError::InvalidKey`]/[`KemError::InvalidCiphertext`] on mismatch — **never
panic** on untrusted input. The JSON (`serde`) representation of
`HybridPublicKey`/`HybridKemCiphertext` is **unchanged**; the byte-encoding
API above is additive.

---

## 2. Profile v2 — `HybridKem-X25519-MLKEM768-v2` (X-Wing)

X-Wing is a general-purpose, standardized PQ/T hybrid KEM combining X25519
and ML-KEM-768, specified in
**`draft-connolly-cfrg-xwing-kem-10`** (IETF CFRG, content dated
**2026-03-02**, published 2026-09-03 — fetched from
<https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.txt> and
cross-checked against the authors' GitHub repository
[`dconnolly/draft-connolly-cfrg-xwing-kem`](https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem),
commit `9b6ce9e614811dba8d46841052f3883cbc4c1a65`, which matches the `-10`
text byte-for-byte). Authors: Deirdre Connolly (SandboxAQ), Peter Schwabe
(MPI-SP & Radboud University), Bas Westerbaan (Cloudflare).

This crate implements X-Wing **natively** (not via the `x-wing` RustCrypto
crate) using its existing `ml-kem`, `x25519-dalek`, and (newly added) `sha3`
dependencies, so it stays `no_std`/`alloc`-only and does not pull in an
additional pre-release KEM crate. The implementation is verified byte-for-byte
against all 3 of the draft's own published test vectors — see §4.

### 2.1 Components

Identical to v1 (X25519 + ML-KEM-768), but combined differently.

### 2.2 Key generation

```text
sk = random(32)                          // the entire X-Wing secret key
expandDecapsulationKey(sk):
  expanded = SHAKE256(sk, 96 bytes)
  d, z, sk_X = expanded[0:32], expanded[32:64], expanded[64:96]
  (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(d, z)
  pk_X = X25519(sk_X, X25519_BASE)
pk = concat(pk_M, pk_X)                  // 1184 + 32 = 1216 bytes
```

The 32-byte seed **is** the decapsulation key — nothing else needs to be
stored (contrast with v1's 96-byte `x25519_sk ‖ d ‖ z`).

### 2.3 Encapsulation

```text
Encapsulate(pk):
  pk_M, pk_X = pk[0:1184], pk[1184:1216]
  ek_X = random(32)
  ct_X = X25519(ek_X, X25519_BASE)
  ss_X = X25519(ek_X, pk_X)
  (ss_M, ct_M) = ML-KEM-768.Encaps(pk_M)
  ss = Combiner(ss_M, ss_X, ct_X, pk_X)
  ct = concat(ct_M, ct_X)                // 1088 + 32 = 1120 bytes
```

### 2.4 Combiner

```text
Combiner(ss_M, ss_X, ct_X, pk_X) = SHA3-256(concat(ss_M, ss_X, ct_X, pk_X, XWingLabel))
```

`XWingLabel` is the 6-byte ASCII string `"\./" "/^\"`, hex
`5c 2e 2f 2f 5e 5c` (draft §4.4: "Move label at the end. As everything fits
within a single block of SHA3-256, this does not make any difference.").

**This is what X-Wing binds that v1 does not**: `ct_X` (the sender's X25519
ephemeral public key) and `pk_X` (the recipient's X25519 public key) are both
hashed directly into the combined shared secret, giving X-Wing the
`MAL-BIND-K-PK`/`MAL-BIND-K-CT` properties noted in §1.6. The draft explicitly
does **not** hash in `ct_M` (the ML-KEM ciphertext) — this is a deliberate
performance/simplicity choice justified by ML-KEM-768's own FO-transform
ciphertext binding (draft §3.2 "Security Considerations" / design goals).

### 2.5 Byte layouts — **ML-KEM first** (opposite of v1)

| Artifact | Layout | Size |
|---|---|---|
| Public key (`XWingPublicKey`) | `pk_M(1184) ‖ pk_X(32)` | 1216 bytes |
| Ciphertext (`XWingCiphertext`) | `ct_M(1088) ‖ ct_X(32)` | 1120 bytes |
| Secret key (the seed itself) | 32 raw bytes | 32 bytes |
| Shared secret | SHA3-256 output | 32 bytes |

Do not mix v1 and v2 byte encodings — see [§5](#cross-profile-confusion).

### 2.6 Rust API (v2 / X-Wing)

```rust
pub struct XWingPublicKey(pub [u8; 1216]);
pub struct XWingCiphertext(pub [u8; 1120]);

impl XWingPublicKey {
    pub const BYTES: usize = 1216;
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(bytes: &[u8]) -> KemResult<Self>;
}
impl XWingCiphertext {
    pub const BYTES: usize = 1120;
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(bytes: &[u8]) -> KemResult<Self>;
}

pub struct XWingKeypair { /* ... */ }        // ZeroizeOnDrop
impl XWingKeypair {
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> KemResult<Self>;
    pub fn from_seed(seed: &[u8; 32]) -> Self;             // GenerateKeyPairDerand
    pub fn public_key(&self) -> XWingPublicKey;
    pub fn seed(&self) -> KemSecretKey;                    // 32 B, zeroizing
    pub fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R, recipient_pk: &XWingPublicKey,
    ) -> KemResult<(XWingCiphertext, SharedSecret)>;
    pub fn decapsulate(&self, ciphertext: &XWingCiphertext) -> KemResult<SharedSecret>;
}
#[cfg(feature = "kat")]
impl XWingKeypair {
    /// EncapsulateDerand(pk, eseed) — eseed[0:32] = m (ML-KEM randomness),
    /// eseed[32:64] = ek_X (X25519 ephemeral scalar). Matches the draft's
    /// own published test-vector `eseed` field exactly.
    pub fn encapsulate_deterministic(
        recipient_pk: &XWingPublicKey, eseed: &[u8; 64],
    ) -> KemResult<(XWingCiphertext, SharedSecret)>;
}
```

`KemAlgorithm::XWing` (serde name `x_wing`, `public_key_size() == 1216`,
`ciphertext_size() == 1120`) identifies X-Wing in the shared `KemAlgorithm`
enum for callers that want a uniform algorithm tag across all of this
crate's KEMs.

`from_seed` is a stable (not `kat`-gated) constructor: the draft explicitly
permits implementations to expose `GenerateKeyPairDerand(sk)` as ordinary API
("For testing, it is convenient to have a deterministic version... An
implementation MAY provide the following derandomized variant"), and
`GenerateKeyPair()` is defined as exactly `GenerateKeyPairDerand(random(32))`.

---

## 3. Which profile to choose

- **New deployments, no existing wire format to preserve:** use **v2 /
  X-Wing** (`XWingKeypair`). It has a standards-track IETF specification, a
  formal security proof establishing composite binding properties v1 lacks
  (§1.6), and published test vectors independently checkable against other
  implementations (Apple CryptoKit, BoringSSL, Cloudflare CIRCL, RustCrypto
  `x-wing`, and others — see the draft's "Implementations" appendix).
- **Existing SAGP / `pqc-kem` 0.1.x–0.2.x deployments:** stay on **v1**
  (`HybridKemKeypair`) — it is `PRIMARY_ALGORITHM`, `HYBRID_PROFILE_ID` still
  points at it, and its JSON wire format and combiner are byte-for-byte
  unchanged from every prior release.

Both profiles ship in this crate simultaneously; choosing one does not
require dropping the other, and a single process can use both for different
purposes (e.g. a v1 peer migrating to v2 over time).

---

## 4. Test-vector format and provenance

### 4.1 v1 — `tests/vectors/hybrid-v1/vectors.json`

**5 deterministic vectors**, generated by this crate itself via the
`kat`-gated `HybridKemKeypair::{from_secrets, encapsulate_deterministic}`
entry points, then frozen so future refactors of `hybrid.rs` cannot silently
change v1's wire/KDF behavior without `tests/kat_hybrid_v1.rs` failing.

**No second, independent implementation of this exact combiner exists** (see
[`tests/vectors/README.md`](../tests/vectors/README.md) for the full
statement) — this is exactly the gap PG-001/K-5 called out
("...a test vector vs a second implementation, if one exists"). To partially
close it despite that, `tests/kat_hybrid_v1.rs::independent_recomputation_of_first_vector`
reimplements the entire v1 combiner from scratch for the first vector using
`x25519_dalek::x25519`, `ml_kem::{DecapsulationKey, EncapsulationKey}`, and
`hkdf::Hkdf<sha2::Sha256>` **directly** — never calling
`HybridKemKeypair::{encapsulate, encapsulate_deterministic, decapsulate}` —
and checks the result against the same frozen `pk`/`ct`/`ss` fields the main
KAT loop checks via the crate's own API. This is a within-crate,
cross-code-path check (both paths ultimately depend on the same `ml-kem`/
`x25519-dalek` crates), not a genuinely independent second implementation;
option (b) below (X-Wing) is what actually provides that.

Each vector object:

| Field | Meaning |
|---|---|
| `x25519_sk` | 32-byte X25519 static secret (hex) |
| `d`, `z` | FIPS 203 ML-KEM-768 keyGen seed halves (hex, 32 bytes each) |
| `eph_x25519_sk` | 32-byte deterministic X25519 ephemeral secret (hex) |
| `m` | 32-byte deterministic ML-KEM-768 encapsulation randomness (hex) |
| `pk` | expected 1216-byte v1 public key (hex) |
| `ct` | expected 1120-byte v1 ciphertext (hex) |
| `ss` | expected 32-byte shared secret (hex) |

### 4.2 v2 / X-Wing — `tests/vectors/xwing/xwing.json`

**All 3 vectors** from the draft's own machine-readable test-vector file,
vendored verbatim (no vectors omitted): fetched from
`spec/test-vectors.json` in
[`dconnolly/draft-connolly-cfrg-xwing-kem`](https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem),
commit `9b6ce9e614811dba8d46841052f3883cbc4c1a65` (same commit as the draft
text above), on 2026-09-11.

Each vector object (draft field names, unchanged):

| Field | Meaning |
|---|---|
| `seed` | 32-byte X-Wing decapsulation key (hex) — equals `sk` |
| `eseed` | 64-byte deterministic encapsulation randomness (hex): `eseed[0:32]` = ML-KEM-768 `m`, `eseed[32:64]` = X25519 ephemeral scalar |
| `sk` | the decapsulation key (equals `seed`) |
| `pk` | expected 1216-byte public key (hex) |
| `ct` | expected 1120-byte ciphertext (hex) |
| `ss` | expected 32-byte shared secret (hex) |

`tests/kat_xwing.rs` checks, for every vector: `seed → pk` (keygen),
`(pk, eseed) → (ct, ss)` (deterministic encapsulation), and `(sk, ct) → ss`
(decapsulation) — **all 3 vectors pass** against this crate's native X-Wing
implementation.

See [`tests/vectors/README.md`](../tests/vectors/README.md) for the same
provenance in the shared vectors index.
