# `tests/vectors/` — Known-Answer Test vectors

This directory ships with the `pqc-kem` crate package (see the `include`
list in [`Cargo.toml`](../../Cargo.toml)) so downstream integrators can reuse
the same vectors this crate tests against (FAB-001 I-3: "one test-vector
file shared across sig/kem/core"). All files are plain JSON with lowercase
hex strings (no `0x` prefix) — no binary blobs, no compression.

These vectors are exercised by `tests/kat_ml_kem.rs` and
`tests/kat_x25519.rs`, both gated behind the crate's `kat` Cargo feature
(non-default):

```sh
cargo test --features kat
```

The `kat` feature also adds a small number of deterministic, test-only
entry points to `MlKem512Keypair`/`MlKem768Keypair`/`MlKem1024Keypair`
(`from_seed_halves`, `encapsulate_deterministic`,
`from_expanded_decapsulation_key_bytes`,
`to_expanded_decapsulation_key_bytes`) and one free function,
`pqc_kem::fips203::hybrid::x25519_kat`, documented inline as
**testing/interop only — do not use for production key generation or key
exchange.**

## `ml-kem/{512,768,1024}/keygen.json` — FIPS 203 keyGen

**Provenance:** NIST ACVP-Server `ML-KEM-keyGen-FIPS203` test vector set
(`vsId 42`, `internalProjection.json`), the same file published upstream at
[`usnistgov/ACVP-Server`](https://github.com/usnistgov/ACVP-Server)
`gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json`. This
crate's copy was **not** fetched fresh from that GitHub repository (no
network access was available in the environment that vendored these files);
instead it was taken from the byte-identical copy that NIST's own reference
implementation vendors for its test suite: `liboqs` 0.13.0's
`tests/ACVP_Vectors/ML-KEM-keyGen-FIPS203/internalProjection.json`, reached
locally via the `oqs-sys 0.11.0+liboqs-0.13.0` crate's vendored source tree
under `%CARGO_HOME%/registry/src/*/oqs-sys-0.11.0+liboqs-0.13.0/liboqs/tests/ACVP_Vectors/`.
Both files carry the same `"vsId": 42` and are, byte for byte, the same
NIST-published ACVP internal-projection file (`liboqs` vendors it verbatim
for its own ACVP conformance tests). Extracted 2026-09-10.

**Format:** for each of the three parameter sets, `testType: "AFT"`, the
first 5 of that group's 25 test cases (`tcId`s 1–5 for ML-KEM-512, 26–30 for
ML-KEM-768, 51–55 for ML-KEM-1024 in the upstream numbering). Each case has:

| field | meaning |
|---|---|
| `d` | keyGen seed half `d` (32 bytes hex) |
| `z` | keyGen seed half `z` (32 bytes hex) |
| `ek` | expected encapsulation (public) key bytes |
| `dk` | expected decapsulation key, in ML-KEM's **expanded** legacy wire format (`ml_kem::ExpandedKeyEncoding`) — **not** the 64-byte `d ‖ z` seed. See the note field inside each JSON file. |

**Mapping to crate API:**
`MlKem768Keypair::from_seed_halves(&d, &z)` (feature `kat`) →
`.public_key().bytes` must equal `ek`;
`.to_expanded_decapsulation_key_bytes()` (feature `kat`) must equal `dk`.

## `ml-kem/{512,768,1024}/encap.json` — FIPS 203 encapDecap, AFT (encapsulation)

**Provenance:** same upstream/vendoring path as above, from
`ML-KEM-encapDecap-FIPS203/internalProjection.json` (`vsId 42`,
`isSample: true`). Extracted 2026-09-10. First 5 of each parameter set's 25
`testType: "AFT"`, `function: "encapsulation"` test cases.

**Format:** each case has `ek` (recipient public key), `m` (the 32-byte
explicit randomness FIPS 203 Algorithm 17 would otherwise draw from an
RNG), `c` (expected ciphertext), `k` (expected shared secret).

**Mapping to crate API:**
`MlKem768Keypair::encapsulate_deterministic(&pk, &m)` (feature `kat`) →
`(ct.bytes, ss.bytes)` must equal `(c, k)`.

## `ml-kem/{512,768,1024}/decap.json` — FIPS 203 encapDecap, VAL (decapsulation)

**Provenance:** same source file as `encap.json`. All 10 of each parameter
set's `testType: "VAL"`, `function: "decapsulation"` test cases (this group
is small enough to take in full).

**Format:** a single group-level `dk` (expanded decapsulation key, shared by
every case in the group) plus a `cases` array of `{c, k, reason}`. `reason`
is either `"valid decapsulation"` (an honest ciphertext) or
`"modified ciphertext"` (FIPS 203's **implicit-rejection** path — `c` does
not decrypt to a value consistent with re-encryption under `dk`). Both
kinds expect a deterministic `k`; a compliant decapsulation implementation
must **never** return an error or panic for a malformed `c` — only ever the
listed pseudorandom `k` (this is exactly the property the roadmap's X-4/P1
item calls out as needing coverage: "including implicit-rejection cases
where `ct` is malformed → expected `k`").

**Mapping to crate API:**
`MlKem768Keypair::from_expanded_decapsulation_key_bytes(&dk)` (feature
`kat`) then `.decapsulate(&ct)` → `.bytes` must equal `k`, for **every**
case regardless of `reason`.

## `x25519/rfc7748.json` — RFC 7748 X25519 vectors

**Provenance:** [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) (Langley,
Hamburg, Turner; January 2016), §5.2 ("Test Vectors") and §6.1
("Diffie-Hellman" / Curve25519 worked example). Fetched live from
`https://www.rfc-editor.org/rfc/rfc7748.txt` on 2026-09-10 and cross-checked
byte-for-byte against the independently-vendored copy of the same two §5.2
scalar-multiplication vectors and the §5.2 iterated (1 / 1,000 / 1,000,000
iteration) vectors in `x25519-dalek 2.0.1`'s own test suite
(`tests/x25519_tests.rs`, functions `rfc7748_ladder_test1_vectorset1`,
`rfc7748_ladder_test1_vectorset2`, and the `#[ignore]`-gated
`rfc7748_ladder_test2`), reached locally at
`%CARGO_HOME%/registry/src/*/x25519-dalek-2.0.1/tests/x25519_tests.rs`. Both
independent copies agreed exactly, byte for byte.

**Format:**
- `x25519_scalar_mult`: the two `X25519(scalar, u) = output` vectors from
  §5.2.
- `x25519_iterated`: the §5.2 "repeatedly apply X25519 starting from
  `k = u = 9`" vectors, at 1, 1,000, and 1,000,000 iterations (the last is
  marked `skip_by_default` — it is 1,000,000 sequential scalar
  multiplications and too slow for a normal `cargo test` run; `tests/kat_x25519.rs`
  only runs it under `--ignored`, matching `x25519-dalek`'s own convention).
- `x25519_diffie_hellman`: the §6.1 Alice/Bob Curve25519 ECDH worked
  example (fixed private keys, derived public keys, and the resulting
  shared secret `K`).

**Mapping to crate API:** this crate deliberately has **no general-purpose
public X25519 API** (X25519 is only ever used internally, as half of
[`HybridKemKeypair`](../../src/fips203/hybrid.rs)'s combiner) — see the
task constraints and `docs/gap-analysis/pqc-kem-gap-roadmap.md` §3.7. The
`kat` feature therefore adds one narrow free function purely for this test,
`pqc_kem::fips203::hybrid::x25519_kat(scalar: [u8; 32], u: [u8; 32]) -> [u8; 32]`,
a thin wrapper over `x25519_dalek::x25519` (the crate's existing dependency,
already in the default dependency graph). `tests/kat_x25519.rs` calls it
directly for every vector above.

## Regenerating / updating these vectors

`tests/vectors/regenerate-ml-kem-vectors.ps1` is the exact PowerShell script
used to (re-)extract `ml-kem/{512,768,1024}/{keygen,encap,decap}.json` from
the two upstream `internalProjection.json` files. It is not run by CI or
`cargo test`; it is a one-shot developer tool. To regenerate:

1. Obtain fresh copies of `ML-KEM-keyGen-FIPS203/internalProjection.json`
   and `ML-KEM-encapDecap-FIPS203/internalProjection.json`, either from
   `usnistgov/ACVP-Server`'s `gen-val/json-files/` directory (needs network
   access) or from a locally-cached `oqs-sys` vendored copy under
   `liboqs/tests/ACVP_Vectors/` (works offline once `cargo fetch` has
   populated `~/.cargo/registry/src/` for a crate graph that depends on
   `oqs-sys`, e.g. via this crate's own `hqc` feature).
2. Edit the two `$keygenSrc` / `$encdecSrc` paths at the top of
   `regenerate-ml-kem-vectors.ps1` to point at the fresh files.
3. Run `pwsh -File tests/vectors/regenerate-ml-kem-vectors.ps1` from the
   repository root. It overwrites the nine `ml-kem/*/*.json` files in place.
4. `cargo test --features kat` to confirm the regenerated vectors still
   pass.

The RFC 7748 vectors in `x25519/rfc7748.json` are static (RFC 7748 is not
expected to be revised); there is no regeneration script for that file —
re-copy the relevant hex strings from the RFC text (§5.2, §6.1) by hand if
ever needed, and re-cross-check against `x25519-dalek`'s test suite as
described above.
