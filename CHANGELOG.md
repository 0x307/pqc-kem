# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [0.3.0] - Unreleased

Work packages WP1–WP6 of the 0.3.0 work plan, plus pre-release hardening. WP1 addresses
K-1 (broken `bike`/`mceliece` feature flags), K-3 (the `ntru` ghost module), and the
unused-dependency findings; WP2 addresses A-Z1 (incomplete zeroization of secret key
material); WP3 is CI and documentation coverage; WP4 adds Known-Answer Tests; WP5 names
the hybrid construction as a versioned profile and adds X-Wing as its successor; WP6 adds
the `aead-wrap` sealed-box helper and brings the JavaScript bindings up to date. This is
a breaking release per `STABILITY.md` §2 (removed public modules/features); see
"Migration from 0.2.x" below.

The X25519+ML-KEM-768 hybrid remains `PRIMARY_ALGORITHM` and is on in every build.

### Added (WP2 — A-Z1 secret-material hardening)

- **`HybridKemKeypair::x25519_secret() -> KemSecretKey`** — returns the 32-byte X25519
  static secret as a zeroizing `KemSecretKey` (algorithm tag
  `KemAlgorithm::HybridX25519MlKem768`). Replaces the deprecated
  `x25519_secret_bytes()`, which returned a plain, non-zeroizing `[u8; 32]`.
- **`HybridKemKeypair::mlkem_seed() -> KemResult<KemSecretKey>`** — returns the 64-byte
  ML-KEM-768 seed (`d ‖ z`) as a zeroizing `KemSecretKey` (algorithm tag
  `KemAlgorithm::MlKem768`). Replaces the deprecated `mlkem_secret_bytes()`, which both
  returned a plain, non-zeroizing `Vec<u8>` *and* silently returned an empty `Vec`
  instead of an error when the underlying seed was unavailable.
- **`MlKem512Keypair::try_secret_key()`, `MlKem768Keypair::try_secret_key()`,
  `MlKem1024Keypair::try_secret_key() -> KemResult<KemSecretKey>`** — fallible form of
  the existing `secret_key()`. Returns `Err(KemError::Internal(..))` instead of
  silently returning an empty seed if the underlying `ml_kem::DecapsulationKey` has no
  recoverable seed (this cannot happen for keys built via this crate's own public
  constructors, but the fallible path now exists so callers never observe a
  silently-empty secret key by accident).
- **`tests/zeroize_tests.rs`** — compile-time `ZeroizeOnDrop` assertions for
  `HybridKemKeypair`, `MlKem{512,768,1024}Keypair`, `KemSecretKey`, `SharedSecret`, and
  (under `--features hqc`) `Hqc{128,192,256}Keypair`; behavioral-equivalence tests
  between each deprecated raw-byte accessor and its zeroizing replacement; round-trip
  encapsulate/decapsulate tests after keypair reconstruction from the new accessors'
  output.

### Changed (WP2 — A-Z1 secret-material hardening)

- **BREAKING (dependency feature change, not API): `x25519-dalek`'s `zeroize` feature
  is now enabled.** Previously `x25519-dalek` was declared with
  `default-features = false, features = ["static_secrets"]` only, which left its
  optional `zeroize` dependency disabled — `StaticSecret`/`EphemeralSecret` carried no
  `Drop` impl and were never zeroized. Now `features = ["static_secrets", "zeroize"]`;
  `default-features = false` and `no_std` compatibility are unchanged (`zeroize` does
  not require `alloc`).
- **`ml-kem`'s `zeroize` feature is now enabled** (`features = ["alloc", "zeroize"]`,
  was `features = ["alloc"]`). This gives `ml_kem::DecapsulationKey<P>` a real `Drop`
  impl (upstream, in `ml-kem` 0.3.2) that zeroizes the 64-byte seed (`d ‖ z`) and the
  expanded decryption key.
- **The `zeroize` dependency now explicitly enables its `alloc` feature**
  (`features = ["derive", "alloc"]`, was `features = ["derive"]`) so
  `Vec<u8>: Zeroize`/`ZeroizeOnDrop` — used by `KemSecretKey`, `SharedSecret`, and the
  `hqc`-feature keypair types below — is guaranteed available under every feature
  combination this crate supports (including `--no-default-features`), rather than
  relying on feature unification from other dependencies in the build graph.
- **`HybridKemKeypair`, `MlKem512Keypair`, `MlKem768Keypair`, and `MlKem1024Keypair` now
  implement `zeroize::ZeroizeOnDrop`.** No explicit `Drop` was needed on these
  wrapper structs: their secret-bearing fields (`x25519_dalek::StaticSecret` and
  `ml_kem::DecapsulationKey`) now zeroize themselves on drop (see the two feature
  changes above), and Rust's ordinary field-drop glue reaches them automatically.
  `EncapsulationKey`/`PublicKey` fields hold only public material and are not zeroized.
- **`Hqc128Keypair`, `Hqc192Keypair`, and `Hqc256Keypair` (behind `--features hqc`) now
  implement `zeroize::ZeroizeOnDrop`** via `#[derive(Zeroize, ZeroizeOnDrop)]` — both
  `public_key_bytes` and `secret_key_bytes` (plain `Vec<u8>` fields with no automatic
  zeroization before this change) are zeroized on drop.
- **`MlKem512Keypair::secret_key()`, `MlKem768Keypair::secret_key()`, and
  `MlKem1024Keypair::secret_key()`** now delegate to the new `try_secret_key()` and
  `.expect(..)` the result, with a documented justification (see rustdoc): this cannot
  panic for any key produced by this crate's public constructors, all of which build
  the underlying key via `DecapsulationKey::from_seed`. Their public signature
  (`-> KemSecretKey`, no `Result`) and observable behavior for every key this crate can
  construct are unchanged from 0.2.x.

### Deprecated (WP2 — A-Z1 secret-material hardening)

- **`HybridKemKeypair::x25519_secret_bytes() -> [u8; 32]`** —
  `#[deprecated(since = "0.3.0", ...)]`. Returns raw, non-zeroizing bytes. Use
  `x25519_secret()` instead. Tracked in `STABILITY.md` §8; earliest removal 0.4.0.
- **`HybridKemKeypair::mlkem_secret_bytes() -> Vec<u8>`** —
  `#[deprecated(since = "0.3.0", ...)]`. Returns raw, non-zeroizing bytes, and silently
  returns an empty `Vec` instead of an error on failure. Use `mlkem_seed()` instead.
  Tracked in `STABILITY.md` §8; earliest removal 0.4.0. Both deprecated methods keep
  their exact 0.2.x behavior (including the silent-empty-on-failure quirk for
  `mlkem_secret_bytes()`) for backward compatibility — only the *new* accessors are
  properly fallible/zeroizing.

### Removed

- **BREAKING: the `bike` feature flag and `src/bike` module.** `bike` was a permanent
  `compile_error!` stub — no working implementation ever shipped in any 0.x release.
  `pqc_kem::bike` and `bike_not_available()` no longer exist. If your build previously
  enabled `features = ["bike"]`, it was already failing to compile; delete the feature
  from your `Cargo.toml`.
- **BREAKING: the `mceliece` feature flag and `src/mceliece` module.** Same situation as
  `bike` above — a permanent `compile_error!` stub, never implemented. `pqc_kem::mceliece`
  and `mceliece_not_available()` no longer exist. If your build previously enabled
  `features = ["mceliece"]`, delete the feature.
- **BREAKING: the `pqcrypto-classicmceliece` and `pqcrypto-traits` dependencies**, pulled
  in only by the now-removed `mceliece` feature. These were the sole reason
  `cargo deny check advisories` failed: three transitively-reachable crates carried
  `unmaintained` advisories inherited from upstream PQClean's archival (see `SECURITY.md`
  for the history). None of the three advisories are reachable in any configuration of
  this crate as of 0.3.0.
- **BREAKING: the `ntru` module and its `NtruDeprecated` marker type.** `ntru` had been a
  deprecation-marker-only module since 0.1.0 (`#[deprecated(since = "0.1.0")]`), with no
  operations ever implemented — its one-minor-version deprecation floor
  (`STABILITY.md` §3) was satisfied well before 0.3.0. NTRU was eliminated from NIST
  post-quantum standardization; use `fips203::MlKem768Keypair` instead. This is the *one*
  CHANGELOG mention of NTRU, by design.
- **Unused dependencies removed:** `aes-gcm`, `sha3`, `hex`, `subtle`. None were referenced
  anywhere in `src/` (verified by repo-wide search before removal). `chacha20poly1305`
  is *not* removed — it stays a non-optional dependency for now and will move behind a
  new opt-in `aead-wrap` feature in a later work package (WP6); this is unchanged from
  0.2.0.

### Deprecated (WP1 — K-1)

- **`KemAlgorithm::Bike` and `KemAlgorithm::ClassicMceliece`** — `#[deprecated(since =
  "0.3.0", ...)]`. Both variants are kept (not removed) specifically so that existing
  serialized values (JSON `"bike"` / `"classic_mceliece"`) continue to deserialize without
  error — removing the enum variants outright would have been a second, unnecessary
  breaking change stacked on top of the feature/module removals above. Neither variant
  ever had a working implementation backing it in any release. Scheduled for removal in
  0.4.0 per `STABILITY.md` §3's one-minor-version deprecation floor; tracked in
  `STABILITY.md` §8. `as_str()`, `public_key_size()`, and `ciphertext_size()` still return
  their existing values for both variants (`#[allow(deprecated)]` used internally so the
  crate itself builds warning-free under `cargo clippy -- -D warnings`).
  - **Migration note for exhaustive `match` on `KemAlgorithm`:** matching on `Bike` or
    `ClassicMceliece` now emits a deprecation warning, not a compile error. Add
    `#[allow(deprecated)]` above your `match` (or the enclosing function) to silence it
    until you drop those arms ahead of the 0.4.0 removal.

### Changed (WP1 — K-1)

- **CI: `--all-features` flipped from a must-fail to a must-pass job.** The old
  `all-features-must-fail-cleanly` job (which asserted `cargo build --all-features` failed
  with exactly the `bike`/`mceliece` compile_error!s) is replaced by
  `all-features-build-test`, which runs `cargo build --all-features && cargo test
  --all-features` and requires both to succeed. As of 0.3.0, `--all-features` only adds
  `hqc` (a real, working implementation) on top of the default feature set.
- **CI: `cargo-deny` is now a hard-fail check, not an intentionally-red one.** Previously,
  `.github/workflows/cargo-deny.yml` documented an *expected* red run (the three
  `mceliece`-reachable advisories above). With those dependencies removed, the workflow is
  expected to pass all four checks (`advisories`, `bans`, `licenses`, `sources`) with
  `deny.toml`'s `advisories.ignore` unchanged (still empty).
- **`verify-gates.ps1`** no longer asserts that `--features bike`/`--features mceliece`
  fail to compile (there is nothing left to gate). It now asserts `cargo build
  --all-features` and `cargo test --all-features` succeed, alongside the existing default /
  `--no-default-features` / `--features hqc` checks.
- **Package descriptions** in `Cargo.toml` and `pqc-kem-wasm/Cargo.toml`, and the
  `dist/package.json` template written by `build.ps1`, no longer mention BIKE, Classic
  McEliece, or NTRU. They now headline ML-KEM (FIPS 203) and the X25519+ML-KEM-768 hybrid,
  with HQC noted as optional and native-only.
- **`SECURITY.md`**'s "Known and accepted advisories" table is replaced with a shorter
  history note: the three advisories it documented are resolved (unreachable in any
  configuration), not merely still-accepted.
- **`README.md`**: removed the BIKE/Classic McEliece rows from the Algorithm Support and
  Feature Flags tables, the "Designed, not yet implemented" section, the NTRU Deprecation
  section, and related mentions in the Unsafe Code Policy and Building-from-Source
  sections; updated the CI section's job description and the cargo-deny badge note.

### Migration from 0.2.x

Per `STABILITY.md` §2/§4, this is a breaking release:

- **If you never enabled `features = ["bike"]` or `features = ["mceliece"]`, and never
  matched exhaustively on every `KemAlgorithm` variant (the common case): no change
  needed.** `cargo add pqc-kem@0.3` is enough.
- **If you enabled `features = ["bike"]` or `features = ["mceliece"]`:** your build was
  already failing at 0.2.0 (both were hard `compile_error!` stubs). Delete the feature
  from your `Cargo.toml`; there is no replacement, because neither algorithm was ever
  implemented here.
- **If you exhaustively `match` on `KemAlgorithm` without a wildcard arm:** your build
  still compiles, but matching the `Bike`/`ClassicMceliece` arms now emits a deprecation
  warning. Add `#[allow(deprecated)]` locally, or switch to a wildcard `_ =>` arm ahead of
  their planned removal in 0.4.0.
- **If you depended on `pqc_kem::bike`, `pqc_kem::mceliece`, or `pqc_kem::ntru`
  directly:** those modules no longer exist. `bike`/`mceliece` never had a working
  implementation to migrate to; for `ntru`, use `fips203::MlKem768Keypair`.
- **Wire/JSON compatibility is unchanged.** `KemAlgorithm::Bike`/`ClassicMceliece` still
  serialize to and deserialize from the same `"bike"`/`"classic_mceliece"` JSON strings as
  0.2.0 — only the Rust-side items are marked deprecated.
- **(WP2, A-Z1) If you called `HybridKemKeypair::x25519_secret_bytes()` or
  `mlkem_secret_bytes()`:** both still work exactly as before (deprecation warning
  only, no behavior change) — but switch to `x25519_secret()` / `mlkem_seed()` for
  zeroize-on-drop secret handling and (for the latter) proper `Result`-based error
  reporting instead of a silent empty `Vec` on failure. No change needed for
  `MlKem{512,768,1024}Keypair::secret_key()`, `HybridKemKeypair::{generate, encapsulate,
  encapsulate_to, decapsulate, from_secret_key_bytes}`, or any wire/JSON type — all
  unchanged in shape and behavior.

### Added (WP3 — X-3/A-D1 CI coverage)

- **CI job `no-std-build`** — `cargo build`/`cargo test --no-default-features`. The `no_std`
  + `alloc`-only claim in README.md was previously only checked locally via
  `verify-gates.ps1`; it is now enforced on every push/PR.
- **CI job `clippy-and-doc`** — `cargo clippy --all-targets -- -D warnings`, then
  `cargo doc --no-deps` with `RUSTDOCFLAGS="-D warnings"` (default features). Catches lint
  regressions and broken intra-doc links (see "Fixed" below) before they ship, rather than
  relying on a contributor to run them locally.
- **CI job `wasm-targets`** — builds the root `pqc-kem` crate and the sibling
  `pqc-kem-wasm` crate for `wasm32-unknown-unknown` (`--no-default-features`), then
  additionally builds the root crate for `wasm32-wasip1` (`--no-default-features`), which was
  verified (this pass) to build cleanly with no `getrandom`-backend blocker.
- **CI job `wasm-pack-node-test`** — installs `wasm-pack` and Node LTS, runs the same
  `wasm-pack build` invocation `build.ps1` runs (translated to bash) from `pqc-kem-wasm/`,
  then runs `node tests/wasm_api_test.mjs` against the freshly built `dist/`. This test
  previously had no CI coverage at all — which is how its `pqc_kem_version()` assertion went
  stale against a literal `"0.1.0"` (A-D1, see "Fixed" below).
- **README.md "What this crate promises"** — states the stable/recommended surface (Hybrid
  X25519+ML-KEM-768, ML-KEM-768 standalone) versus completeness-only (ML-KEM-512/1024) versus
  optional/native-only/less-exercised (HQC), referencing `STABILITY.md`'s `0.x` policy (K-2).
- **README.md "Per-target support matrix"** — evidence-based table (build/test run or
  existing CI job cited per cell) across `native (std)`, `native no_std+alloc`,
  `wasm32-unknown-unknown` (both the root crate and the `pqc-kem-wasm` cdylib surface),
  `wasm32-wasip1`, and `wasm32-wasip2`, for ML-KEM-512/768/1024, the hybrid construction, HQC,
  serde/JSON, and zeroization (X-3).
- **README.md "Audit and FIPS status"** — states plainly that this crate has not been
  independently audited and carries no CMVP/FIPS 140-3 validation; that `ml-kem` (RustCrypto,
  `0.3.2`) implements FIPS 203 but is not itself CMVP-validated; that `x25519-dalek` (`2.0.1`)
  provides the classical component; that constant-time behavior is delegated to those two
  crates; and lists the exact dependency versions on the default crypto path from
  `Cargo.lock`, with a pointer to `SECURITY.md` (X-5).

### Fixed (WP3 — A-D1 stale artifacts)

- **The 9 pre-existing `rustdoc::broken_intra_doc_links` warnings in `cargo doc --no-deps`
  are resolved; `cargo doc --no-deps` is now 0 warnings with both default features and
  `--no-default-features`.** Three were in [`src/fips203/mod.rs`](src/fips203/mod.rs)'s module
  doc, which linked `[`MlKem512`]`/`[`MlKem768`]`/`[`MlKem1024`]` — names that were never the
  actual exported types (`MlKem512Keypair`/`MlKem768Keypair`/`MlKem1024Keypair`); fixed by
  correcting the link targets. The other six were in [`src/lib.rs`](src/lib.rs)'s and
  [`src/hqc/mod.rs`](src/hqc/mod.rs)'s module docs, which linked `Hqc128Keypair`/
  `Hqc192Keypair`/`Hqc256Keypair` — real types, but ones that only exist behind the
  non-default `hqc` feature, so the links broke whenever docs were built with default
  features (the common case, including docs.rs); fixed by changing those three references to
  plain code spans (no link) with a comment explaining why, rather than links.
- **`tests/wasm_api_test.mjs`'s `pqc_kem_version()` assertion** — was hardcoded to the literal
  `"0.1.0"` (the crate has been at `0.2.0` or `0.3.0` since before this test was last touched,
  so it was already silently wrong before this release). Now reads the expected version from
  `pqc-kem-wasm/Cargo.toml` at test-run time (with a hardcoded `"0.3.0"` fallback, documented
  inline, if the manifest can't be read/parsed), so it can't drift out of sync the same way
  again. The file header's build-command comment (`--features wasm`, a flag removed in
  0.2.0) is also corrected to the current `build.ps1`/raw `wasm-pack` invocation.
- **`wit/pqc-kem.wit`'s header** — was stale on three counts: `SOURCE OF TRUTH: src/wasm.rs`
  (that module was removed in 0.2.0's `CRA-1` split; the JS API lives in
  `pqc-kem-wasm/src/lib.rs` now), a build command citing the removed `--features wasm` flag,
  and a version pin of `@0.1.0`. All three corrected; the informational `package` line and the
  two `pqc_kem_version()`/`primary_algorithm()` example outputs elsewhere in the file are
  updated from `"0.1.0"` to `"0.3.0"` to match. Verified every class/method/free-function
  documented in the file still matches [`pqc-kem-wasm/src/lib.rs`](pqc-kem-wasm/src/lib.rs)
  one-to-one (no drift found beyond the header/version strings above).
- **README.md's WASM free-function table** — `pqc_kem_version()`'s documented return value
  corrected from `"0.1.0"` to `"0.3.0"`; the "Run Tests" section's stale "81 tests pass" claim
  (last accurate at 0.1.0) replaced with the current, re-verified count (99 tests + 3
  doctests, default features).
- **README.md "WIT Component Model" section** — previously described a `cargo component
  build` step and a `world pqc-kem { export ml-kem; ... }` WIT world that do not exist and
  have never been built by anything in this repo (X-3). Replaced with an accurate "WIT
  reference document (Component Model status: not shipped)" section stating plainly that
  [`wit/pqc-kem.wit`](wit/pqc-kem.wit) is a descriptive interface contract for the
  `wasm-bindgen` JS API, not a buildable Component Model interface, and that no WASM
  Component is produced anywhere in this repo.

### Docs (WP3 — X-3/A-D1)

- **`release-notes.md`** rewritten for 0.3.0 (was still describing 0.1.0's algorithm table and
  artifact list), including a "Migration from 0.2.x" section covering the WP1 removals
  (`bike`/`mceliece`/`ntru`), the WP2 zeroization-accessor deprecations, and the now-mandatory
  `cargo build --all-features` pass. Prior 0.1.0 history is not fabricated or backdated —
  `CHANGELOG.md` remains the authoritative record per `STABILITY.md` §4; `release-notes.md` is
  a reader-facing summary of it.

### Added (WP4 — X-4/P1 Known-Answer Tests and vector files)

- **New non-default `kat` Cargo feature** (`no_std`/`alloc`-compatible, adds no new
  dependencies) gating a small set of deterministic, **testing/interop-only** entry points
  used to check this crate against externally published Known-Answer-Test vectors:
  - `MlKem512Keypair`/`MlKem768Keypair`/`MlKem1024Keypair::from_seed_halves(d: &[u8; 32], z: &[u8; 32]) -> Self`
    — construct a keypair directly from the FIPS 203 keyGen seed halves, matching NIST ACVP
    `ML-KEM-keyGen-FIPS203` vectors' `d`/`z` fields.
  - `MlKem512Keypair`/`MlKem768Keypair`/`MlKem1024Keypair::encapsulate_deterministic(pk: &KemPublicKey, m: &[u8; 32]) -> KemResult<(KemCiphertext, SharedSecret)>`
    — deterministic encapsulation using caller-supplied randomness `m` instead of an RNG,
    reproducing NIST ACVP `ML-KEM-encapDecap-FIPS203` `AFT` (encapsulation) vectors exactly.
    Achievable directly through `ml-kem` 0.3.2's existing public API
    (`EncapsulationKey::encapsulate_deterministic`, already used internally by this crate's
    `encapsulate()` with an RNG-drawn `m` — see rustdoc for the "hazmat"/`doc(hidden)`
    nuance: the method compiles and is callable without any extra `ml-kem` feature).
  - `MlKem512Keypair`/`MlKem768Keypair`/`MlKem1024Keypair::from_expanded_decapsulation_key_bytes(bytes: &[u8]) -> KemResult<Self>`
    and `::to_expanded_decapsulation_key_bytes(&self) -> Vec<u8>` — load/serialize a
    decapsulation key using ML-KEM's deprecated "expanded" wire format
    (`ml_kem::ExpandedKeyEncoding`), which is the format NIST ACVP `ML-KEM-keyGen-FIPS203`'s
    `dk` field and `ML-KEM-encapDecap-FIPS203`'s `VAL` (decapsulation) test groups' `dk` field
    both use (**not** the 64-byte `d ‖ z` seed this crate's normal public API uses
    everywhere else). This crate never produces this format outside `kat`.
  - `fips203::hybrid::x25519_kat(scalar: [u8; 32], u: [u8; 32]) -> [u8; 32]` — a thin wrapper
    over `x25519_dalek::x25519`, exposed only so `tests/kat_x25519.rs` can check RFC 7748
    §5.2/§6.1 vectors. This crate intentionally has no general-purpose public X25519 API.
  - **Not included in this work package** (deferred to WP5 per the roadmap's own scoping):
    `HybridKemKeypair::from_secrets`/hybrid deterministic encapsulation and the canonical
    hybrid byte encoding — WP4's scope is explicitly "the ML-KEM part only" of the roadmap's
    §3.6 item 3.
- **`tests/vectors/`** — vendored, compact JSON Known-Answer-Test vector files, shipped as
  part of the published crate package (confirmed via `cargo package --list`):
  - `tests/vectors/ml-kem/{512,768,1024}/{keygen,encap,decap}.json` — subsets of the official
    NIST ACVP `ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203` vector sets (`vsId 42`),
    reached via the byte-identical copy vendored by `liboqs` 0.13.0 (`oqs-sys` crate's vendored
    source tree) rather than a fresh GitHub fetch. 5 keyGen + 5 encap + 10 decap cases per
    parameter set (30 cases × 3 = 90 total), including implicit-rejection ("modified
    ciphertext") decapsulation cases for every parameter set.
  - `tests/vectors/x25519/rfc7748.json` — RFC 7748 §5.2 (both scalar-multiplication vectors,
    plus the 1/1,000/1,000,000-iteration self-composition vectors) and §6.1 (the Alice/Bob
    Diffie-Hellman worked example), fetched live from the RFC editor and cross-checked
    byte-for-byte against `x25519-dalek` 2.0.1's own vendored copy of the same vectors.
  - `tests/vectors/README.md` — full provenance (upstream source, exact local vendoring path,
    date), the JSON format for each file, and `tests/vectors/regenerate-ml-kem-vectors.ps1`
    for reproducing the ML-KEM files from a fresh ACVP source.
- **`tests/kat_ml_kem.rs`** — for each of ML-KEM-512/768/1024: keyGen KAT (seed → `ek`/expanded
  `dk` match), encapsulation KAT (`ek` + `m` → `c`/`k` match via `encapsulate_deterministic`),
  and decapsulation KAT (expanded `dk` → `c` → `k` match, including implicit-rejection cases —
  every decap KAT asserts at least one "modified ciphertext" case is present and passes without
  erroring). Also asserts wrong-length/wrong-algorithm inputs are rejected with `KemError`, not
  a panic. Declared with `required-features = ["kat"]`, so cargo does not build it at all when the
  feature is disabled, so plain `cargo test` is unaffected.
- **`tests/kat_x25519.rs`** — RFC 7748 §5.2 scalar-mult and iterated vectors (1,000,000-iteration
  case gated behind `#[ignore]`, matching `x25519-dalek`'s own convention) and the §6.1
  Alice/Bob worked example, via `fips203::hybrid::x25519_kat`. Also `required-features = ["kat"]`.
- **CI:** new `kat-feature-build-test` job — `cargo build`/`cargo test` with `--features kat`
  and with `--no-default-features --features kat`.
- **`verify-gates.ps1`:** three new gate checks — `cargo build --features kat`,
  `cargo test --features kat`, `cargo build --no-default-features --features kat` — all
  expected to succeed (this feature is additive-only, no gated-must-fail contract).
- **Docs:** README.md gains a "Known-Answer Tests" subsection (under Security Considerations)
  and a `kat` row in the Feature Flags table; `STABILITY.md` gains a new §9 explicitly placing
  every `kat`-gated item outside the normal breaking-change contract (testing-only, no
  stability guarantee, may change or be removed in any `0.x` release without a deprecation
  cycle).

### Added (WP5 — K-5 named hybrid profiles, and X-Wing)

- **`docs/hybrid-profiles.md`** — normative specification naming two versioned hybrid
  profiles, with byte layouts, combiners and migration guidance.
- **Profile v1, `HybridKem-X25519-MLKEM768-v1`** — the existing `HybridKemKeypair`,
  named. Its bytes are unchanged: X25519 and ML-KEM-768 combined with HKDF-SHA256 under the
  info string `pqc-kem-hybrid-v1`. `PRIMARY_ALGORITHM` and `HYBRID_PROFILE_ID` point at v1,
  so existing deployments are unaffected.
- **Profile v2, `HybridKem-X25519-MLKEM768-v2` = X-Wing** (`draft-connolly-cfrg-xwing-kem-10`)
  — new `XWingKeypair`, `XWingPublicKey` (1216 bytes) and `XWingCiphertext` (1120 bytes). A
  SHA3-256 combiner that also binds the X25519 ciphertext and public key, which v1 does not,
  with both component keys expanded from one 32-byte seed by SHAKE-256
  (`XWingKeypair::from_seed`). Recommended for new deployments. Native Rust implementation.
- **`HYBRID_PROFILE_V1`, `HYBRID_PROFILE_V2`, `HYBRID_PROFILE_ID`** (an alias of v1) and a
  `HybridProfile { V1, V2XWing }` enum.
- **Canonical byte encodings** — `HybridPublicKey::{to_bytes, from_bytes}` and
  `HybridKemCiphertext::{to_bytes, from_bytes}`. The JSON wire format is unchanged.
- **`kat`-gated deterministic entry points** — `HybridKemKeypair::from_secrets`,
  `HybridKemKeypair::encapsulate_deterministic` and `XWingKeypair::encapsulate_deterministic`.
  Testing-only, under `STABILITY.md` §9.
- **Vectors.** `tests/vectors/xwing/xwing.json` holds the three vectors published by the
  X-Wing draft's own authors, vendored verbatim, and `tests/kat_xwing.rs` checks this crate's
  implementation against them. `tests/vectors/hybrid-v1/vectors.json` holds five vectors
  generated by this crate: no independent implementation of the v1 combiner exists, so these
  guard against regressions rather than prove correctness. `tests/kat_hybrid_v1.rs` narrows
  that gap by recomputing the first vector from scratch with the underlying primitives.
- **Dependencies:** `sha3` and `digest`, for X-Wing's combiner and key expansion.

X-Wing is Rust-only in this release: the `pqc-kem-wasm` JavaScript bundle exposes profile v1.

### Added (WP6 — `aead-wrap` sealed boxes and WASM parity)

- **`aead-wrap` feature and `pqc_kem::aead_wrap` module** (non-default) — seal a payload to a
  KEM public key: encapsulate, derive an AEAD key with HKDF-SHA256 under the label
  `pqc-kem-aead-wrap-v1` (bound to the KEM algorithm and a caller-supplied `context`), and
  encrypt with the KEM ciphertext bound into the AAD. `seal_hybrid` / `open_hybrid` for the v1
  hybrid, `seal_ml_kem_768` / `open_ml_kem_768` for ML-KEM-768, `derive_aead_key` for protocols
  that do their own framing, and the `SealedBox` wire type with JSON helpers.
- **Two suites: XChaCha20-Poly1305 (default) and ChaCha20-Poly1305** (through
  `seal_*_with_suite`). Nonces are always random and generated internally; no function takes
  one. Each box records its suite.
- **One error for every failed open.** Structural problems report `InvalidCiphertext`; a wrong
  key, tampering, or a wrong context or AAD all return the same error, so a failure reveals
  nothing about which check failed. The derived key and the opened plaintext zeroize on drop.
- **`tests/aead_wrap_tests.rs`** (17 tests) and **`tests/vectors/aead_wrap_v1.json`** — five
  derivation vectors computed by an independent RFC 5869 implementation, itself checked against
  RFC 5869 test case 1. The tests cover round trips for both KEMs and both suites, every
  tamper position, wrong context, AAD and key, a box relabelled as the other KEM, and
  malformed boxes.
- **WASM bindings:** `WasmHybridKemKeypair::{public_key_bytes, decapsulate_bytes, aead_open}`,
  `WasmMlKem768Keypair::aead_open`, and free functions `hybrid_encapsulate_bytes`,
  `hybrid_profile_id`, `aead_seal_hybrid` and `aead_seal_ml_kem_768`. JavaScript sealing is
  XChaCha20-Poly1305 only; opening accepts either suite. `tests/wasm_api_test.mjs` covers the
  new surface, and `wit/pqc-kem.wit` documents it.
- **Dependencies:** `chacha20poly1305` 0.10, optional, behind `aead-wrap`, without its `alloc`
  feature. The tracked `pqc-kem-wasm` lockfile gains it; nothing changes for default builds.
- **CI:** new job `aead-wrap-feature-build-test` (std and no_std tests, a wasm32 build, clippy
  and rustdoc with `-D warnings`).

### Changed (pre-release hardening)

- **What ships to crates.io is now an allowlist** (`include` in `Cargo.toml`). Previously
  every tracked file shipped. The allowlist carries sources, test files, the KAT vector data
  and the lockfile, which is what the packaged-crate CI job needs to build and test.
  Maintainer tooling under `tests/` no longer ships.
- **Feature-only test targets use `required-features`** instead of a file-level
  `#![cfg(feature = ...)]`: `kat_ml_kem`, `kat_x25519`, `kat_xwing`, `kat_hybrid_v1` and
  `hqc_tests`. A file-level `cfg` compiles to an empty binary that reports "0 passed" as a
  success; a default `cargo test` printed five of them. Cargo now declines to build them
  without their feature, and asking for one explicitly without it is an error.
- **`tests/wasm_api_test.mjs` checks `pqc_kem_version()` against pqc-kem's own manifest.**
  It had compared against `pqc-kem-wasm`'s. Both read 0.3.0, so it passed by coincidence,
  and the first release to bump one without the other would have failed or passed for the
  wrong reason. It also no longer falls back to a hardcoded version when the manifest can't
  be read.
- **`tests/vectors/regenerate-ml-kem-vectors.ps1`** finds liboqs's ACVP files through
  `CARGO_HOME` instead of a path that existed on one machine.

### Added (pre-release hardening)

- **`benches/kem.rs`** and **`scripts/bench-report.mjs`** — criterion benchmarks for every
  construction the crate ships: ML-KEM-512/768/1024, hybrid v1, X-Wing, and HQC behind its
  feature. The report states its own provenance, compares both hybrid profiles against
  ML-KEM-768 and against each other with every figure computed from the run, and refuses to
  publish if either hybrid profile is missing. `criterion` is a new dev-dependency with its
  plotting stack disabled; `[profile.bench]` is pinned.

### Fixed (pre-release hardening)

- The downstream-consumer fixture's and `pqc-kem-wasm`'s tracked lockfiles lacked `sha3` and
  `keccak`, which WP5 added. Both CI jobs build with `--locked` and would have failed.
- **Removed** twelve scratch files from the repository root and the orphaned
  `vendor/pqcrypto-bike` stub, whose only user was the removed `bike` feature. None were
  referenced by code or tests.
- Documentation no longer links to planning material outside this repository. Five of those
  links were in rustdoc and would have been dead on docs.rs. The README's roadmap note had
  also listed Known-Answer Tests and a canonical hybrid encoding as future work; both ship in
  this release.

## [0.2.0] - 2026-09-02

This release combines two independent pieces of work landed together: the real HQC
implementation (below) and a fix for `pqc-kem`'s broken `wasm32-unknown-unknown` build
(`CRA-1`, Linear). See "Migration from 0.1.x" at the end of this entry for what changes for
existing consumers.

### Added

- **New sibling crate: [`pqc-kem-wasm`](./pqc-kem-wasm)** (`CRA-1`). Carries the
  `wasm-bindgen` JS/TS bindings and the `crate-type = ["cdylib"]` standalone `.wasm` artifact
  that used to live in `pqc-kem` itself (`src/wasm.rs`, the `wasm` feature). Not published to
  crates.io (`publish = false`) — it exists purely to produce the prebuilt npm package via
  `wasm-pack` (`build.ps1` / `build-wasm.ps1`), same as before. See README.md's "Crate
  layout" for why this needed to be a separate crate rather than a feature flag: Cargo builds
  *every* declared `crate-type` for a package regardless of what a given consumer actually
  needs, so a crate declaring both `cdylib` and `rlib` forces every ordinary library consumer
  to also satisfy the `cdylib` link requirements — proven by a new downstream-consumer CI
  regression test (`tests/downstream-consumer-fixture/`) that fails on an earlier draft of
  this fix (lang items gated behind a `standalone` feature, `crate-type` left unconditional)
  for exactly this reason.
- Real HQC-128/192/256 (NIST 2025 standard) implementation behind the `hqc` feature flag,
  replacing the previous `compile_error!` stub. Native-target only (C FFI via `liboqs`, the
  `oqs` crate — not `wasm32-unknown-unknown` compatible; use ML-KEM for WASM targets).
  `KemAlgorithm::Hqc128/192/256` wire types are unchanged from 0.1.0 (no breaking change to
  the already-shipped type definitions or public key sizes).
- `tests/hqc_tests.rs` — keygen/encapsulate/decapsulate round-trip, shared-secret-equality,
  and public-key/ciphertext-size assertions per security level, plus negative tests proving
  a wrong-secret-key or malformed-ciphertext decapsulation returns `Err` and never panics —
  gated behind `--features hqc` (16 tests).

### Changed

- **BREAKING: `pqc-kem`'s `[lib] crate-type` is now `["rlib"]` only** (was `["cdylib",
  "rlib"]`) (`CRA-1`). `pqc-kem` was previously unbuildable for `wasm32-unknown-unknown` in
  *any* configuration: `cargo build --target wasm32-unknown-unknown --no-default-features
  --features wasm` hit `error[E0152]: found duplicate lang item panic_impl` (this crate
  unconditionally defined `#[global_allocator]`/`#[panic_handler]` whenever its own `std`
  feature was off, which is invalid — a library crate can't tell from its own feature flags
  whether the final linked program has `std` from elsewhere), and the `std`-enabled path hit
  a separate `getrandom` 0.4 wasm32 backend gap. Fixed by making `pqc-kem` an ordinary
  `rlib`-only library that never defines those lang items, and wiring `getrandom` 0.4's
  `wasm_js` backend in as a target-conditional dependency for `wasm32-unknown-unknown` (no
  feature flag needed). `pqc-kem` itself now builds cleanly for `wasm32-unknown-unknown` as a
  plain dependency of any Rust project, including your own `wasm-bindgen` app.
- **BREAKING: the `wasm` feature flag and `pqc_kem::wasm` module are removed from
  `pqc-kem`.** That surface (the `wasm-bindgen` JS/TS bindings) moved to the new
  `pqc-kem-wasm` crate — see "Added" above and "Migration from 0.1.x" below.
- **Dependency: `pqcrypto-hqc` → `liboqs` (`oqs` crate).** The stub's original comment
  claimed `pqcrypto-hqc 0.1`'s published API didn't expose what this crate needed (82
  compile errors). Re-verified live rather than trusted: the current published
  `pqcrypto-hqc` (0.2.x) API *does* match almost exactly — that claim was stale. However, a
  more serious, independent defect was found instead: `pqcrypto-hqc` 0.2.2's
  `decapsulate()` wraps the underlying PQClean C reference implementation's informational
  "decapsulation check failed" return code — the FO-transform's *normal, expected*
  implicit-rejection outcome for **any** ciphertext/secret-key mismatch, not a rare
  adversarial edge case — in a hard `assert_eq!(.., 0)`, which **panics** (and, under a
  `panic = "abort"` profile, aborts the process) instead of returning an error. Verified
  live with two independent reproductions (a bit-flipped ciphertext, and an honestly
  mismatched secret key) — both panic via `pqcrypto-hqc`. `liboqs` wraps the identical
  underlying return code as a proper `Result` instead; verified live that neither
  reproduction panics via `liboqs` — both cleanly return `Err`. See
  [`src/hqc/mod.rs`](src/hqc/mod.rs) module docs and README.md "Why `liboqs` and not
  `pqcrypto-hqc`?" for the full writeup.
- **Corrected HQC-128/256 ciphertext sizes: 4481 → 4433 bytes, 14469 → 14421 bytes.**
  HQC-192's 8978-byte ciphertext was already correct. Verified live against both
  `pqcrypto-hqc` 0.2.2 and `liboqs` 0.13.0 — two independent implementations of the same
  NIST submission, which agree on the corrected sizes. This reflects the HQC round-4/2023
  parameter revision to the error-correcting code, which changed ciphertext size at the
  128- and 256-bit levels but not the 192-bit level. Public key sizes (2249/4522/7245
  bytes) were already correct and are unchanged. This correction lands *before* any real
  implementation ever shipped (0.1.0's `hqc` was a hard compile error), so there is no
  previously-working wire format being broken.
- `README.md` and module-level docs for `hqc` no longer describe the feature as "NOT YET
  IMPLEMENTED" / "Gated — not implemented."
- CI now builds and tests `--features hqc` explicitly in its own job (previously excluded
  from all CI jobs because `--all-features` deliberately omits it). The `--all-features`
  job's expected-failure assertion is narrowed from three named features (hqc/bike/mceliece)
  to two (bike/mceliece only) — `hqc` now compiles and is included in `--all-features`.
- `SECURITY.md`'s accepted-advisories table drops `RUSTSEC-2026-0168` (`pqcrypto-hqc`)
  entirely — it is no longer a dependency of this crate in any configuration, not merely an
  accepted advisory. Re-ran `cargo deny check` after the swap: no new advisory, license,
  ban, or source finding from `oqs`/`oqs-sys`/`liboqs`.

### Not changed

- `bike` and `mceliece` features remain `compile_error!` stubs, unchanged.
- The primary `HybridKemKeypair` (X25519+ML-KEM-768) construction and its
  `"pqc-kem-hybrid-v1"` HKDF info string are unchanged.
- `KemAlgorithm::Hqc128/192/256` enum variants and public key sizes are unchanged.
- No public API, algorithm, or cryptographic changes from the wasm/no_std fix (`CRA-1`) —
  build configuration only. `HybridKemKeypair`, `MlKem{512,768,1024}Keypair`, and every wire
  type are unchanged.

### Migration from 0.1.x

Per `STABILITY.md` §2/§4, this is a breaking release, not a patch:

- **Library consumers of `pqc-kem` (the common case): no change needed.** `cargo add pqc-kem`
  and `cargo add pqc-kem@0.2` (Cargo's `^0.1` doesn't match `0.2.0`, so this must be a
  deliberate bump) is enough. If you were previously enabling `features = ["wasm"]` on
  `pqc-kem` directly, that feature no longer exists — see below.
- **If you consumed `pqc-kem`'s WASM/JS bindings (`WasmHybridKemKeypair`, `hybrid_encapsulate`,
  etc., or built `pqc-kem` itself with `--features wasm`):** that surface moved to the new
  `pqc-kem-wasm` crate. The compiled JS/TS API is unchanged (same function/class names, same
  `pqc_kem.js`/`pqc_kem_bg.wasm` file names) — only the Rust-side crate producing it changed.
  If you build the WASM artifact yourself rather than consuming the npm package, point your
  build at `pqc-kem-wasm/` instead of `pqc-kem/` (see README.md's updated build commands).
- **If you built `pqc-kem` itself as a standalone `no_std` cdylib** (e.g. directly invoking
  `cargo build --no-default-features --features wasm` against 0.1.x): `pqc-kem` no longer
  produces a `cdylib` at all. Use `pqc-kem-wasm` for that instead.

## [0.1.0] - 2026-08-27

### Added

- Initial release: ML-KEM-512, ML-KEM-768, and ML-KEM-1024 (NIST FIPS 203), plus the
  recommended Hybrid X25519+ML-KEM-768 construction (HKDF-SHA256 combiner) — pure Rust,
  `no_std`-compatible, 81 tests passing.
- WASM bindings (`wasm` feature) for `wasm32-unknown-unknown`, with wire types
  (`KemPublicKey`, `KemCiphertext`, `SharedSecret`, `HybridPublicKey`, `HybridKemCiphertext`)
  supporting base64url JSON and multibase (base58btc) encoding for DID Documents / JWK
  payloads.
- `no_std` + `alloc` support, caller-supplied RNG, secret key material zeroized on drop.
- `hqc`, `bike`, and `mceliece` feature flags exist so the intended algorithm surface is
  visible, but each is a hard `compile_error!` stub, not a runtime option — see README.md for
  status.

See [README.md](README.md) for full API and feature documentation.
