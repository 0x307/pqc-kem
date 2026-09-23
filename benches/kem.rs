//! Every key-encapsulation operation this crate offers, benched individually.
//!
//! Companion to `pqc-sig`'s `benches/signatures.rs`, and written to the same
//! rules. See `BENCHMARKS.md` for the generated table.
//!
//! # What is measured, and what is deliberately absent
//!
//! **ML-KEM always runs.** It is pure Rust and `no_std`, and it is what a WASM
//! target can use.
//!
//! **Both hybrid profiles always run.** `HybridKemKeypair` (profile v1, the
//! crate's `PRIMARY_ALGORITHM`) and `XWingKeypair` (profile v2) are part of
//! every build, so they are part of every run. Each gets its own group rather
//! than being folded into ML-KEM-768's numbers, because the difference between
//! them and ML-KEM-768 alone *is* the cost of the X25519 hedge, and a reader
//! should be able to read that cost off the table instead of inferring it.
//!
//! **HQC runs only behind `--features hqc`.** Unlike `pqc-sig`, where an absent
//! FN-DSA makes the harness panic, absence here is permitted: HQC is C-backed
//! through `liboqs`, so demanding it would make `cargo bench` fail for anyone
//! without a C toolchain, and it is not a headline algorithm. Absence is never
//! *silent*, though: the report generator records which features a run was
//! built with, so a table missing HQC says so.
//!
//! There is nothing else to measure. BIKE, Classic McEliece and the NTRU KEM
//! marker were removed from the crate in 0.3.0; none of them ever had a working
//! implementation, and benchmarking a placeholder is the commonest way a
//! performance table becomes a lie.

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

use pqc_kem::{HybridKemKeypair, MlKem1024Keypair, MlKem512Keypair, MlKem768Keypair, XWingKeypair};

/// Record which features this binary was *compiled* with, for the report
/// generator to read.
///
/// `target/criterion` accumulates results across runs and criterion never
/// clears it, so the directory is a union of every run the machine has done,
/// not a description of the last one. A run made without `hqc` after one made
/// with it would otherwise publish the earlier HQC rows as if just measured.
///
/// An mtime window was the other candidate and is a worse one: a single run of
/// this suite spans minutes, so any window wide enough to hold one run is wide
/// enough to swallow the run before it. This is not a timing question. The
/// binary knows what it was built with at compile time, so it writes that down
/// and the generator stops guessing.
fn write_run_manifest() {
    use std::io::Write;

    let features: Vec<&str> = [
        cfg!(feature = "hqc").then_some("hqc"),
        cfg!(feature = "kat").then_some("kat"),
    ]
    .into_iter()
    .flatten()
    .collect();

    let dir = std::env::var("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target"))
        .join("criterion");

    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }

    let json = format!(
        "{{\"features\":[{}],\"unix_time\":{}}}\n",
        features
            .iter()
            .map(|f| format!("\"{f}\""))
            .collect::<Vec<_>>()
            .join(","),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );

    if let Ok(mut f) = std::fs::File::create(dir.join("run-manifest.json")) {
        let _ = f.write_all(json.as_bytes());
    }
}

/// ML-KEM, FIPS 203.
///
/// Unlike ML-DSA signing, encapsulation and decapsulation have no rejection
/// loop, so a fixed input does not freeze a variable iteration count and there
/// is no need to cycle a pool the way `pqc-sig`'s signing benchmarks do. For
/// the same reason the key does not need a fixed seed: nothing here varies in
/// cost with the key the way ML-DSA signing does.
///
/// Decapsulation is benched on a *valid* ciphertext. ML-KEM's implicit
/// rejection means a malformed one costs the same by construction -- that is a
/// constant-time property, and asserting it needs a different tool than a
/// median and a confidence interval.
///
/// Runs first in the group and writes the run manifest on the way in -- it is
/// the one function here that is never gated, so it is the only safe place to
/// put something every run must do.
fn ml_kem(c: &mut Criterion) {
    write_run_manifest();

    macro_rules! bench_ml_kem {
        ($name:literal, $kp:ty) => {{
            let mut group = c.benchmark_group($name);

            group.bench_function("keygen", |b| {
                b.iter(|| <$kp>::generate(&mut OsRng).expect("keygen"))
            });

            let kp = <$kp>::generate(&mut OsRng).expect("keygen");
            let pk = kp.public_key();

            group.bench_function("encapsulate", |b| {
                b.iter(|| <$kp>::encapsulate(&mut OsRng, &pk).expect("encapsulate"))
            });

            let (ct, _) = <$kp>::encapsulate(&mut OsRng, &pk).expect("encapsulate");
            group.bench_function("decapsulate", |b| {
                b.iter(|| kp.decapsulate(&ct).expect("decapsulate"))
            });

            group.finish();
        }};
    }

    bench_ml_kem!("ml-kem-512", MlKem512Keypair);
    bench_ml_kem!("ml-kem-768", MlKem768Keypair);
    bench_ml_kem!("ml-kem-1024", MlKem1024Keypair);
}

/// Hybrid profile v1: X25519 + ML-KEM-768 with an HKDF-SHA256 combiner.
/// The crate's `PRIMARY_ALGORITHM`, and what existing deployments use.
///
/// **This group contains classical cryptography**, deliberately: a hybrid is
/// secure if *either* component holds, which for key exchange hedges against
/// a recorded session being decrypted later if ML-KEM ever falls.
fn hybrid_v1(c: &mut Criterion) {
    let mut group = c.benchmark_group("hybrid-v1-x25519-ml-kem-768");

    group.bench_function("keygen", |b| {
        b.iter(|| HybridKemKeypair::generate(&mut OsRng).expect("keygen"))
    });

    let kp = HybridKemKeypair::generate(&mut OsRng).expect("keygen");
    let x_pub = kp.x25519_public_bytes();
    let m_pub = kp.mlkem_public_bytes();

    group.bench_function("encapsulate", |b| {
        b.iter(|| HybridKemKeypair::encapsulate(&mut OsRng, &x_pub, &m_pub).expect("encapsulate"))
    });

    let (ct, _) = HybridKemKeypair::encapsulate(&mut OsRng, &x_pub, &m_pub).expect("encapsulate");
    group.bench_function("decapsulate", |b| {
        b.iter(|| kp.decapsulate(&ct).expect("decapsulate"))
    });

    group.finish();
}

/// Hybrid profile v2: X-Wing (`draft-connolly-cfrg-xwing-kem`), the same two
/// components as v1 under a SHA3-256 combiner that also binds the X25519
/// ciphertext and public key. Recommended for new deployments.
///
/// Benched separately from v1 because the two differ in more than the
/// combiner: X-Wing derives its ML-KEM and X25519 keys by expanding a single
/// 32-byte seed with SHAKE-256, so its keygen and decapsulation do work v1's
/// do not. The v1-versus-v2 difference is what a new deployment choosing
/// between them actually pays.
fn hybrid_v2_xwing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hybrid-v2-xwing");

    group.bench_function("keygen", |b| {
        b.iter(|| XWingKeypair::generate(&mut OsRng).expect("keygen"))
    });

    let kp = XWingKeypair::generate(&mut OsRng).expect("keygen");
    let pk = kp.public_key();

    group.bench_function("encapsulate", |b| {
        b.iter(|| XWingKeypair::encapsulate(&mut OsRng, &pk).expect("encapsulate"))
    });

    let (ct, _) = XWingKeypair::encapsulate(&mut OsRng, &pk).expect("encapsulate");
    group.bench_function("decapsulate", |b| {
        b.iter(|| kp.decapsulate(&ct).expect("decapsulate"))
    });

    group.finish();
}

/// HQC, a NIST 2025 standard, through `liboqs`. Native-only: it does not build
/// for `wasm32-unknown-unknown`, which is why it is optional here and why the
/// crate steers WASM consumers to ML-KEM.
#[cfg(feature = "hqc")]
fn hqc(c: &mut Criterion) {
    use pqc_kem::hqc::Hqc128Keypair;

    let mut group = c.benchmark_group("hqc-128");
    group.bench_function("keygen", |b| {
        b.iter(|| Hqc128Keypair::generate(&mut OsRng).expect("keygen"))
    });
    let kp = Hqc128Keypair::generate(&mut OsRng).expect("keygen");
    let pk = kp.public_key();
    group.bench_function("encapsulate", |b| {
        b.iter(|| Hqc128Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate"))
    });
    let (ct, _) = Hqc128Keypair::encapsulate(&mut OsRng, &pk).expect("encapsulate");
    group.bench_function("decapsulate", |b| {
        b.iter(|| kp.decapsulate(&ct).expect("decapsulate"))
    });
    group.finish();
}

// HQC's group is named only when its feature is on, rather than stubbed to an
// empty function. The generator reads which features the binary was built
// with from the run manifest, so an absent HQC group is reported as "not
// measured in this run" instead of the table silently lacking rows.
#[cfg(feature = "hqc")]
criterion_group!(kem, ml_kem, hybrid_v1, hybrid_v2_xwing, hqc);

#[cfg(not(feature = "hqc"))]
criterion_group!(kem, ml_kem, hybrid_v1, hybrid_v2_xwing);

criterion_main!(kem);
