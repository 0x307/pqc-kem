//! NTRU — Eliminated from NIST Post-Quantum Standardization
//!
//! NTRU was withdrawn from the NIST post-quantum standardization process in
//! Round 4 (2022) due to concerns about patent encumbrances and the availability
//! of better alternatives (ML-KEM).
//!
//! # ⚠️ DO NOT USE
//! This module exists only as a deprecation marker. NTRU is:
//! - **Not standardized** by NIST
//! - **Patent-encumbered** (patents expired 2017, but legacy concerns remain)
//! - **Superseded** by ML-KEM (FIPS 203) which is superior in all metrics
//!
//! Use [`crate::fips203::MlKem768Keypair`] instead.

use crate::error::KemError;

/// Marker type indicating NTRU is not supported.
///
/// NTRU was eliminated from the NIST post-quantum standardization process.
/// Use ML-KEM (FIPS 203) instead.
///
/// # Migration
/// Replace any NTRU usage with:
/// ```rust,no_run
/// use pqc_kem::fips203::MlKem768Keypair;
/// // MlKem768Keypair provides equivalent security with NIST standardization
/// ```
#[deprecated(
    since  = "0.1.0",
    note   = "NTRU was eliminated from NIST post-quantum standardization. Use ML-KEM (FIPS 203) instead."
)]
pub struct NtruDeprecated;

#[allow(deprecated)]
impl NtruDeprecated {
    /// Always returns an error. NTRU is not implemented.
    pub fn not_supported() -> KemError {
        KemError::AlgorithmNotAvailable(
            "NTRU".into(),
            "ntru (not available — NTRU was eliminated from NIST standardization; use ML-KEM instead)".into(),
        )
    }
}
