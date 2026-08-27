//! WASM bindings for `pqc-kem` via `wasm-bindgen`.
//!
//! These bindings expose the KEM operations to JavaScript/TypeScript.
//! All byte arrays cross the WASM boundary as `Uint8Array`.
//! All errors are returned as JavaScript `Error` objects (via `Result<T, JsValue>`).
//!
//! # Usage from JavaScript
//! ```javascript
//! import init, {
//!   WasmHybridKemKeypair,
//!   WasmMlKem768Keypair,
//!   hybrid_encapsulate,
//!   ml_kem_768_encapsulate,
//! } from './pqc_kem.js';
//!
//! await init();
//!
//! // Hybrid KEM (recommended)
//! const keypair = new WasmHybridKemKeypair();
//! const pubKey = keypair.public_key_json();
//! const { ciphertext, shared_secret } = hybrid_encapsulate(pubKey);
//! const recovered = keypair.decapsulate(ciphertext);
//! ```

extern crate alloc;
use alloc::{format, string::{String, ToString}, vec::Vec};

use wasm_bindgen::prelude::*;

use crate::fips203::{HybridKemKeypair, MlKem512Keypair, MlKem768Keypair, MlKem1024Keypair};
use crate::types::{HybridKemCiphertext, HybridPublicKey, KemAlgorithm, KemPublicKey};

// ── RNG for WASM ──────────────────────────────────────────────────────────────
// In WASM, we use getrandom which hooks into window.crypto.getRandomValues()
// The `getrandom/js` feature must be enabled (set in Cargo.toml under [features] wasm).

fn wasm_rng() -> rand_core::OsRng {
    rand_core::OsRng
}

// ── Error Conversion ──────────────────────────────────────────────────────────

fn to_js_error(e: crate::error::KemError) -> JsValue {
    JsValue::from_str(&e.to_string())
}

// ── Hybrid KEM (X25519 + ML-KEM-768) ─────────────────────────────────────────

/// Hybrid X25519 + ML-KEM-768 keypair for use in JavaScript/WASM environments.
///
/// This is the **recommended** KEM for all applications. It provides security
/// against both classical and quantum adversaries.
#[wasm_bindgen]
pub struct WasmHybridKemKeypair {
    inner: HybridKemKeypair,
}

#[wasm_bindgen]
impl WasmHybridKemKeypair {
    /// Generate a new hybrid keypair using the browser's Web Crypto entropy source.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmHybridKemKeypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = HybridKemKeypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }

    /// Returns the public key as a JSON string.
    ///
    /// The JSON contains `x25519_key`, `mlkem_key`, `x25519_multibase`, `mlkem_multibase`.
    /// Share this with senders who want to encapsulate to you.
    #[wasm_bindgen]
    pub fn public_key_json(&self) -> Result<String, JsValue> {
        self.inner.public_key().to_json().map_err(to_js_error)
    }

    /// Returns the X25519 public key as raw bytes (32 bytes).
    #[wasm_bindgen]
    pub fn x25519_public_bytes(&self) -> Vec<u8> {
        self.inner.x25519_public_bytes().to_vec()
    }

    /// Returns the ML-KEM-768 public key as raw bytes (1184 bytes).
    #[wasm_bindgen]
    pub fn mlkem_public_bytes(&self) -> Vec<u8> {
        self.inner.mlkem_public_bytes()
    }

    /// Decapsulate a hybrid ciphertext JSON string, returning the 32-byte shared secret.
    ///
    /// The ciphertext JSON must have been produced by `hybrid_encapsulate()`.
    #[wasm_bindgen]
    pub fn decapsulate(&self, ciphertext_json: &str) -> Result<Vec<u8>, JsValue> {
        let ct = HybridKemCiphertext::from_json(ciphertext_json).map_err(to_js_error)?;
        let ss = self.inner.decapsulate(&ct).map_err(to_js_error)?;
        Ok(ss.bytes.clone())
    }
}

/// Encapsulate to a recipient's hybrid public key.
///
/// # Parameters
/// - `recipient_public_key_json`: JSON string from `WasmHybridKemKeypair.public_key_json()`
///
/// # Returns
/// A JSON object with:
/// - `ciphertext`: JSON string of the `HybridKemCiphertext` (send to recipient)
/// - `shared_secret`: base64url-encoded 32-byte shared secret (keep secret)
#[wasm_bindgen]
pub fn hybrid_encapsulate(recipient_public_key_json: &str) -> Result<String, JsValue> {
    let pub_key = HybridPublicKey::from_json(recipient_public_key_json).map_err(to_js_error)?;

    let x25519_bytes = pub_key.x25519_bytes().map_err(to_js_error)?;
    let mlkem_bytes  = pub_key.mlkem_bytes().map_err(to_js_error)?;

    let x25519_arr: [u8; 32] = x25519_bytes.as_slice().try_into()
        .map_err(|_| JsValue::from_str("X25519 public key must be 32 bytes"))?;

    let mut rng = wasm_rng();
    let (ct, ss) = HybridKemKeypair::encapsulate(&mut rng, &x25519_arr, &mlkem_bytes)
        .map_err(to_js_error)?;

    use base64ct::{Base64Url, Encoding};
    let result = format!(
        r#"{{"ciphertext":{},"shared_secret":"{}"}}"#,
        ct.to_json().map_err(to_js_error)?,
        Base64Url::encode_string(&ss.bytes),
    );

    Ok(result)
}

// ── ML-KEM-512 ────────────────────────────────────────────────────────────────

/// ML-KEM-512 keypair for WASM environments (Security Level 1).
#[wasm_bindgen]
pub struct WasmMlKem512Keypair {
    inner: MlKem512Keypair,
}

#[wasm_bindgen]
impl WasmMlKem512Keypair {
    /// Generate a new ML-KEM-512 keypair.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmMlKem512Keypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = MlKem512Keypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }

    /// Returns the public key as raw bytes (800 bytes).
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().bytes
    }

    /// Returns the public key as a base64url string.
    #[wasm_bindgen]
    pub fn public_key_base64url(&self) -> String {
        self.inner.public_key().to_base64url()
    }

    /// Decapsulate a ciphertext (768 bytes), returning the 32-byte shared secret.
    #[wasm_bindgen]
    pub fn decapsulate(&self, ciphertext_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        use crate::types::KemCiphertext;
        let ct = KemCiphertext::new(KemAlgorithm::MlKem512, ciphertext_bytes.to_vec());
        let ss = self.inner.decapsulate(&ct).map_err(to_js_error)?;
        Ok(ss.bytes.clone())
    }
}

/// Encapsulate to an ML-KEM-512 public key (800 bytes).
///
/// Returns a JSON object: `{"ciphertext": "<base64url>", "shared_secret": "<base64url>"}`
#[wasm_bindgen]
pub fn ml_kem_512_encapsulate(recipient_public_key_bytes: &[u8]) -> Result<String, JsValue> {
    use base64ct::{Base64Url, Encoding};

    let pk = KemPublicKey::new(KemAlgorithm::MlKem512, recipient_public_key_bytes.to_vec());
    let mut rng = wasm_rng();
    let (ct, ss) = MlKem512Keypair::encapsulate(&mut rng, &pk).map_err(to_js_error)?;

    Ok(format!(
        r#"{{"ciphertext":"{}","shared_secret":"{}"}}"#,
        Base64Url::encode_string(&ct.bytes),
        Base64Url::encode_string(&ss.bytes),
    ))
}

// ── ML-KEM-768 ────────────────────────────────────────────────────────────────

/// ML-KEM-768 keypair for WASM environments (Security Level 3, recommended).
#[wasm_bindgen]
pub struct WasmMlKem768Keypair {
    inner: MlKem768Keypair,
}

#[wasm_bindgen]
impl WasmMlKem768Keypair {
    /// Generate a new ML-KEM-768 keypair.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmMlKem768Keypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = MlKem768Keypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }

    /// Returns the public key as raw bytes (1184 bytes).
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().bytes
    }

    /// Returns the public key as a base64url string.
    #[wasm_bindgen]
    pub fn public_key_base64url(&self) -> String {
        self.inner.public_key().to_base64url()
    }

    /// Decapsulate a ciphertext (1088 bytes), returning the 32-byte shared secret.
    #[wasm_bindgen]
    pub fn decapsulate(&self, ciphertext_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        use crate::types::KemCiphertext;
        let ct = KemCiphertext::new(KemAlgorithm::MlKem768, ciphertext_bytes.to_vec());
        let ss = self.inner.decapsulate(&ct).map_err(to_js_error)?;
        Ok(ss.bytes.clone())
    }
}

/// Encapsulate to an ML-KEM-768 public key (1184 bytes).
///
/// Returns a JSON object: `{"ciphertext": "<base64url>", "shared_secret": "<base64url>"}`
#[wasm_bindgen]
pub fn ml_kem_768_encapsulate(recipient_public_key_bytes: &[u8]) -> Result<String, JsValue> {
    use base64ct::{Base64Url, Encoding};

    let pk = KemPublicKey::new(KemAlgorithm::MlKem768, recipient_public_key_bytes.to_vec());
    let mut rng = wasm_rng();
    let (ct, ss) = MlKem768Keypair::encapsulate(&mut rng, &pk).map_err(to_js_error)?;

    Ok(format!(
        r#"{{"ciphertext":"{}","shared_secret":"{}"}}"#,
        Base64Url::encode_string(&ct.bytes),
        Base64Url::encode_string(&ss.bytes),
    ))
}

// ── ML-KEM-1024 ───────────────────────────────────────────────────────────────

/// ML-KEM-1024 keypair for WASM environments (Security Level 5).
#[wasm_bindgen]
pub struct WasmMlKem1024Keypair {
    inner: MlKem1024Keypair,
}

#[wasm_bindgen]
impl WasmMlKem1024Keypair {
    /// Generate a new ML-KEM-1024 keypair.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmMlKem1024Keypair, JsValue> {
        let mut rng = wasm_rng();
        let inner = MlKem1024Keypair::generate(&mut rng).map_err(to_js_error)?;
        Ok(Self { inner })
    }

    /// Returns the public key as raw bytes (1568 bytes).
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().bytes
    }

    /// Returns the public key as a base64url string.
    #[wasm_bindgen]
    pub fn public_key_base64url(&self) -> String {
        self.inner.public_key().to_base64url()
    }

    /// Decapsulate a ciphertext (1568 bytes), returning the 32-byte shared secret.
    #[wasm_bindgen]
    pub fn decapsulate(&self, ciphertext_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        use crate::types::KemCiphertext;
        let ct = KemCiphertext::new(KemAlgorithm::MlKem1024, ciphertext_bytes.to_vec());
        let ss = self.inner.decapsulate(&ct).map_err(to_js_error)?;
        Ok(ss.bytes.clone())
    }
}

/// Encapsulate to an ML-KEM-1024 public key (1568 bytes).
///
/// Returns a JSON object: `{"ciphertext": "<base64url>", "shared_secret": "<base64url>"}`
#[wasm_bindgen]
pub fn ml_kem_1024_encapsulate(recipient_public_key_bytes: &[u8]) -> Result<String, JsValue> {
    use base64ct::{Base64Url, Encoding};

    let pk = KemPublicKey::new(KemAlgorithm::MlKem1024, recipient_public_key_bytes.to_vec());
    let mut rng = wasm_rng();
    let (ct, ss) = MlKem1024Keypair::encapsulate(&mut rng, &pk).map_err(to_js_error)?;

    Ok(format!(
        r#"{{"ciphertext":"{}","shared_secret":"{}"}}"#,
        Base64Url::encode_string(&ct.bytes),
        Base64Url::encode_string(&ss.bytes),
    ))
}

// ── Utility Functions ─────────────────────────────────────────────────────────

/// Returns the crate version string.
#[wasm_bindgen]
pub fn pqc_kem_version() -> String {
    crate::VERSION.into()
}

/// Returns the primary algorithm identifier string.
#[wasm_bindgen]
pub fn primary_algorithm() -> String {
    crate::PRIMARY_ALGORITHM.into()
}
