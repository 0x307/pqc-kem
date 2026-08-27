//! Stub placeholder for `pqcrypto-bike`.
//!
//! This crate will be replaced with proper FFI bindings to the AWS BIKE KEM
//! C implementation: <https://github.com/awslabs/bike-kem>
//!
//! The `bikel1` module mirrors the `pqcrypto` crate API so that `pqc-kem`'s
//! `bike` feature compiles once the real implementation is wired up.

/// BIKE Level 1 (128-bit security) — stub implementation.
pub mod bikel1 {
    use pqcrypto_traits::kem::{
        Ciphertext as CiphertextTrait, PublicKey as PublicKeyTrait,
        SecretKey as SecretKeyTrait, SharedSecret as SharedSecretTrait,
    };

    /// BIKE-L1 public key stub.
    #[derive(Clone)]
    pub struct PublicKey(Vec<u8>);

    /// BIKE-L1 secret key stub.
    #[derive(Clone)]
    pub struct SecretKey(Vec<u8>);

    /// BIKE-L1 ciphertext stub.
    #[derive(Clone)]
    pub struct Ciphertext(Vec<u8>);

    /// BIKE-L1 shared secret stub.
    #[derive(Clone)]
    pub struct SharedSecret(Vec<u8>);

    impl PublicKeyTrait for PublicKey {
        fn as_bytes(&self) -> &[u8] { &self.0 }
        fn from_bytes(bytes: &[u8]) -> Result<Self, pqcrypto_traits::Error> {
            Ok(Self(bytes.to_vec()))
        }
    }

    impl SecretKeyTrait for SecretKey {
        fn as_bytes(&self) -> &[u8] { &self.0 }
        fn from_bytes(bytes: &[u8]) -> Result<Self, pqcrypto_traits::Error> {
            Ok(Self(bytes.to_vec()))
        }
    }

    impl CiphertextTrait for Ciphertext {
        fn as_bytes(&self) -> &[u8] { &self.0 }
        fn from_bytes(bytes: &[u8]) -> Result<Self, pqcrypto_traits::Error> {
            Ok(Self(bytes.to_vec()))
        }
    }

    impl SharedSecretTrait for SharedSecret {
        fn as_bytes(&self) -> &[u8] { &self.0 }
        fn from_bytes(bytes: &[u8]) -> Result<Self, pqcrypto_traits::Error> {
            Ok(Self(bytes.to_vec()))
        }
    }

    /// Generate a BIKE-L1 keypair — stub, always panics.
    pub fn keypair() -> (PublicKey, SecretKey) {
        unimplemented!("pqcrypto-bike stub: real implementation pending FFI bindings to https://github.com/awslabs/bike-kem")
    }

    /// Encapsulate to a BIKE-L1 public key — stub, always panics.
    pub fn encapsulate(_pk: &PublicKey) -> (SharedSecret, Ciphertext) {
        unimplemented!("pqcrypto-bike stub: real implementation pending FFI bindings to https://github.com/awslabs/bike-kem")
    }

    /// Decapsulate a BIKE-L1 ciphertext — stub, always panics.
    pub fn decapsulate(_ct: &Ciphertext, _sk: &SecretKey) -> SharedSecret {
        unimplemented!("pqcrypto-bike stub: real implementation pending FFI bindings to https://github.com/awslabs/bike-kem")
    }
}
