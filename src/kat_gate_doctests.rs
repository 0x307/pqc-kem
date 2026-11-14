//! Compile-fail checks that the `kat`-only entry points can't be reached
//! without the `kat` feature (KEM-02).
//!
//! Compiled only by rustdoc when it collects doctests (`cfg(doctest)`), so
//! it adds nothing to any build. Each item below carries one doctest that
//! calls one `kat`-gated function. Its fence is chosen by the feature:
//!
//! - without `kat` it is `compile_fail` with the expected error code
//!   (`E0599` no such associated function or method, `E0425` no such free
//!   function), so the doctest passes only if that call is refused for that
//!   reason;
//! - with `kat` it is a normal doctest, so the same code must compile and
//!   run. That is the control: it proves each snippet is otherwise valid,
//!   and the only thing failing the default build is the missing feature.
//!
//! One function per snippet, because a `compile_fail` doctest with several
//! calls would pass as soon as any one of them fails.
//!
//! Run both directions with `cargo test --doc` and
//! `cargo test --doc --features kat`.


#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let _kp = pqc_kem::HybridKemKeypair::from_secrets(&[1u8; 32], &[2u8; 32], &[3u8; 32]);"]
#[doc = "```"]
pub struct HybridFromSecrets;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let pk = pqc_kem::HybridKemKeypair::from_secret_key_bytes(&[1u8; 32], &[2u8; 64]).unwrap().public_key();"]
#[doc = "let _ = pqc_kem::HybridKemKeypair::encapsulate_deterministic(&pk, &[4u8; 32], &[5u8; 32]).unwrap();"]
#[doc = "```"]
pub struct HybridEncapsulateDeterministic;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0425")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let _out: [u8; 32] = pqc_kem::fips203::hybrid::x25519_kat([1u8; 32], [9u8; 32]);"]
#[doc = "```"]
pub struct X25519Kat;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let pk = pqc_kem::XWingKeypair::from_seed(&[7u8; 32]).public_key();"]
#[doc = "let _ = pqc_kem::XWingKeypair::encapsulate_deterministic(&pk, &[5u8; 64]).unwrap();"]
#[doc = "```"]
pub struct XWingEncapsulateDeterministic;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let _kp = pqc_kem::MlKem512Keypair::from_seed_halves(&[1u8; 32], &[2u8; 32]);"]
#[doc = "```"]
pub struct MlKem512FromSeedHalves;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let pk = pqc_kem::MlKem512Keypair::from_secret_key_bytes(&[2u8; 64]).unwrap().public_key();"]
#[doc = "let _ = pqc_kem::MlKem512Keypair::encapsulate_deterministic(&pk, &[3u8; 32]).unwrap();"]
#[doc = "```"]
pub struct MlKem512EncapsulateDeterministic;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let _ = pqc_kem::MlKem512Keypair::from_expanded_decapsulation_key_bytes(&[0u8; 8]);"]
#[doc = "```"]
pub struct MlKem512FromExpanded;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let kp = pqc_kem::MlKem512Keypair::from_secret_key_bytes(&[2u8; 64]).unwrap();"]
#[doc = "let _bytes: Vec<u8> = kp.to_expanded_decapsulation_key_bytes();"]
#[doc = "```"]
pub struct MlKem512ToExpanded;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let _kp = pqc_kem::MlKem768Keypair::from_seed_halves(&[1u8; 32], &[2u8; 32]);"]
#[doc = "```"]
pub struct MlKem768FromSeedHalves;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let pk = pqc_kem::MlKem768Keypair::from_secret_key_bytes(&[2u8; 64]).unwrap().public_key();"]
#[doc = "let _ = pqc_kem::MlKem768Keypair::encapsulate_deterministic(&pk, &[3u8; 32]).unwrap();"]
#[doc = "```"]
pub struct MlKem768EncapsulateDeterministic;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let _ = pqc_kem::MlKem768Keypair::from_expanded_decapsulation_key_bytes(&[0u8; 8]);"]
#[doc = "```"]
pub struct MlKem768FromExpanded;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let kp = pqc_kem::MlKem768Keypair::from_secret_key_bytes(&[2u8; 64]).unwrap();"]
#[doc = "let _bytes: Vec<u8> = kp.to_expanded_decapsulation_key_bytes();"]
#[doc = "```"]
pub struct MlKem768ToExpanded;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let _kp = pqc_kem::MlKem1024Keypair::from_seed_halves(&[1u8; 32], &[2u8; 32]);"]
#[doc = "```"]
pub struct MlKem1024FromSeedHalves;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let pk = pqc_kem::MlKem1024Keypair::from_secret_key_bytes(&[2u8; 64]).unwrap().public_key();"]
#[doc = "let _ = pqc_kem::MlKem1024Keypair::encapsulate_deterministic(&pk, &[3u8; 32]).unwrap();"]
#[doc = "```"]
pub struct MlKem1024EncapsulateDeterministic;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let _ = pqc_kem::MlKem1024Keypair::from_expanded_decapsulation_key_bytes(&[0u8; 8]);"]
#[doc = "```"]
pub struct MlKem1024FromExpanded;

#[cfg_attr(not(feature = "kat"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "kat", doc = "```")]
#[doc = "let kp = pqc_kem::MlKem1024Keypair::from_secret_key_bytes(&[2u8; 64]).unwrap();"]
#[doc = "let _bytes: Vec<u8> = kp.to_expanded_decapsulation_key_bytes();"]
#[doc = "```"]
pub struct MlKem1024ToExpanded;
