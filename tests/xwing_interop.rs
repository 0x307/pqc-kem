//! X-Wing interop against an independent implementation (KEM-01).
//!
//! `tests/kat_xwing.rs` checks this crate's X-Wing against the draft's own
//! published vectors. This file checks it against a second, independently
//! written X-Wing: RustCrypto's `x-wing` crate (dev-dependency only, pinned
//! in `Cargo.toml`). The other implementation encapsulates to one of this
//! crate's public keys, and this crate must decapsulate its ciphertext to the
//! same shared secret. The reverse direction is checked too.
//!
//! What is and isn't independent: `x-wing` has its own key expansion,
//! combiner, byte layout and X25519 (it uses `x25519-dalek` 3, this crate
//! uses 2). Its ML-KEM-768 half comes from the same RustCrypto `ml-kem`
//! crate this crate uses, so this test doesn't cross-check ML-KEM itself;
//! the NIST ACVP vectors in `tests/kat_ml_kem.rs` do that.
//!
//! Control: `flipped_ciphertext_byte_breaks_agreement` flips one byte of the
//! other implementation's ciphertext and checks that the shared secrets no
//! longer match, so the agreement assertions above it can fail.

use pqc_kem::fips203::{XWingCiphertext, XWingKeypair, XWingPublicKey};
use x_wing::kem::common::rand_core::{TryCryptoRng, TryRng};
use x_wing::{Decapsulate, Decapsulator, Encapsulate, KeyExport, KeyInit, TryKeyInit};

/// Fixed recipient seed. Not one of the draft's vector seeds, so this is a
/// case neither implementation was tuned against.
const SEED: [u8; 32] = [
    0x30, 0x78, 0x33, 0x30, 0x37, 0x2d, 0x6b, 0x65, 0x6d, 0x2d, 0x30, 0x2e, 0x33, 0x2e, 0x32, 0x2d,
    0x78, 0x77, 0x69, 0x6e, 0x67, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6f, 0x70, 0x2d, 0x30, 0x31,
];

/// Fixed 64 bytes of encapsulation randomness: `m` (ML-KEM) then the
/// X25519 ephemeral scalar, the split both implementations use.
const ESEED: [u8; 64] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
    0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17, 0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

/// Hands out fixed bytes, so the other implementation's ciphertext is the
/// same on every run.
struct FixedRng(Vec<u8>);

impl TryRng for FixedRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        assert!(dest.len() <= self.0.len(), "FixedRng ran out of bytes");
        dest.copy_from_slice(&self.0[..dest.len()]);
        self.0.drain(..dest.len());
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

/// The other implementation's encapsulation key, parsed from this crate's
/// public-key bytes.
fn their_ek(pk: &XWingPublicKey) -> x_wing::EncapsulationKey {
    x_wing::EncapsulationKey::new_from_slice(&pk.to_bytes())
        .expect("x-wing accepts this crate's X-Wing public key bytes")
}

/// The other implementation's ciphertext for `SEED`/`ESEED`, and its shared
/// secret.
fn their_fixed_exchange(pk: &XWingPublicKey) -> (Vec<u8>, Vec<u8>) {
    let (ct, ss) = their_ek(pk).encapsulate_with_rng(&mut FixedRng(ESEED.to_vec()));
    (ct.to_vec(), ss.to_vec())
}

fn our_decap(ours: &XWingKeypair, ct: &[u8]) -> Vec<u8> {
    let ct = XWingCiphertext::from_bytes(ct).expect("1120-byte X-Wing ciphertext");
    ours.decapsulate(&ct).expect("decapsulate").bytes.clone()
}

#[test]
fn both_implementations_derive_the_same_public_key_from_a_seed() {
    let ours = XWingKeypair::from_seed(&SEED);
    let theirs = x_wing::DecapsulationKey::new(&SEED.into());
    assert_eq!(
        ours.public_key().to_bytes(),
        theirs.encapsulation_key().to_bytes().to_vec(),
    );
}

#[test]
fn fixed_ciphertext_from_rustcrypto_decapsulates() {
    let ours = XWingKeypair::from_seed(&SEED);
    let (ct, their_ss) = their_fixed_exchange(&ours.public_key());
    assert_eq!(ct.len(), 1120);
    assert_eq!(our_decap(&ours, &ct), their_ss);
}

#[test]
fn random_ciphertexts_from_rustcrypto_decapsulate() {
    let mut rng = rand::thread_rng();
    for _ in 0..16 {
        let ours = XWingKeypair::generate(&mut rng).expect("keygen");
        let (ct, their_ss) = their_ek(&ours.public_key()).encapsulate();
        assert_eq!(our_decap(&ours, &ct), their_ss.to_vec());
    }
}

#[test]
fn rustcrypto_decapsulates_our_ciphertext() {
    let theirs = x_wing::DecapsulationKey::new(&SEED.into());
    let pk_bytes = theirs.encapsulation_key().to_bytes();
    let pk = XWingPublicKey::from_bytes(&pk_bytes).expect("1216-byte X-Wing public key");

    let mut rng = rand::thread_rng();
    for _ in 0..16 {
        let (ct, our_ss) = XWingKeypair::encapsulate(&mut rng, &pk).expect("encapsulate");
        let their_ct = x_wing::Ciphertext::try_from(ct.to_bytes().as_slice())
            .expect("1120-byte ciphertext");
        assert_eq!(theirs.decapsulate(&their_ct).to_vec(), our_ss.bytes);
    }
}

/// Control for the tests above: one flipped byte, in either half of the
/// ciphertext, and the two sides no longer agree.
#[test]
fn flipped_ciphertext_byte_breaks_agreement() {
    let ours = XWingKeypair::from_seed(&SEED);
    let (ct, their_ss) = their_fixed_exchange(&ours.public_key());
    assert_eq!(our_decap(&ours, &ct), their_ss, "unflipped must agree");

    // 0 is in the ML-KEM ciphertext, 1088 is the first byte of ct_X.
    for idx in [0usize, 1087, 1088, 1119] {
        let mut flipped = ct.clone();
        flipped[idx] ^= 0x01;
        assert_ne!(
            our_decap(&ours, &flipped),
            their_ss,
            "flipping byte {idx} must change the decapsulated secret"
        );
    }
}
