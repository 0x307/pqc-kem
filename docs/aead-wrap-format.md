# `aead-wrap` output: does a sealed box carry a format version?

**Answer (checked against 0.3.1 and this branch, 2026-11-14): no.** A sealed
box has no format or version tag. Nothing in its bytes says which version of
the `aead-wrap` construction made it.

## What a sealed box is on the wire

`aead_wrap::SealedBox` has no binary encoding (`to_bytes`/`from_bytes`). Its
only encoding is the JSON object from `SealedBox::to_json` (serde), with
exactly five fields:

| Field | Content | Tags anything? |
|---|---|---|
| `kem_algorithm` | `KemAlgorithm`, e.g. `"ml_kem768"`, `"hybrid_x25519_ml_kem768"` | Names the KEM, not the box format |
| `suite` | `"xchacha20-poly1305"` or `"chacha20-poly1305"` | Names the AEAD, not the box format |
| `kem_ct` | base64url KEM ciphertext: 1088 bytes (ML-KEM-768) or 1120 (hybrid v1, `x25519 ‖ mlkem`, no tag byte) | No |
| `nonce` | base64url, 24 or 12 bytes | No |
| `ciphertext` | base64url body followed by the 16-byte Poly1305 tag | No |

There is no `version` field, and no version byte in front of `kem_ct` or
`ciphertext`.

## Where the version does live

The construction version is the HKDF label `AEAD_WRAP_INFO_V1 =
"pqc-kem-aead-wrap-v1"`, which goes into the key derivation, not into the
output. A box made under a future `-v2` derivation would look the same on the
wire as a v1 box. A v1 reader would derive a different key, and the box would
fail to open with the uniform `KemError::SymmetricCipher`, the same error as
tampering. So a version mismatch is safe (it can't decrypt to the wrong
plaintext) but it can't be told apart from a corrupted box.

Two more facts matter for adding a tag later:

- `SealedBox` doesn't use `#[serde(deny_unknown_fields)]`. A 0.3.x reader
  ignores a field it doesn't know, so a `version` field added later would be
  skipped by old readers, not refused.
- `kem_algorithm` and `suite` are already explicit, so a new KEM or AEAD can
  be added without a version tag. A tag is only needed to change the
  derivation, the AAD layout (`kem_ct ‖ aad`) or the field set.

Both facts are pinned by tests in `tests/aead_wrap_tests.rs`:
`sealed_box_json_has_exactly_five_fields_and_no_version` and
`sealed_box_reader_ignores_an_unknown_version_field`.

## What 0.3.2 does about it

Nothing on the wire. Adding a version tag changes the bytes of every sealed
box, which is a wire change, and the 0.3.2 release makes none. It is left
for 0.4.0 (Tier 2, with X-Wing in `aead-wrap`): add a `version` field, decide
whether a reader refuses a box without one, and consider
`deny_unknown_fields` at the same time.
