/**
 * tests/wasm_api_test.mjs
 *
 * Node.js ESM regression tests for the pqc-kem WASM API.
 * Run with: node tests/wasm_api_test.mjs
 *
 * Requires a successful wasm-pack build in dist/ (there is no `wasm` feature
 * on `pqc-kem` -- it was removed; see CHANGELOG.md 0.3.0 and README.md
 * "Feature Flags"). Produce dist/ with either:
 *   powershell -ExecutionPolicy Bypass -File build.ps1
 * or the equivalent raw wasm-pack invocation it runs, from pqc-kem-wasm/:
 *   wasm-pack build --target web --out-dir ../dist --release -- --no-default-features
 */

import { readFileSync } from 'fs';
import { fileURLToPath, pathToFileURL } from 'url';
import { dirname, join } from 'path';

// ── Resolve paths relative to this file ──────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const distDir    = join(__dirname, '..', 'dist');
const wasmPath   = join(distDir, 'pqc_kem_bg.wasm');

// ── Expected version, read from pqc-kem's Cargo.toml at run time ───────────
// Avoids a second hardcoded literal drifting out of sync with the crate
// version the way the old literal "0.1.0" did (A-D1).
//
// Reads the *pqc-kem* manifest, not pqc-kem-wasm's. `pqc_kem_version()`
// returns `pqc_kem::VERSION`, which is `env!("CARGO_PKG_VERSION")` evaluated
// inside pqc-kem, so that is the version it must be compared against. The
// two manifests agree today only because both were bumped together; the wasm
// crate is `publish = false` and is free to lag, and comparing against it
// would then fail for the wrong reason or pass while checking nothing.
//
// No hardcoded fallback: if the manifest can't be read, the test must fail
// rather than quietly compare against a literal nobody updates.
function readExpectedVersion() {
  const manifestPath = join(__dirname, '..', 'Cargo.toml');
  const manifest = readFileSync(manifestPath, 'utf8');
  const match = manifest.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) throw new Error(`no version line found in ${manifestPath}`);
  return match[1];
}
const expectedVersion = readExpectedVersion();

// ── Load the wasm-bindgen JS glue (web target) ────────────────────────────────
// On Windows, dynamic import() requires a file:// URL — not a raw Win32 path.
// The web target uses `import.meta.url` for the default WASM path, so we must
// pass the WASM bytes directly via initSync to avoid fetch() in Node.
const {
  default: init,
  initSync,
  WasmHybridKemKeypair,
  WasmMlKem512Keypair,
  WasmMlKem768Keypair,
  WasmMlKem1024Keypair,
  hybrid_encapsulate,
  ml_kem_512_encapsulate,
  ml_kem_768_encapsulate,
  ml_kem_1024_encapsulate,
  pqc_kem_version,
  primary_algorithm,
  hybrid_encapsulate_bytes,
  hybrid_profile_id,
  aead_seal_hybrid,
  aead_seal_ml_kem_768,
} = await import(pathToFileURL(join(distDir, 'pqc_kem.js')).href);

// ── Initialize WASM synchronously from file bytes ────────────────────────────
const wasmBytes = readFileSync(wasmPath);
initSync({ module: wasmBytes });

// ── Helpers ───────────────────────────────────────────────────────────────────

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertEqual(a, b, message) {
  if (a !== b) {
    throw new Error(`Assertion failed: ${message} — expected ${JSON.stringify(a)}, got ${JSON.stringify(b)}`);
  }
}

/**
 * Decode a base64url string (no padding, URL-safe alphabet) to Uint8Array.
 * Uses Node.js Buffer for reliability.
 */
function base64urlDecode(str) {
  // Convert base64url → base64 (add padding, swap chars)
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4;
  const b64 = pad === 0 ? padded : padded + '='.repeat(4 - pad);
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

let passed = 0;
let failed = 0;

function runTest(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${e.message}`);
    failed++;
  }
}

async function runTestAsync(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${e.message}`);
    failed++;
  }
}

// =============================================================================
// TEST 1 — Hybrid KEM round-trip
// =============================================================================
console.log('\nTest 1 — Hybrid KEM round-trip:');
runTest('keypair generates and public_key_json returns valid JSON', () => {
  const keypair = new WasmHybridKemKeypair();
  const pubKeyJson = keypair.public_key_json();
  const pub = JSON.parse(pubKeyJson);
  assert(typeof pub.x25519_key      === 'string', 'x25519_key must be a string');
  assert(typeof pub.mlkem_key       === 'string', 'mlkem_key must be a string');
  assert(typeof pub.x25519_multibase === 'string', 'x25519_multibase must be a string');
  assert(typeof pub.mlkem_multibase  === 'string', 'mlkem_multibase must be a string');
  keypair.free();
});

runTest('hybrid_encapsulate returns ciphertext and shared_secret fields', () => {
  const keypair = new WasmHybridKemKeypair();
  const pubKeyJson = keypair.public_key_json();
  const result = JSON.parse(hybrid_encapsulate(pubKeyJson));
  assert(result.ciphertext   !== undefined, 'result must have ciphertext field');
  assert(typeof result.shared_secret === 'string', 'shared_secret must be a base64url string');
  keypair.free();
});

runTest('hybrid decapsulate returns 32-byte Uint8Array', () => {
  const keypair = new WasmHybridKemKeypair();
  const pubKeyJson = keypair.public_key_json();
  const result = JSON.parse(hybrid_encapsulate(pubKeyJson));
  const recovered = keypair.decapsulate(JSON.stringify(result.ciphertext));
  assert(recovered instanceof Uint8Array, 'recovered must be Uint8Array');
  assertEqual(recovered.length, 32, 'recovered shared secret must be 32 bytes');
  keypair.free();
});

// =============================================================================
// TEST 2 — ML-KEM-512 round-trip
// =============================================================================
console.log('\nTest 2 — ML-KEM-512 round-trip:');
runTest('ML-KEM-512 public key is 800 bytes', () => {
  const keypair = new WasmMlKem512Keypair();
  const pubKey = keypair.public_key_bytes();
  assert(pubKey instanceof Uint8Array, 'public key must be Uint8Array');
  assertEqual(pubKey.length, 800, 'ML-KEM-512 public key must be 800 bytes');
  keypair.free();
});

runTest('ML-KEM-512 encapsulate + decapsulate round-trip', () => {
  const keypair = new WasmMlKem512Keypair();
  const pubKey = keypair.public_key_bytes();
  const result = JSON.parse(ml_kem_512_encapsulate(pubKey));
  const ct = base64urlDecode(result.ciphertext);
  assertEqual(ct.length, 768, 'ML-KEM-512 ciphertext must be 768 bytes');
  const recovered = keypair.decapsulate(ct);
  assert(recovered instanceof Uint8Array, 'recovered must be Uint8Array');
  assertEqual(recovered.length, 32, 'recovered shared secret must be 32 bytes');
  keypair.free();
});

// =============================================================================
// TEST 3 — ML-KEM-768 round-trip
// =============================================================================
console.log('\nTest 3 — ML-KEM-768 round-trip:');
runTest('ML-KEM-768 public key is 1184 bytes', () => {
  const keypair = new WasmMlKem768Keypair();
  const pubKey = keypair.public_key_bytes();
  assert(pubKey instanceof Uint8Array, 'public key must be Uint8Array');
  assertEqual(pubKey.length, 1184, 'ML-KEM-768 public key must be 1184 bytes');
  keypair.free();
});

runTest('ML-KEM-768 encapsulate + decapsulate round-trip', () => {
  const keypair = new WasmMlKem768Keypair();
  const pubKey = keypair.public_key_bytes();
  const result = JSON.parse(ml_kem_768_encapsulate(pubKey));
  const ct = base64urlDecode(result.ciphertext);
  assertEqual(ct.length, 1088, 'ML-KEM-768 ciphertext must be 1088 bytes');
  const recovered = keypair.decapsulate(ct);
  assert(recovered instanceof Uint8Array, 'recovered must be Uint8Array');
  assertEqual(recovered.length, 32, 'recovered shared secret must be 32 bytes');
  keypair.free();
});

// =============================================================================
// TEST 4 — ML-KEM-1024 round-trip
// =============================================================================
console.log('\nTest 4 — ML-KEM-1024 round-trip:');
runTest('ML-KEM-1024 public key is 1568 bytes', () => {
  const keypair = new WasmMlKem1024Keypair();
  const pubKey = keypair.public_key_bytes();
  assert(pubKey instanceof Uint8Array, 'public key must be Uint8Array');
  assertEqual(pubKey.length, 1568, 'ML-KEM-1024 public key must be 1568 bytes');
  keypair.free();
});

runTest('ML-KEM-1024 encapsulate + decapsulate round-trip', () => {
  const keypair = new WasmMlKem1024Keypair();
  const pubKey = keypair.public_key_bytes();
  const result = JSON.parse(ml_kem_1024_encapsulate(pubKey));
  const ct = base64urlDecode(result.ciphertext);
  assertEqual(ct.length, 1568, 'ML-KEM-1024 ciphertext must be 1568 bytes');
  const recovered = keypair.decapsulate(ct);
  assert(recovered instanceof Uint8Array, 'recovered must be Uint8Array');
  assertEqual(recovered.length, 32, 'recovered shared secret must be 32 bytes');
  keypair.free();
});

// =============================================================================
// TEST 5 — Shared secret equality (hybrid KEM)
// =============================================================================
console.log('\nTest 5 — Shared secret equality (hybrid KEM):');
runTest('sender and recipient shared secrets are byte-for-byte identical', () => {
  const keypair = new WasmHybridKemKeypair();
  const pubKeyJson = keypair.public_key_json();
  const result = JSON.parse(hybrid_encapsulate(pubKeyJson));

  // Sender's shared secret (base64url-encoded)
  const senderSs = base64urlDecode(result.shared_secret);
  assertEqual(senderSs.length, 32, 'sender shared secret must be 32 bytes');

  // Recipient decapsulates
  const recipientSs = keypair.decapsulate(JSON.stringify(result.ciphertext));
  assertEqual(recipientSs.length, 32, 'recipient shared secret must be 32 bytes');

  // Byte-for-byte comparison
  for (let i = 0; i < 32; i++) {
    if (senderSs[i] !== recipientSs[i]) {
      throw new Error(`Shared secret mismatch at byte ${i}: sender=${senderSs[i]}, recipient=${recipientSs[i]}`);
    }
  }

  keypair.free();
});

// =============================================================================
// TEST 6 — Version and algorithm strings
// =============================================================================
console.log('\nTest 6 — Version and algorithm strings:');
runTest(`pqc_kem_version() returns "${expectedVersion}" (read from pqc-kem's Cargo.toml)`, () => {
  const v = pqc_kem_version();
  assertEqual(v, expectedVersion, 'pqc_kem_version()');
});

runTest('primary_algorithm() returns "X25519+ML-KEM-768"', () => {
  const a = primary_algorithm();
  assertEqual(a, 'X25519+ML-KEM-768', 'primary_algorithm()');
});

// =============================================================================
// TEST 7 — Zeroization: free() and double-free protection
// =============================================================================
console.log('\nTest 7 — Zeroization: free() does not throw, double-free throws:');
runTest('free() does not throw on first call', () => {
  const kp = new WasmHybridKemKeypair();
  kp.free(); // must not throw
});

runTest('free() throws on second call (double-free protection)', () => {
  const kp = new WasmHybridKemKeypair();
  kp.free();
  let threw = false;
  try {
    kp.free();
  } catch (e) {
    threw = true;
  }
  assert(threw, 'second free() should have thrown');
});

// =============================================================================
// TEST 8 — Shared secret fill(0) (zeroization in JS)
// =============================================================================
console.log('\nTest 8 — Shared secret fill(0):');
runTest('shared secret Uint8Array can be zeroed with fill(0)', () => {
  const keypair = new WasmHybridKemKeypair();
  const pubKeyJson = keypair.public_key_json();
  const result = JSON.parse(hybrid_encapsulate(pubKeyJson));
  const ss = keypair.decapsulate(JSON.stringify(result.ciphertext));
  assert(ss instanceof Uint8Array, 'ss must be Uint8Array');
  assertEqual(ss.length, 32, 'ss must be 32 bytes');
  ss.fill(0);
  assert(ss.every(b => b === 0), 'all bytes must be 0 after fill(0)');
  keypair.free();
});

// =============================================================================
// TEST 9 — Hybrid profile v1 canonical byte encoding (WP5)
// =============================================================================
console.log('\nTest 9 — Hybrid canonical byte encoding:');
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const eqBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

runTest('hybrid public_key_bytes() is the 1216-byte canonical encoding', () => {
  const kp = new WasmHybridKemKeypair();
  assertEqual(kp.public_key_bytes().length, 1216, 'public_key_bytes length');
  kp.free();
});

runTest('hybrid_encapsulate_bytes + decapsulate_bytes agree on the secret', () => {
  const kp = new WasmHybridKemKeypair();
  const r = JSON.parse(hybrid_encapsulate_bytes(kp.public_key_bytes()));
  const ct = base64urlDecode(r.ciphertext_bytes);
  const ss = base64urlDecode(r.shared_secret);
  assertEqual(ct.length, 1120, 'canonical ciphertext length');
  assertEqual(ss.length, 32, 'shared secret length');
  assert(eqBytes(kp.decapsulate_bytes(ct), ss), 'decapsulate_bytes must recover the same secret');
  kp.free();
});

runTest('hybrid_profile_id() names profile v1', () => {
  assertEqual(hybrid_profile_id(), 'HybridKem-X25519-MLKEM768-v1', 'hybrid_profile_id()');
});

// =============================================================================
// TEST 10 — aead-wrap: seal to a public key, open with the keypair (WP6)
// =============================================================================
console.log('\nTest 10 — aead-wrap:');
const enc = (t) => new TextEncoder().encode(t);
const CTX = enc('test-protocol-v1');
const AAD = enc('header: v1');
const MSG = enc('a payload only the recipient can read');

runTest('hybrid seal/open round-trips, sealed with XChaCha20-Poly1305', () => {
  const kp = new WasmHybridKemKeypair();
  const sealed = aead_seal_hybrid(kp.public_key_json(), CTX, AAD, MSG);
  assertEqual(JSON.parse(sealed).suite, 'xchacha20-poly1305', 'suite on the wire');
  assert(eqBytes(kp.aead_open(sealed, CTX, AAD), MSG), 'opened plaintext must match');
  kp.free();
});

runTest('ML-KEM-768 seal/open round-trips', () => {
  const kp = new WasmMlKem768Keypair();
  const sealed = aead_seal_ml_kem_768(kp.public_key_bytes(), CTX, AAD, MSG);
  assert(eqBytes(kp.aead_open(sealed, CTX, AAD), MSG), 'opened plaintext must match');
  kp.free();
});

runTest('a tampered sealed box refuses to open', () => {
  const kp = new WasmHybridKemKeypair();
  const box = JSON.parse(aead_seal_hybrid(kp.public_key_json(), CTX, AAD, MSG));
  const body = base64urlDecode(box.ciphertext);
  body[0] ^= 1;
  box.ciphertext = b64u(body);
  let threw = false;
  try { kp.aead_open(JSON.stringify(box), CTX, AAD); } catch { threw = true; }
  assert(threw, 'opening a tampered box must throw');
  kp.free();
});

runTest('the wrong context refuses to open', () => {
  const kp = new WasmMlKem768Keypair();
  const sealed = aead_seal_ml_kem_768(kp.public_key_bytes(), CTX, AAD, MSG);
  let threw = false;
  try { kp.aead_open(sealed, enc('other-protocol-v1'), AAD); } catch { threw = true; }
  assert(threw, 'a different context must not open the box');
  kp.free();
});

// =============================================================================
// Summary
// =============================================================================
console.log(`\n${'─'.repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
} else {
  console.log('All tests passed ✓');
}
