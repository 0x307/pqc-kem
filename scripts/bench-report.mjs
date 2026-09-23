#!/usr/bin/env node
// Generate BENCHMARKS.md from a criterion run.
//
// The table is generated, never written by hand, because a published number
// and the harness that produced it must not be able to drift apart. If you
// want to change what the table says, change what gets measured.
//
//   cargo bench --bench kem
//   node scripts/bench-report.mjs > BENCHMARKS.md
//
// Adapted from pqc-sig's copy of this script. The duplication is deliberate:
// two small scripts in two repos beat a shared crate that both must depend on
// to produce a document.
//
// Reads criterion's own estimates.json rather than parsing its console output:
// the JSON carries the median and a 95% confidence interval, so the table can
// report spread instead of a single number pretending to be exact.
//
// Requires node. Generating the report is a maintainer task; running the
// benchmarks is not, and needs nothing but cargo.

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { execSync } from "node:child_process";
import { join } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const CRIT = join(ROOT, "target", "criterion");

function sh(cmd, fallback = "unknown") {
  try {
    return execSync(cmd, { cwd: ROOT, stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
  } catch {
    return fallback;
  }
}

/** Nanoseconds to a human figure, with the unit chosen per value. */
function fmt(ns) {
  if (ns < 1_000) return `${ns.toFixed(1)} ns`;
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(1)} µs`;
  if (ns < 1_000_000_000) return `${(ns / 1_000_000).toFixed(2)} ms`;
  return `${(ns / 1_000_000_000).toFixed(2)} s`;
}

/** Walk target/criterion/<group>/<bench>/new/estimates.json. */
function collect() {
  if (!existsSync(CRIT)) return [];
  const out = [];
  for (const group of readdirSync(CRIT)) {
    const gdir = join(CRIT, group);
    if (!statSync(gdir).isDirectory() || group === "report") continue;
    for (const bench of readdirSync(gdir)) {
      const est = join(gdir, bench, "new", "estimates.json");
      if (!existsSync(est)) continue;
      const j = JSON.parse(readFileSync(est, "utf8"));

      // Criterion also records how far this run moved from the previous one,
      // as a fraction, in change/estimates.json. That number is the whole
      // stability story: the confidence interval above measures noise *within*
      // a run and is blind to the machine getting hotter between them.
      let drift = null;
      const chg = join(gdir, bench, "change", "estimates.json");
      if (existsSync(chg)) {
        try {
          drift = JSON.parse(readFileSync(chg, "utf8")).median.point_estimate;
        } catch {
          drift = null;
        }
      }

      out.push({
        group,
        bench,
        median: j.median.point_estimate,
        lo: j.median.confidence_interval.lower_bound,
        hi: j.median.confidence_interval.upper_bound,
        drift,
      });
    }
  }
  return out;
}

// What the benchmark binary was actually compiled with, written by
// benches/kem.rs at the start of every run. `target/criterion` is a union of
// every run this machine has ever done -- criterion never clears it -- so the
// directory listing alone cannot say what the *last* run measured. Without
// this, a run made without `hqc` after one made with it would publish the
// earlier HQC rows as though they had just been measured.
const MANIFEST = join(CRIT, "run-manifest.json");
let runFeatures = null;
if (existsSync(MANIFEST)) {
  try {
    runFeatures = JSON.parse(readFileSync(MANIFEST, "utf8")).features ?? [];
  } catch {
    runFeatures = null;
  }
}
if (runFeatures === null) {
  console.error(
    "No readable target/criterion/run-manifest.json.\n" +
      "It is written by benches/kem.rs, so this means either the bench has not\n" +
      "been run since the manifest was introduced, or results were carried over\n" +
      "from elsewhere. Either way the directory cannot be trusted to describe\n" +
      "the last run. Re-run `cargo bench --bench kem` (plus any --features)."
  );
  process.exit(1);
}

const allRows = collect();

// Drop groups the last run could not have produced. Their numbers may be
// perfectly real, but they belong to a different build, and a table that
// mixes builds is exactly the drift this file exists to prevent.
const gated = { hqc: "hqc" };
const rows = allRows.filter((r) => {
  for (const [prefix, feat] of Object.entries(gated)) {
    if (r.group.startsWith(prefix)) return runFeatures.includes(feat);
  }
  return true;
});

const dropped = [...new Set(allRows.filter((r) => !rows.includes(r)).map((r) => r.group))];
if (dropped.length) {
  console.error(
    `note: ignoring ${dropped.length} stale group(s) from an earlier run with ` +
      `different features: ${dropped.join(", ")}`
  );
}

if (rows.length === 0) {
  console.error(
    "No criterion results found under target/criterion.\n" +
      "Run `cargo bench --bench kem` first."
  );
  process.exit(1);
}

// Absent ML-KEM means the run did not measure the crate's recommended
// default, which would publish a table about everything except the thing
// most readers came for. Refuse rather than emit it.
//
// HQC is deliberately NOT guarded this way: it wraps a C-backed crate, so
// requiring it would make the report unbuildable for anyone without a C
// toolchain. Its absence is reported below instead of being silently passed
// over.
if (!rows.some((r) => r.group.startsWith("ml-kem"))) {
  console.error(
    "No ML-KEM results found, so this run did not measure the crate's\n" +
      "recommended default. Re-run `cargo bench --bench kem`."
  );
  process.exit(1);
}

const hasHqc = rows.some((r) => r.group.startsWith("hqc"));
// Both hybrid profiles ship in every build -- v1 is PRIMARY_ALGORITHM -- so
// both must be in every run. A table missing either would describe less than
// the crate actually offers, which is the ML-KEM guard's reasoning again.
const V1 = "hybrid-v1-x25519-ml-kem-768";
const V2 = "hybrid-v2-xwing";
for (const g of [V1, V2]) {
  if (!rows.some((r) => r.group === g)) {
    console.error(
      `No ${g} results found. Both hybrid profiles are part of every build,\n` +
        "so a run without them did not measure the crate as shipped."
    );
    process.exit(1);
  }
}

// Which features the numbers came from, stated in the provenance table. A
// table containing HQC rows and a table without them describe different
// builds, and a reader cannot tell which one they have from the rows alone.
//
// Taken from the run manifest, not inferred from which groups appeared: those
// answer different questions. A feature can be on while its group produces
// nothing, and that gap is worth seeing rather than smoothing over.
const featuresUsed = runFeatures;

const version = (readFileSync(join(ROOT, "Cargo.toml"), "utf8").match(
  /^version\s*=\s*"([^"]+)"/m
) || [, "unknown"])[1];

const commit = sh("git rev-parse --short HEAD");
// `:(exclude)BENCHMARKS.md` because of how this script is meant to be run:
// `node scripts/bench-report.mjs > BENCHMARKS.md`. The shell truncates that
// file before node starts, so without the exclusion the report sees its own
// output as a modification and stamps itself "(working tree dirty)". Every
// report carried that stamp until 2026-09-23, on trees that were otherwise
// clean -- which tells a reader the numbers may not match the named commit
// when they did.
const dirty =
  sh('git status --porcelain -- . ":(exclude)BENCHMARKS.md"') !== ""
    ? " (working tree dirty)"
    : "";
const rustc = sh("rustc --version");
const date = new Date().toISOString().slice(0, 10);

let cpu = "unknown";
if (process.platform === "win32") {
  // Not `wmic`: it is deprecated and absent on current Windows, and returns
  // an empty string rather than failing, so the report would have quietly
  // said "unknown" forever.
  cpu =
    sh(
      'powershell -NoProfile -Command "(Get-CimInstance Win32_Processor).Name"',
      ""
    ).trim() || "unknown";
} else if (process.platform === "linux") {
  cpu = sh("grep -m1 'model name' /proc/cpuinfo", "").split(":").slice(1).join(":").trim();
} else if (process.platform === "darwin") {
  cpu = sh("sysctl -n machdep.cpu.brand_string");
}

const groups = [...new Set(rows.map((r) => r.group))].sort();

// ── Measurement stability ────────────────────────────────────────────────────
//
// A benchmark that moved between two runs of unchanged code measured the
// machine, not the code. This is the check that makes that visible in the
// document instead of only in whoever happened to run it twice.
//
// 5% is the threshold below which a figure is worth quoting. Above it, the
// number is a property of the conditions as much as of the code.
const DRIFT_LIMIT = 0.05;
const withDrift = rows.filter((r) => r.drift !== null);
const drifted = withDrift.filter((r) => Math.abs(r.drift) > DRIFT_LIMIT);
const worst = withDrift.length
  ? withDrift.reduce((a, b) => (Math.abs(b.drift) > Math.abs(a.drift) ? b : a))
  : null;
// A third of the suite moving is not a code change, it is the environment.
const UNSTABLE_RATIO = 0.33;
const unstable = withDrift.length > 0 && drifted.length / withDrift.length > UNSTABLE_RATIO;
const pct = (d) => `${d >= 0 ? "+" : ""}${(d * 100).toFixed(1)}%`;

let md = `# Benchmarks
${
  unstable
    ? `
> [!WARNING]
> **These figures are not stable on the machine that produced them.**
> ${drifted.length} of ${withDrift.length} benchmarks moved more than
> ${(DRIFT_LIMIT * 100).toFixed(0)}% against the previous run of the same code,
> the worst by **${pct(worst.drift)}** (\`${worst.group}/${worst.bench}\`).
>
> Treat the absolute numbers below as indicative only. Comparisons *within* a
> single run remain meaningful, because every operation throttles together —
> so "A is twice B" survives what "A is 29.8 ms" does not.
>
> See **Measurement stability** below.
`
    : ""
}

Generated by \`scripts/bench-report.mjs\` from a criterion run. **Do not edit
by hand** — a published number and the harness that produced it must not be
able to drift apart.

Reproduce:

\`\`\`bash
cargo bench --bench kem${featuresUsed.length ? ` --features ${featuresUsed.join(",")}` : ""}
node scripts/bench-report.mjs > BENCHMARKS.md
\`\`\`

The feature flags above are the ones this run used, not a suggestion — run it
without them and you get a different table, correctly.

## Provenance

| | |
|---|---|
| Crate version | \`${version}\` |
| Commit | \`${commit}\`${dirty} |
| Date | ${date} |
| Toolchain | ${rustc} |
| CPU | ${cpu} |
| Profile | \`[profile.bench]\`: \`opt-level = 3\`, \`lto = true\`, \`codegen-units = 1\`, \`overflow-checks = true\` |
| Harness | [\`benches/kem.rs\`](benches/kem.rs) |
| Features | ${featuresUsed.length ? featuresUsed.map((f) => `\`${f}\``).join(", ") : "none (default build)"} |

**The profile is stated, not inherited.** \`[profile.bench]\` sets
\`opt-level = 3\` explicitly. It does not set \`panic\`: cargo ignores that for
the bench profile and says so, so benchmarks always build with unwinding
whatever the shipping \`panic = "abort"\` does.

Sibling crate \`pqc-sig\` learned this the hard way: its release profile sets
\`opt-level = "z"\`, benchmarks silently inherited it, and the first run
published there described a size-optimised build with nothing saying so.

This crate's release profile sets only \`panic = "abort"\`, so an inherited
bench profile would have taken cargo's release defaults — \`opt-level = 3\`
already, but \`lto\` off and \`codegen-units = 16\`. Not wrong the way
\`opt-level = "z"\` was wrong, just unpinned: a later edit to
\`[profile.release]\` would change what every number in this file means,
without changing a word of the file. Pinning it is what stops that.

\`overflow-checks\` is on deliberately and is the one setting here that costs
throughput. A crypto library that silently wraps on overflow in release is a
worse trade than a few percent, so the figures are measured with the checks a
consumer would actually run.

## What these are

**Real cryptography, on every line.** There are no deterministic stand-ins, no
mock adapters and no stub backends measured here.

Two families in this crate are deliberately **not** benchmarked, because
measuring a placeholder is the commonest way a performance table becomes a
lie:

- \`bike\` is a compile-time-error stub by design and has no implementation.
- \`ntru\` is a deprecation marker for the NTRU **KEM**, withdrawn by NIST in
  Round 4. (Not to be confused with the NTRU *lattice trapdoor* under
  FN-DSA/Falcon, which is FIPS 206 and very much alive.)

Times are the **median** with a 95% confidence interval. Unlike \`pqc-sig\`'s
signing benchmarks, no input pool is needed: ML-KEM encapsulation and
decapsulation have no rejection loop, so a fixed input does not freeze a
variable iteration count.

Decapsulation is measured on a **valid** ciphertext. ML-KEM's implicit
rejection means a malformed one costs the same by construction — but that is a
constant-time claim, and a median with a confidence interval is not the tool
that establishes it.

## Results

`;

for (const g of groups) {
  md += `### ${g}\n\n| Operation | Median | 95% CI |\n|---|---:|---|\n`;
  for (const r of rows.filter((x) => x.group === g).sort((a, b) => a.bench.localeCompare(b.bench))) {
    md += `| \`${r.bench}\` | ${fmt(r.median)} | ${fmt(r.lo)} – ${fmt(r.hi)} |\n`;
  }
  md += "\n";
}

{
  // Computed, never asserted. An earlier version of this section carried the
  // hand-written claim "X25519 adds roughly twice what ML-KEM-768 costs" --
  // true of encapsulation, wrong about keygen and decapsulation -- in a file
  // whose premise is that a published number and the harness producing it
  // must not drift apart. Every figure in the prose below is derived from rows.
  const med = (group, bench) => rows.find((r) => r.group === group && r.bench === bench)?.median;
  const costRows = ["keygen", "encapsulate", "decapsulate"]
    .map((op) => ({ op, m: med("ml-kem-768", op), v1: med(V1, op), v2: med(V2, op) }))
    .filter((r) => r.m != null && r.v1 != null && r.v2 != null);
  const x = (a, b) => `${(a / b).toFixed(2)}×`;
  const worstV1 = costRows.slice().sort((a, b) => b.v1 / b.m - a.v1 / a.m)[0];
  const v2vsv1 = costRows.map((r) => `${x(r.v2, r.v1)} on \`${r.op}\``).join(", ");

  md += `## What the hybrid costs, which is why each profile has its own group

Both hybrid profiles combine X25519 with ML-KEM-768. v1 (\`${V1}\`) is the
crate's \`PRIMARY_ALGORITHM\` and derives the shared secret with HKDF-SHA256;
v2 (\`${V2}\`) is X-Wing, which uses a SHA3-256 combiner that also binds the
X25519 ciphertext and public key, and expands a single seed into both keys.
Benching them separately from \`ml-kem-768\` makes the cost of the X25519 hedge
something a reader can read off the table rather than infer.

| Operation | ML-KEM-768 alone | v1 (HKDF) | v2 (X-Wing) | v1 ÷ ML-KEM-768 | v2 ÷ ML-KEM-768 | v2 ÷ v1 |
|---|---:|---:|---:|---:|---:|---:|
${costRows
  .map((r) => `| \`${r.op}\` | ${fmt(r.m)} | ${fmt(r.v1)} | ${fmt(r.v2)} | ${x(r.v1, r.m)} | ${x(r.v2, r.m)} | ${x(r.v2, r.v1)} |`)
  .join("\n")}

**The classical half is not the cheap half.** v1 takes ${x(worstV1.v1, worstV1.m)}
ML-KEM-768's time on \`${worstV1.op}\`, the operation where X25519 shows most.
Against v1, X-Wing takes ${v2vsv1}.

The hybrid is the default anyway, on purpose. For key exchange the threat is
a session recorded today and decrypted later, and a hybrid stays secure if
*either* component holds, so an unexpected break in ML-KEM does not expose
recorded traffic. A broken signature scheme can be rotated out; a recorded
ciphertext cannot be re-encrypted. The cost above is what that hedge costs.
`;
}

md += `## Measurement stability

Criterion's confidence intervals above measure variation **within** a run.
They say nothing about variation **between** runs, which on a thermally
constrained machine is much larger — and which looks identical to a real
regression.

This section reports the shift against the previous run of this suite. If the
code did not change in between, everything here is measurement noise by
definition.

${
  withDrift.length === 0
    ? "No previous run to compare against. Run `cargo bench` twice to populate this."
    : unstable
      ? `**Unstable.** ${drifted.length} of ${withDrift.length} benchmarks moved more than ${(DRIFT_LIMIT * 100).toFixed(0)}% against the previous run.

| Benchmark | Shift |
|---|---:|
${drifted
  .sort((a, b) => Math.abs(b.drift) - Math.abs(a.drift))
  .slice(0, 12)
  .map((r) => `| \`${r.group}/${r.bench}\` | ${pct(r.drift)} |`)
  .join("\n")}

A laptop under sustained benchmark load throttles, and the effect compounds
across a long suite: the operations measured last are measured on the hottest
silicon. Publishing an absolute figure taken this way states a property of the
afternoon rather than of the code.

**For figures intended to be quoted**, regenerate on a machine with a stable
clock: a desktop or server part with thermal headroom, idle, with frequency
scaling pinned. The numbers will differ, and they will mean something.`
      : drifted.length === 0
        ? `**Stable.** No benchmark moved more than ${(DRIFT_LIMIT * 100).toFixed(0)}% against the previous run${worst ? `; the largest shift was ${pct(worst.drift)} (\`${worst.group}/${worst.bench}\`)` : ""}.`
        : `**Mixed.** ${drifted.length} of ${withDrift.length} benchmarks moved more than ${(DRIFT_LIMIT * 100).toFixed(0)}% against the previous run, the worst by **${pct(worst.drift)}** (\`${worst.group}/${worst.bench}\`). That is below the ${(UNSTABLE_RATIO * 100).toFixed(0)}% of the suite it would take to call the whole run unstable, but it is not nothing.

| Benchmark | Shift |
|---|---:|
${drifted
  .sort((a, b) => Math.abs(b.drift) - Math.abs(a.drift))
  .slice(0, 12)
  .map((r) => `| \`${r.group}/${r.bench}\` | ${pct(r.drift)} |`)
  .join("\n")}

With the code unchanged between runs, shifts of this size are the machine, not
the crate. Treat the absolute figures above as indicative until they are
regenerated somewhere with a stable clock.`
}

## What is not measured

Stated so the absence is not mistaken for a result.

${hasHqc ? "" : "- **HQC.** Not measured in this run; rebuild with `--features hqc`. It is a real implementation via `liboqs`, not a stub — absent here only because it needs a C toolchain.\n"}\
- **Key and ciphertext sizes.** Fixed per parameter set and documented in the
  crate docs; they are not timings and do not belong in this table.
- **WASM.** Every figure here is native. HQC does not build for
  \`wasm32-unknown-unknown\` at all; ML-KEM and both hybrid profiles do.
- **Constant-time behaviour.** A median and a confidence interval say nothing
  about whether timing varies with secret data. That needs a different tool
  and a different claim.
- **Comparison against anything classical on its own.** X25519 appears only
  inside the two hybrid profiles, as part of a construction rather than as a
  baseline to beat. No aggregate "PQC overhead" figure: an
  aggregate hides which operation moved.
`;

process.stdout.write(md);
console.error(`ok: ${rows.length} benchmarks across ${groups.length} groups`);
