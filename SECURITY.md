# Security Policy

## Reporting a vulnerability

Email **security@0x307.com**. This address is monitored and routes to a human — not a
mailing list nobody reads.

Please do not open a public GitHub issue for a suspected vulnerability. Include as much
detail as you can: affected version, reproduction steps, and impact if known.

## Response window

Reports are acknowledged within **5 business days**. This is a best-effort
project with a single maintainer and no on-call rotation — see
[`STABILITY.md`](./STABILITY.md) for the full support posture. The response window above is
the one committed number in that posture; everything else is best-effort.

## Supported versions

This project ships `0.x`. Security fixes land on the latest published minor version. Older
`0.x` minors are not backported to, consistent with the stated stability policy.

## Dependency scanning

Dependencies are scanned with [`cargo-deny`](https://embarkstudios.github.io/cargo-deny/)
against the [`deny.toml`](./deny.toml) in this repo — advisories, licenses, bans, and
sources. It runs on every push to `main`, on pull requests, and on a weekly schedule
(Mondays 06:00 UTC), and a failure files a tracking issue rather than only turning a run
red. To reproduce locally:

```
cargo deny --config deny.toml check
```

`deny.toml` sets `all-features = true` on purpose. It scans the **full opt-in surface**,
not just the default build: a feature you *can* enable is one whose advisories you should
know about *before* you enable it, not after.

### Known and accepted advisories

**The `cargo-deny` workflow is expected to fail, and a red run there is the correct,
intended state — not a broken build.** The four advisories below are known, accepted, and
deliberately *not* suppressed: `advisories.ignore` in `deny.toml` is empty, so nothing is
hidden from the tool. That is what keeps a genuinely *new* advisory visible instead of
letting it land silently on top of an already-accepted one. The `CI` workflow is separate
and is the one that must stay green.

All four have the same root cause. The [PQClean](https://github.com/PQClean/PQClean)
project — the upstream C implementations behind the `pqcrypto-*` crate family — is
[being archived in or after July 2026](https://github.com/PQClean/PQClean/issues/604), so
every binding in that family inherits an `unmaintained` advisory
([announcement](https://github.com/rustpq/pqcrypto/issues/97)). No safe upgrade exists.

| Advisory | Crate | Reachable only via |
|---|---|---|
| [RUSTSEC-2026-0162](https://rustsec.org/advisories/RUSTSEC-2026-0162) | `pqcrypto-traits` | `hqc` or `mceliece` |
| [RUSTSEC-2026-0163](https://rustsec.org/advisories/RUSTSEC-2026-0163) | `pqcrypto-internals` | `hqc` or `mceliece` (transitive) |
| [RUSTSEC-2026-0167](https://rustsec.org/advisories/RUSTSEC-2026-0167) | `pqcrypto-classicmceliece` | `mceliece` |
| [RUSTSEC-2026-0168](https://rustsec.org/advisories/RUSTSEC-2026-0168) | `pqcrypto-hqc` | `hqc` |

**Why this is an accept and not a shrug:**

- **None of these are in the default build.** `default = ["std"]`; `hqc` and `mceliece` are
  separate opt-in features. A plain `cargo build` / `cargo test` — what a `cargo add
  pqc-kem` consumer gets — never links any of these four crates.
- **Those features don't currently build at all.** `hqc`, `bike`, and `mceliece` are gated
  behind deliberate `compile_error!` stubs, because the published `pqcrypto-*` APIs don't
  expose what this crate calls against. So today the advisories aren't merely opt-in, they
  are unreachable: there is no configuration of this crate that ships that code. CI asserts
  this in both directions.
- **These are maintenance-capacity advisories, not known vulnerabilities.** No CVE, no
  exploit — upstream is winding down.

**Revisit triggers**, so "accepted" doesn't quietly become "forgotten":

- **`pqcrypto-hqc` / `pqcrypto-classicmceliece`** — revisit if and when HQC or Classic
  McEliece gets a real, non-stub implementation here. The advisory is inherited from
  PQClean's archival, not from anything specific to how this crate uses them; any real
  implementation needs a maintained source regardless.
- **`pqcrypto-traits` / `pqcrypto-internals`** — these resolve on their own if the two
  bindings above are replaced, since they are shared plumbing for that family.
- **Anything failing beyond this table** — a new RUSTSEC ID, a license, a ban, or a source
  — is *not* covered by this acceptance and needs its own decision recorded here.

Decision recorded 2026-08-24 (P1-06); applied to this repo 2026-08-25 (P2-07).
