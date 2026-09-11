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

### Advisory history: the `mceliece`/`bike`-reachable PQClean advisories (resolved in 0.3.0)

Prior to 0.3.0, `cargo deny check` was expected to fail: three transitively-reachable
crates (`pqcrypto-traits`, `pqcrypto-internals`, `pqcrypto-classicmceliece`), pulled in
only by the non-default, never-implemented `mceliece` feature, carried `unmaintained`
advisories because the upstream [PQClean](https://github.com/PQClean/PQClean) project (the
C implementations behind the `pqcrypto-*` crate family) was
[being archived in or after July 2026](https://github.com/PQClean/PQClean/issues/604)
([announcement](https://github.com/rustpq/pqcrypto/issues/97)). That was a recorded
accept-and-document decision (P1-06, 2026-08-24; applied 2026-08-25, P2-07):
`advisories.ignore` in `deny.toml` stayed empty on purpose, and the three RUSTSEC IDs were
listed here with rationale instead of suppressed.

**0.3.0 (WP1, feature-surface hygiene) removed the root cause**, not just the symptom: the
`bike` and `mceliece` features and their `src/bike`/`src/mceliece` modules — each a
permanent `compile_error!` stub that never had a working implementation — were deleted
entirely, along with the `pqcrypto-classicmceliece` and `pqcrypto-traits` dependencies. As
of 0.3.0, none of the three advisories above are reachable through any configuration of
this crate, `--all-features` included. `cargo deny check` is expected to pass all four
checks (advisories, bans, licenses, sources) and is treated as a hard-fail CI gate going
forward — see `.github/workflows/cargo-deny.yml`.

(`hqc` moved off the `pqcrypto-*` family to `liboqs`/the `oqs` crate in 0.2.0, for an
unrelated reason — a correctness/panic-safety defect in `pqcrypto-hqc`'s `decapsulate()`,
documented in `CHANGELOG.md` and `src/hqc/mod.rs` module docs — and was already unaffected
by the advisories above.)

**If a new advisory appears:** record the decision (resolved, accepted, or blocking) in a
new section here, following the same shape as this one — don't silently add to
`advisories.ignore`.
