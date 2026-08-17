# Dependency and License Review

Review date: 2026-08-17  
Lockfile: `Cargo.lock` (235 third-party packages)  
Project license: MIT (`LICENSE`)

## Supply-chain findings

- `cargo audit --no-fetch` scanned the lockfile against 1,216 cached RustSec advisories and returned exit code 0 with no vulnerability finding.
- `cargo metadata --locked` found no Git-sourced dependency and no package with missing license metadata.
- Direct dependencies use crates.io releases pinned by `Cargo.lock`; production builds use `cargo build --locked`.
- The Docker build pins `rust:1.97.1-bookworm` and uses Debian Bookworm slim for runtime. Image digests must be recorded by the production release process because mutable tag refresh is an explicit operator decision.

## Declared license families

The resolved dependency graph declares only the following SPDX families/combinations:

- MIT, Apache-2.0, BSD-3-Clause, Unicode-3.0, Zlib, BSL-1.0, and Unlicense;
- dual/multi-license combinations of those licenses;
- five packages include `Apache-2.0 WITH LLVM-exception` as one selectable alternative;
- two packages include `LGPL-2.1-or-later` only as one alternative alongside permissive MIT/Apache-2.0 terms.

No dependency is forced to a copyleft-only license by its declared expression. This is an engineering inventory, not legal advice; the distributing organization should retain its own legal approval process.

## Release policy

For every production release:

1. keep `Cargo.lock` committed and build with `--locked`;
2. run RustSec audit with a current advisory database when network policy permits;
3. rerun `cargo metadata --locked` and investigate any missing license, Git source, or new license family;
4. review major-version upgrades and crypto/auth/database changes manually;
5. record the container image digest and preserve source/lockfile corresponding to it.
