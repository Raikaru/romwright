# Releasing

A release is a directory of artifacts, an SPDX SBOM naming everything they
were built from, and a manifest recording each artifact's size and SHA-256.
Every command below is run by `tests/m6-004_release_artifacts.py`, which then
checks the results — including that a tampered artifact fails verification —
so a documented step that no longer works fails the gate.

`$RELEASE` is the directory the artifacts are staged in.

## Tagging is reserved

AGENTS.md II.1 reserves tagging a release to the human: it is a public claim.
These steps produce and verify the artifacts; publishing them is a separate,
deliberate act.

## Build and stage

```console
$ cargo build --profile dist -p romwright-cli -p romwright-worker -p romwright-desktop
$ cargo build --profile dist-service -p romwright-api
$ python3 packaging/package_desktop.py --no-build --output build/desktop-package
$ python3 packaging/stage_release.py --release $RELEASE --package build/desktop-package
```

What ships is built with two profiles (`Cargo.toml`), and nothing in a release is
taken from the development `release` profile (the tests' own builds, `cargo test
--release`, a `cargo build --release` to try a change: fast to build, not what a
user runs).

- `dist` inherits `release` and adds `lto = "fat"` with one code-generation
  unit: the binaries are 19% smaller and the importer's resident code 4 MB
  less, at about twice the build time. The CLI, the worker and the desktop are
  built with it.
- `dist-service` is `dist` optimised for size (`opt-level = "s"`), with the
  importer's crates (`romwright-core` and the SLEIGH decoder, `kuna-*`) kept at
  full optimisation. It builds `romwright-api`, the one binary that stays
  resident for a whole session beside a decompiler, whose memory
  `tests/m7-003` bounds: a request round touches about 2 MB of its code, and
  the kernel maps the 64 KiB around every page it touches, so the resident
  size follows the binary's size. The service is 14.9 MB instead of 17.3 and a
  session's resident size 1.5-1.8 MB less. The importer, which the service
  shares with the CLI, stays at full optimisation: a CLI built with this
  profile imported Persona 4 and a GBA image within 5-9% of the `dist` one
  (host noise is of that order), while size-optimising the importer as well
  (`z`) made an import 1.7x slower. `panic =
  "abort"` would shave more and is not used: the structurer and the merge pass
  catch a panic in one function and report it for that function, which a
  service must not turn into a dead process. In a stdio session the service
  also keeps one allocator arena (`mallopt`, `romwright-api/src/main.rs`): its
  request thread and its job thread take turns, and the second arena was
  0.9 MB resident beside the first's 0.7; the HTTP transport serves
  connections concurrently and keeps glibc's default.

The memory gates (`tests/m7-001`, `m7-002`, `m7-003`) build and measure the
binaries with the profile each ships with, so that they measure what ships.

`stage_release.py` copies whatever the build produced, `.exe` suffixes
included, and fails if a binary is missing rather than shipping a partial set.
Both scripts read the build from `$CARGO_TARGET_DIR` when that variable is set,
`target/` otherwise: `dist/` for the CLI, the worker and the desktop,
`dist-service/` for the service (`stage_release.py --binaries DIR` reads every
binary from one directory instead).

`package_desktop.py` writes the desktop archive,
`romwright-<version>-<system>-<machine>.tar.gz` (for example
`romwright-0.5.0-Linux-x86_64.tar.gz`), with one top-level directory holding
`bin/romwright-desktop`, the `bin/romwright-worker` it decompiles through and
the `bin/romwright-cli` its **Create project** runs, plus
`share/doc/romwright/` with `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`
and the OFL licences of the fonts compiled into the executable. Without
`--no-build` it runs `cargo build --profile dist` itself. The archive is named after the
system and processor, so the staging step finds it rather than naming it.
`docs/desktop.md` covers how that archive is gated.

## Describe

```console
$ python3 packaging/sbom.py --output $RELEASE/romwright.spdx.json
```

The SBOM is SPDX 2.3 built from the Cargo dependency graph. The gate requires
it to name **every** workspace crate and to declare a licence for every
package, so a dependency added without a licence cannot ship quietly.

## Manifest and verify

```console
$ python3 packaging/update_manifest.py --version 0.5.0-dev --root $RELEASE --output $RELEASE/update.json $RELEASE
$ python3 packaging/verify_update.py $RELEASE/update.json --root $RELEASE
```

Passing the release directory manifests every file in it and excludes the
manifest itself, so the artifact list cannot drift from what was staged.
Verification recomputes each size and digest, refuses a path that escapes the
root, and reports every failure rather than the first.

The gate proves the verification bites: it flips one byte in the largest
artifact (`SHA-256 mismatch`), truncates it (`size mismatch`), and restores it.

## What is not covered

Reproducibility is not claimed: these steps produce artifacts from this
checkout, and nothing here asserts that two builds are byte-identical. Signing
is not implemented — the manifest carries digests, not signatures.
