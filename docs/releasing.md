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
$ cargo build --release -p lre-cli -p lre-api -p lre-worker
$ python3 packaging/stage_release.py --release $RELEASE
```

`stage_release.py` copies whatever the build produced, `.exe` suffixes
included, and fails if a binary is missing rather than shipping a partial set.

<!-- requires: qt -->

```console
$ cmake -S desktop/ventris-qt -B build/ventris-qt -DCMAKE_BUILD_TYPE=Release
$ cmake --build build/ventris-qt --config Release --target ventris-qt
$ cmake --build build/ventris-qt --config Release --target package
$ python3 packaging/stage_release.py --release $RELEASE --package build/ventris-qt
```

The desktop archive is named after the system and processor
(`ventris-0.5-Linux-x86_64.tar.gz`), so the staging step finds it rather than
naming it. `docs/desktop.md` covers what that archive contains and how it is
gated.

## Describe

```console
$ python3 packaging/sbom.py --output $RELEASE/ventris.spdx.json
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
