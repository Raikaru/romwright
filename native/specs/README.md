# Analyzer specs for the native worker (static, Java-free runtime)

These five files are the exact documents `DecompInterface.registerProgram`
sends, generated ONCE by `lre-cli dump-specs` (bridge, Ghidra 12.1.3) for
the x86-64 ELF fixture and vendored as static assets:

- pspec.xml / cspec.xml — install data files (x86-64.pspec, x86-64-gcc.cspec)
- tspec.xml — Java encodeTranslator output (in RAW-SLEIGH mode the worker
  replaces the `<sleigh>` tag with the SLA path, so the content is inert)
- coretypes.xml + registers.txt — program-fixed knowledge (base types,
  register offsets)

Regeneration (only when the pinned language changes):
    lre-cli dump-specs <program> --out native/specs

At runtime the worker is 100% Java-free; this directory is a build-time
artifact exactly like the compiled x86-64.sla.

The locked i386, AArch64 and PowerPC corpus contexts use generated caches
in `<language-id-with-dashes>/`. Their committed `*.manifest.json` files
record the exact language/compiler, pinned upstream and bridge provenance,
representative input hash, and all five output hashes and byte counts.
Provision these caches before running the native corpus gate:

```sh
python3 scripts/gen_native_specs.py --corpus-dir /path/to/corpus
python3 scripts/gen_native_specs.py --corpus-dir /path/to/corpus --check
python3 tests/m2-006_specs.py --corpus-dir /path/to/corpus
```

Provisioning invokes the bridge with the locked context. A fresh export
must match an existing manifest; it never silently replaces the manifest.
The ignored cache directories are reproducible build inputs, not new
runtime project owners. `--check` verifies their hashes without starting
Java. Decompilation uses only the native worker and compiled SLEIGH.
