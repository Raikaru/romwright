# Security policy

## Supported versions

Security fixes target the latest published release and the current default
branch. Older releases may remain vulnerable and are not guaranteed to receive
backports.

## Reporting a vulnerability

Do not disclose an unpatched vulnerability in a public issue, discussion, or
pull request. The canonical repository is
https://github.com/Raikaru/romwright, maintained by the `Raikaru` GitHub
account. Private vulnerability reporting is enabled at **Security →
Advisories → Report a vulnerability**.

Include:

- affected release or commit;
- operating system and architecture;
- exact command or integration exercised;
- a minimal reproduction or proof of concept;
- impact and any required local permissions.

## Review boundary

The security review covers the shipped runtime surfaces:

- Rust runtime dependency versions are recorded in `Cargo.lock`. Library crates
  forbid `unsafe_code` where reviewed native interfaces are not required;
- binary parsing and analysis are bounded by the selected image and function
  range; truncated or malformed ELF/PE input must return a typed error, never
  panic or execute bytes from the target file;
- the native worker and SLEIGH console are spawned as child processes without
  a shell (`Command` with argv only); user-supplied paths and addresses are
  passed as arguments, never interpolated into a shell command line;
- matching runs execute explicitly configured local compiler recipes and objdiff.
  Recipes and toolchains must be trusted: process-group deadlines and cancellation
  do not isolate filesystem, network or memory access. Untrusted compilation
  requires external sandboxing;
- the Java bridge (a development-only oracle path, never a supported runtime
  surface for the JVM-free workflow) loads Ghidra's own jars from the pinned
  install and is not exposed to untrusted input directly.

The repository's runtime dependency and release checks are part of the
release gate. They do not replace review of the host, binary inputs, proxy, or
local file permissions.
