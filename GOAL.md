# GOAL

The Stage-4 JVM-free workflow is the verified baseline, not the full completion
claim. The ratified milestone roadmap requires program-model accuracy equal to
or better than stock Ghidra against ground truth (C1), improvements over stock
Ghidra measured against ground truth (C2), and measured game-first sessions on
the approved targets (C3).

C1 covers every gated program-model fact (discovery, references, prototypes,
switch tables, strings, library identification, C++ facts): accuracy against
ground truth (symbols, DWARF, linker maps, objdiff) is equal to or better than
stock Ghidra's. Where a fact has no ground truth, stock Ghidra stays the
reference and the parity gate applies. Stock Ghidra is otherwise a baseline
to beat, reported as the margin by which we lead it, not a target to match.

## Stages

| Stage | Exit condition | Status |
|---|---|---|
| 1 | Rust core + SQLite store + Java JSON-RPC bridge, e2e verified | **done** |
| 1.5 | Baseline benchmarks + native-worker feasibility spike + ADR-0001 | **done** (39.5 MB spike vs 375 MiB stock; see benchmarks/reports/) |
| 2 | Store owns all facts; bridge on-demand only; reopen Java-free | **done** (schema v2: comments/datatypes; reopen verified no-JVM) |
| 3 | Native SLEIGH/disasm + decompiler worker replaces bridge (x86-64); differential tests pass | **done** (raw-SLEIGH worker wired into CLI `decompile`; differential passes) |
| 4 | JVM-free supported workflow, ELF+PE native import, memory/perf gates, support matrix | **done — gated** (benchmarks/gate.sh: 39.9 MB peak vs 375 MiB stock, 0.32 s median wall (3 runs); support matrix in README/STATUS) |

## Hard rules

- Every Ghidra API call verified against `.ghidra-java/` sources or the
  install jars — never from memory (see CONTRIBUTING.md).
- `third_party/ghidra/` stays pinned and hash-manifested; never edited in place.
- Subagents read-only research only; the primary agent owns all edits.
- No capability claimed without a test proving it.

## Remaining work

- M1 discovery is verified on the current tree: all 20 ELF rows have
  precision/recall 1.0. The held DOL has recall 0.993789 and precision
  0.956652; its acceptance gate constrains recall, not precision.
- M2 program model at or above stock Ghidra: constant propagation, data
  references and strings, inferred prototypes, switch recovery, library
  identification and C++ facts. The ground-truth gates (and the parity gate
  for facts without ground truth), not discovery alone, establish C1.
- M3 ground-truth gates pass: fresh DWARF scoring, the reproduced stock
  baseline and fresh regression scoring. The frozen comparison covers 20 ELF
  rows; the broader DWARF gate retains its explicit exemptions.
- M4's register-parameter improvement and aggregate gates pass with the
  approved opt-in policy. Default-enabling passes remains reserved.
- M5 end-to-end game sessions on the human-approved targets.
- M6 user/analyzer documentation, release infrastructure and contributor
  sustainability. Releases and outside contribution merges remain reserved.
- M12 version diffing: match the functions of one program onto another and
  carry names across, so a decompilation with symbols can name a retail
  image. Scored against symbol truth the matcher never reads; an anchor's
  precision is 1.0 by construction and gated as such.

`STATUS.md` records the current milestone, exact next task and measured evidence.

P1–P4 in `docs/game-decomp-plan.md` are separate from the migration stages.
They are not closed by the architecture work or by passing M1/M3/M4 gates:
the acceptance audit found implementation gaps and unproved superiority
criteria. See the latest acceptance audit in `STATUS.md`.
