#!/usr/bin/env python3
"""m3-001: function recovery scored against DWARF truth, not against Ghidra.

Every `fn.*` number so far measures parity with Ghidra's own analysis. That
says the two tools agree; it does not say either is right. M3 scores against
the compiler's own debug information on the locked corpus, and records what
stock Ghidra scores on the same truth so later milestones have a baseline
rather than an anecdote.

Assertions
  1. `benchmarks/dwarf_gate.py` scores every locked corpus entry -- a
     skipped row is a skipped row, never a pass.
  2. Truth is the compiler's: concrete `DW_TAG_subprogram` entries inside
     executable segments, biased to the store's own image base for ET_DYN.
     Every row carries a non-empty truth set and its provenance digests.
  3. `dwarf.fn.recall >= 0.98` per row and in aggregate, for the native
     importer and for the pinned stock-Ghidra oracle.
  4. `dwarf.fn.unattributed == 0`: a recovered entry that DWARF does not
     describe must still be explained -- a symbol in the unstripped twin, a
     store thunk row, a linker stub inside a `.plt*` section, or a function
     stock Ghidra also created. Anything else is an invented function.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

# Expected failures, each tied to a diagnosed mechanism -- visible here so
# the gate stays green only for everything else. An exemption that stops
# firing fails loudly so it gets removed instead of going stale.
# - mipsel `add`: an 8-byte unreferenced leaf DWARF describes but neither
#   tool seeds (no callers, no unwind entry, too short for patterns; O0
#   recovers it only because main still calls it). Parity holds.
# - mipsel_plain_pie stock: Ghidra recovers nearby-but-different entries
#   on the PIE layout (13 functions, neither DWARF address among them).
# - mipsel_cpp_o2 unattributed: the 0x20980 false entry (same address as
#   the m12/m19-004 exemptions); the row must list exactly that address.
# - mipsel_many_o2 native recall (RETIRED 2026-09-11): the 7/401 collapse
#   was the unseeded-`main` rule; const-prop DATA-to-code seeding now
#   recovers 401/401 and the stale guard fired on schedule.
# - pe32 plain/pie recall, both producers: SJLJ 32-bit CRT leaves
#   (startup, TLS/thread helpers, libmingwex internals) neither tool
#   seeds -- no unwind tables exist to seed from and nothing references
#   them. Parity holds throughout (stock 0.76-0.82 vs native 0.80-0.84,
#   native-missed - stock-missed is empty after stub promotion).
# - pe32_many_o2 recall, both producers: same leaf class at 0.9750 vs
#   stock 0.9636.
EXPECTED_RECALL_EXEMPT = {
    "mipsel_plain_o2": {"native", "ghidra"},
    "mipsel_plain_pie": {"native", "ghidra"},
    "pe32_plain_o0": {"native", "ghidra"},
    "pe32_plain_o2": {"native", "ghidra"},
    "pe32_plain_pie": {"native", "ghidra"},
    "pe32_many_o2": {"native", "ghidra"},
}
EXPECTED_UNATTRIBUTED = {"mipsel_cpp_o2": ["00020980"]}

ROOT = Path(__file__).resolve().parents[1]
RECALL_THRESHOLD = 0.98


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report_path = arguments.report or Path(
        subprocess.check_output(["mktemp", "-t", "m3-001-XXXXXX.json"], text=True).strip())
    result = subprocess.run(
        [sys.executable, str(ROOT / "benchmarks/dwarf_gate.py"),
         "--corpus-dir", str(arguments.corpus_dir), "--report", str(report_path)],
        cwd=ROOT, capture_output=True, text=True)
    print(result.stdout.strip())
    # The scorer's exit code is its own un-exempted verdict; the tied
    # exemptions below are the gate's verdict. A scorer crash surfaces
    # as a missing or incomplete report, which the coverage check catches.

    report = json.loads(report_path.read_text())
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    expected = {f"{row['architecture']}_{row['variant']}"
                for row in manifest["entries"] if row.get("status") == "ok"}
    scored = {row["id"] for row in report["rows"]}
    skipped_ids = {row["id"] for row in report["rows"] if row["status"] == "skipped"}
    if scored - expected - skipped_ids or expected - scored:
        raise AssertionError(f"unscored corpus entries: {sorted(expected - scored)}, "
                             f"unexpected rows: {sorted(scored - expected - skipped_ids)}")

    failures = []
    for row in report["rows"]:
        if row["status"] == "skipped":
            # Only msvc off-Windows may skip (mirrors the m1-006 verifier
            # rule); anything else skipped is a coverage hole, not a pass.
            if sys.platform == "win32" or not row["id"].startswith("msvc_"):
                failures.append(
                    f"{row['id']}: unexpected skip ({row.get('reason', 'no reason')})")
            continue
        # The scorer's status is informational: rows tripping only tied
        # exemptions are expected-fails, not gate failures. A row that
        # crashed out of scoring carries no metrics and can never be one.
        if not row.get("metrics") or "truth" not in row:
            failures.append(f"{row['id']}: unscored ({row.get('reason', 'see metrics')})")
            continue
        exempt_producers = EXPECTED_RECALL_EXEMPT.get(row["id"], set())
        for producer in ("native", "ghidra"):
            recall = row["metrics"][f"{producer}.dwarf.fn.recall"]
            if recall < RECALL_THRESHOLD:
                if producer not in exempt_producers:
                    failures.append(
                        f"{row['id']}: {producer} dwarf.fn.recall {recall:.4f} < {RECALL_THRESHOLD}")
            elif producer in exempt_producers:
                failures.append(f"{row['id']}: {producer} recall exemption stale (now {recall:.4f})")
        expected_unattr = EXPECTED_UNATTRIBUTED.get(row["id"])
        unattributed = row["metrics"]["native.dwarf.fn.unattributed"]
        if expected_unattr is not None:
            if sorted(row.get("unattributed", [])) != sorted(expected_unattr):
                failures.append(
                    f"{row['id']}: unattributed exemption stale "
                    f"(now {row.get('unattributed', [])})")
        elif unattributed != 0:
            failures.append(
                f"{row['id']}: {unattributed} recovered entries are neither DWARF, "
                f"symbol, thunk, stub nor Ghidra: {row.get('unattributed')}")
    if failures:
        raise AssertionError("; ".join(failures))

    for row in report["rows"]:
        if row["status"] == "skipped":
            continue
        if not row["truth"]["functions"]:
            raise AssertionError(f"{row['id']}: empty DWARF truth set")
        for digest in ("binary_sha256", "twin_sha256", "oracle_sha256"):
            if len(row["provenance"].get(digest, "")) != 64:
                raise AssertionError(f"{row['id']}: missing {digest} provenance")

    # Aggregates exclude exempted rows' contributions, computed exactly
    # from each row's missing-address lists (never from rounded recall).
    # A row exempt for either producer leaves both aggregates, so the two
    # headline recalls are scored on the same set and stay comparable.
    # The excluded rows are named in the PASS line, not hidden in a total.
    recall_excluded = {row["id"] for row in report["rows"]
                       if EXPECTED_RECALL_EXEMPT.get(row["id"])}
    adj_truth = report["totals"]["truth_functions"]
    adj_matched = {producer: report["totals"][f"{producer}_matched"]
                   for producer in ("native", "ghidra")}
    adj_unattributed = report["totals"]["native.dwarf.fn.unattributed"]
    for row in report["rows"]:
        if row["status"] == "skipped" or not row.get("metrics") or "truth" not in row:
            continue
        missing = row.get("missing", {})
        if row["id"] in recall_excluded:
            truth = row["truth"]["functions"]
            adj_truth -= truth
            for producer in ("native", "ghidra"):
                adj_matched[producer] -= truth - len(missing.get(producer, []))
        if row["id"] in EXPECTED_UNATTRIBUTED:
            adj_unattributed -= len(EXPECTED_UNATTRIBUTED[row["id"]])
    recalls = {}
    for producer in ("native", "ghidra"):
        recalls[producer] = adj_matched[producer] / adj_truth
        if recalls[producer] < RECALL_THRESHOLD:
            raise AssertionError(
                f"aggregate {producer} dwarf.fn.recall {recalls[producer]:.4f} "
                f"< {RECALL_THRESHOLD}")
    if adj_unattributed != 0:
        raise AssertionError(
            f"aggregate {adj_unattributed} unattributed outside exemptions")

    exempt = sum(len(v) for v in EXPECTED_RECALL_EXEMPT.values()) + len(EXPECTED_UNATTRIBUTED)
    print(f"m3-001: PASS ({adj_truth} DWARF functions over "
          f"{len(report['rows'])} corpus entries; recall-exempt rows excluded "
          f"from both aggregates: {sorted(recall_excluded)}; "
          f"native recall {recalls['native']:.4f}, "
          f"stock Ghidra {recalls['ghidra']:.4f})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
