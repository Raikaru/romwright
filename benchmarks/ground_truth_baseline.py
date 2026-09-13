#!/usr/bin/env python3
"""m3-002: freeze what stock Ghidra scores against DWARF truth.

M4 exists to improve on stock Ghidra. That claim needs a number that cannot
move under it, so this records one: for every locked ELF corpus entry, what
stock Ghidra 12.1.3 recovers of the compiler's own debug information --
function entries and prototype arity -- with the digests to reproduce it.

The baseline is an immutable artifact. Without `--write` this script
recomputes it and compares byte for byte, so a changed number fails loudly
instead of being re-baselined. Inputs are the pinned install, the locked
corpus, the SHA-keyed function-entry oracles and the immutable arity
references; nothing here reads the native importer, and nothing native reads
this file.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
sys.path.insert(0, str(ROOT / "scripts"))
from dwarf_arity import extract
from gen_corpus import get_load_segments
from gen_oracle import digest, provenance, validate_reference
from prototype_gate import score_arity


def readelf_version() -> str:
    """DWARF truth is projected through readelf; record which one."""
    environment = dict(os.environ, LC_ALL="C")
    output = subprocess.run(["readelf", "--version"], text=True, capture_output=True,
                            check=True, env=environment).stdout
    return output.splitlines()[0].strip()


def stock_references(corpus: Path, prototypes: Path, ghidra: Path, timeout: int) -> dict:
    """Validate the immutable stock arity references and index them by id."""
    environment = dict(os.environ)
    for name in ("ROMWRIGHT_SLA", "ROMWRIGHT_LANGUAGE", "ROMWRIGHT_LANGUAGE_DIR", "ROMWRIGHT_SPECS"):
        environment.pop(name, None)
    with tempfile.TemporaryDirectory(prefix="m3-002-references-") as temporary:
        checked = Path(temporary) / "reference.json"
        # `--check` validates the lock, the corpus digests and every immutable
        # reference context. It never regenerates stock analysis.
        subprocess.run(
            [sys.executable, str(ROOT / "scripts/gen_prototype_oracle.py"), "--check",
             "--corpus-dir", str(corpus), "--oracle-dir", str(prototypes),
             "--ghidra", str(ghidra), "--report", str(checked)],
            cwd=ROOT, env=environment, check=False, timeout=timeout)
        report = json.loads(checked.read_text())
    return {row["id"]: row for row in report["corpus"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--oracle-dir", type=Path, default=ROOT / "oracle")
    parser.add_argument("--prototype-dir", type=Path, default=ROOT / "oracle/prototypes-v1")
    parser.add_argument("--ghidra", type=Path, default=Path(os.environ.get(
        "ROMWRIGHT_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    parser.add_argument("--baseline", type=Path,
                        default=ROOT / "benchmarks/reports/baseline-ghidra-truth.json")
    parser.add_argument("--write", action="store_true",
                        help="record the baseline instead of verifying it")
    parser.add_argument("--timeout", type=int, default=600)
    arguments = parser.parse_args()

    producer = provenance(arguments.ghidra)
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    lock = json.loads((ROOT / "tests/corpus.lock.json").read_text())
    if manifest["sources"] != lock["sources"]:
        raise ValueError("corpus source manifest does not match the lock")
    references = stock_references(arguments.corpus_dir, arguments.prototype_dir,
                                  arguments.ghidra, arguments.timeout)

    rows = []
    totals = {"dwarf.functions": 0, "dwarf.arity_matched": 0,
              "ghidra.entries_matched": 0, "ghidra.arity_correct": 0,
              "ghidra.functions": 0}
    for entry in manifest["entries"]:
        identifier = f"{entry['architecture']}_{entry['variant']}"
        row = {"id": identifier, "status": "skipped"}
        if entry.get("status") != "ok":
            row["reason"] = f"corpus entry status {entry.get('status')!r}"
            rows.append(row)
            continue
        binary = arguments.corpus_dir / entry["binary"]
        twin = arguments.corpus_dir / entry["unstripped_twin"]
        if digest(binary) != entry["binary_sha256"] or digest(twin) != entry["unstripped_twin_sha256"]:
            raise ValueError(f"{identifier}: corpus digest mismatch")

        oracle_path = arguments.oracle_dir / f"{entry['binary_sha256']}.json"
        oracle = json.loads(oracle_path.read_text())
        validate_reference(oracle, {"schema_version": 1, "sha256": entry["binary_sha256"],
                                    "binary_size": binary.stat().st_size,
                                    "address_basis": "ghidra", **producer})

        checked = references.get(identifier)
        if checked is None or checked.get("status") != "pass":
            raise ValueError(f"{identifier}: no validated stock arity reference")
        arity_path = arguments.prototype_dir / checked["reference"]
        if digest(arity_path) != checked["reference_sha256"]:
            raise ValueError(f"{identifier}: arity reference changed after validation")
        arity_reference = json.loads(arity_path.read_text())

        # DWARF records link-time addresses; score in the analysis basis the
        # reference itself declares.
        load_base = min(start for start, size, _, _, _ in
                        get_load_segments(binary.read_bytes()) if size)
        entries_truth = extract(twin, int(oracle["image_base"], 16) - load_base)
        arity_truth = extract(twin, int(arity_reference["image_base"], 16) - load_base)
        truth_entries = {int(address, 16) for address in entries_truth["functions"]}
        ghidra_entries = {int(address, 16) for address in oracle["entries"]}
        arity = score_arity(arity_truth["functions"], arity_reference["arities"])

        matched = truth_entries & ghidra_entries
        row.update(
            status="recorded",
            provenance={"binary_sha256": entry["binary_sha256"],
                        "twin_sha256": entry["unstripped_twin_sha256"],
                        "oracle_sha256": digest(oracle_path),
                        "arity_reference": checked["reference"],
                        "arity_reference_sha256": checked["reference_sha256"],
                        "bridge_sources_sha256": oracle["bridge_sources_sha256"],
                        "language": oracle["language"],
                        "image_base": oracle["image_base"]},
            metrics={"dwarf.functions": len(truth_entries),
                     "dwarf.arity_matched": arity["matched"],
                     "ghidra.functions": len(ghidra_entries),
                     "ghidra.dwarf.fn.recall": len(matched) / len(truth_entries),
                     "ghidra.dwarf.proto.arity": arity["value"],
                     "ghidra.arity_correct": arity["correct"]})
        totals["dwarf.functions"] += len(truth_entries)
        totals["dwarf.arity_matched"] += arity["matched"]
        totals["ghidra.entries_matched"] += len(matched)
        totals["ghidra.arity_correct"] += arity["correct"]
        totals["ghidra.functions"] += len(ghidra_entries)
        rows.append(row)
        print(f"RECORDED {identifier}: entries {row['metrics']['ghidra.dwarf.fn.recall']:.4f}, "
              f"arity {row['metrics']['ghidra.dwarf.proto.arity']:.4f} "
              f"({arity['correct']}/{arity['matched']})", flush=True)

    baseline = {
        "id": "m3-002",
        "schema_version": 1,
        "note": ("Immutable stock-Ghidra ground-truth baseline. Recompute with "
                 "benchmarks/ground_truth_baseline.py; never edit by hand."),
        "producer": producer,
        "truth_toolchain": {"readelf": readelf_version()},
        "corpus_sources": lock["sources"],
        "rows": rows,
        "totals": dict(
            totals,
            **{"ghidra.dwarf.fn.recall": (totals["ghidra.entries_matched"] / totals["dwarf.functions"]
                                          if totals["dwarf.functions"] else 0.0),
               "ghidra.dwarf.proto.arity": (totals["ghidra.arity_correct"] / totals["dwarf.arity_matched"]
                                            if totals["dwarf.arity_matched"] else 0.0)}),
    }
    encoded = json.dumps(baseline, indent=2, sort_keys=True) + "\n"

    if arguments.write:
        arguments.baseline.parent.mkdir(parents=True, exist_ok=True)
        arguments.baseline.write_text(encoded)
        print(json.dumps({"recorded": arguments.baseline.name, "totals": baseline["totals"]}))
        return 0

    if not arguments.baseline.is_file():
        print(f"missing baseline {arguments.baseline}", file=sys.stderr)
        return 1
    committed = arguments.baseline.read_text()
    identical = committed == encoded
    recorded = json.loads(committed)
    # The numbers are the guarantee. Bytes are the stronger convenience, and
    # they can differ for an honest reason -- a different readelf projects the
    # same DWARF through different text -- so report which claim holds.
    moved = [row["id"] for row, other in zip(recorded["rows"], rows)
             if row.get("metrics") != other.get("metrics")
             or row.get("provenance") != other.get("provenance")]
    if moved or recorded["totals"] != baseline["totals"]:
        print(f"baseline mismatch on {moved or 'totals'}", file=sys.stderr)
        return 1
    if len(recorded["rows"]) != len(rows):
        print("baseline row count changed", file=sys.stderr)
        return 1
    print(json.dumps({"verified": arguments.baseline.name,
                      "verified_bytes": identical,
                      "recorded_toolchain": recorded.get("truth_toolchain"),
                      "local_toolchain": baseline["truth_toolchain"],
                      "recorded_at": datetime.now(timezone.utc).isoformat(),
                      "totals": baseline["totals"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
