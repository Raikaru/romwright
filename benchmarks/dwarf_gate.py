#!/usr/bin/env python3
"""m3-001: score function recovery against DWARF truth on the locked corpus.

Truth here is the compiler's own debug information, not Ghidra's analysis:
concrete `DW_TAG_subprogram` entries from the unstripped twin, restricted to
executable segments, and biased to the store's image base for ET_DYN images
(DWARF records link-time addresses; the loader picks the base).

Two producers are scored against that truth: the native importer reading the
stripped binary, and the pinned stock-Ghidra oracle for the same image. The
Ghidra column is the M3 baseline -- later milestones claim improvement
against a recorded number, never against a memory of one.

DWARF describes what the compiler compiled, so it is silent about CRT stubs,
PLT slots and linker-generated code that both tools legitimately recover.
Recall is therefore the metric; the entries DWARF does not describe are
*attributed* instead: a symbol in the unstripped twin, a thunk the store
proved, a linker stub inside a `.plt*` section, or a function stock Ghidra
also created. An entry with none of those is an invented function and fails
the gate.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
sys.path.insert(0, str(ROOT / "scripts"))
from dwarf_arity import extract
from gen_oracle import digest, provenance, validate_reference

RECALL_THRESHOLD = 0.98
SECTION = re.compile(
    r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)")
SYMBOL_INDEX = re.compile(r"^\d+:$")


def readelf(*arguments: str) -> str:
    environment = dict(os.environ, LC_ALL="C", DEBUGINFOD_URLS="")
    return subprocess.run(["readelf", *arguments], text=True, capture_output=True,
                          check=True, timeout=120, env=environment).stdout


MINGW_NM = {"pe64": "x86_64-w64-mingw32-nm", "pe32": "i686-w64-mingw32-nm"}


def is_pe(binary: Path) -> bool:
    with open(binary, "rb") as handle:
        return handle.read(2) == b"MZ"


def symbol_addresses(binary: Path, architecture: str = "") -> set[int]:
    """Every defined symbol address in the unstripped twin, any symbol type."""
    if is_pe(binary):
        tool = MINGW_NM[architecture]
        result = subprocess.run([tool, str(binary)], capture_output=True,
                                text=True, timeout=120)
        if result.returncode:
            raise ValueError(f"{tool} failed on {binary.name}")
        addresses = set()
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[1] != "U":
                try:
                    addresses.add(int(parts[0], 16))
                except ValueError:
                    continue
        return addresses
    addresses = set()
    for line in readelf("-sW", str(binary)).splitlines():
        parts = line.split()
        if len(parts) >= 8 and SYMBOL_INDEX.match(parts[0]):
            try:
                addresses.add(int(parts[1], 16))
            except ValueError:
                continue
    return addresses


def stub_ranges(binary: Path) -> list[tuple[int, int]]:
    """Linker stub sections: PLT slots are code neither tool invents."""
    if is_pe(binary):
        return []
    ranges = []
    for line in readelf("-SW", str(binary)).splitlines():
        match = SECTION.match(line)
        if match and match[1].startswith(".plt"):
            address, size = int(match[2], 16), int(match[3], 16)
            if address and size:
                ranges.append((address, size))
    return ranges


def is_shared_object(binary: Path, big_endian: bool) -> bool:
    """ET_DYN images are mapped at the loader's base, not at link time."""
    if is_pe(binary):
        # Our PE loader keeps link VAs, DLLs included (m19-001 scores its
        # DLL rows with no base adjustment).
        return False
    header = binary.read_bytes()[16:18]
    return int.from_bytes(header, "big" if big_endian else "little") == 3


def native_import(binary: Path, work: Path) -> tuple[set[int], set[int], int]:
    """Import the stripped binary; return entries, thunk entries, image base."""
    project = work / binary.stem
    project.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "import", str(binary),
         "--name", "scored", "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError(f"native import failed: {result.stderr.strip()}")
    store = sqlite3.connect(project / "project.sqlite")
    entries = {int(row[0], 16) for row in store.execute("SELECT entry FROM functions")}
    thunks = {int(row[0], 16) for row in store.execute("SELECT function FROM thunks")}
    base = min(int(row[0], 16) for row in store.execute("SELECT start FROM memory_regions"))
    return entries, thunks, base


def score(truth: set[int], observed: set[int]) -> dict:
    matched = truth & observed
    return {"truth": len(truth), "observed": len(observed), "matched": len(matched),
            "recall": len(matched) / len(truth) if truth else 0.0,
            "missing": sorted(f"{address:08x}" for address in truth - observed)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--oracle-dir", type=Path, default=ROOT / "oracle")
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    # The oracle column is only a baseline if it came from the pinned bridge.
    producer = provenance(Path(os.environ.get(
        "VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    lock = json.loads((ROOT / "tests/corpus.lock.json").read_text())
    if manifest["sources"] != lock["sources"]:
        raise ValueError("corpus source manifest does not match the lock")

    report = {"id": "m3-001", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"dwarf.fn.recall": RECALL_THRESHOLD,
                             "dwarf.fn.unattributed": 0},
              # Pins so a consumer can tell fresh evidence from stale.
              "sources": {"dwarf_gate_sha256": digest(Path(__file__)),
                          "dwarf_reader_sha256": digest(ROOT / "benchmarks/dwarf_arity.py")},
              "rows": [], "totals": {}}
    totals = {"truth_functions": 0, "native_matched": 0, "ghidra_matched": 0,
              "native_observed": 0, "native.dwarf.fn.unattributed": 0,
              "undescribed": 0}

    with tempfile.TemporaryDirectory(prefix="m3-001-") as temporary:
        work = Path(temporary)
        for entry in manifest["entries"]:
            identifier = f"{entry['architecture']}_{entry['variant']}"
            row = {"id": identifier, "status": "skipped", "metrics": {}, "runs": 1}
            if entry.get("status") != "ok":
                row["reason"] = f"corpus entry status {entry.get('status')!r}"
                report["rows"].append(row)
                continue
            binary = arguments.corpus_dir / entry["binary"]
            twin = arguments.corpus_dir / entry["unstripped_twin"]
            reference_path = arguments.oracle_dir / f"{entry['binary_sha256']}.json"
            try:
                if digest(binary) != entry["binary_sha256"]:
                    raise ValueError("corpus binary digest mismatch")
                if digest(twin) != entry["unstripped_twin_sha256"]:
                    raise ValueError("unstripped twin digest mismatch")
                reference = json.loads(reference_path.read_text())
                validate_reference(reference, {
                    "schema_version": 1, "sha256": entry["binary_sha256"],
                    "binary_size": binary.stat().st_size,
                    "address_basis": "ghidra", **producer})

                observed, thunks, base = native_import(binary, work)
                big_endian = entry["endian"] == "big"
                bias = base if is_shared_object(binary, big_endian) else 0
                truth_export = extract(twin, bias)
                truth = {int(address, 16) for address in truth_export["functions"]}
                ghidra = {int(address, 16) for address in reference["entries"]}
                symbols = {address + bias for address in symbol_addresses(twin, entry["architecture"])}
                stubs = [(start + bias, size) for start, size in stub_ranges(twin)]

                undescribed = observed - truth
                unattributed = sorted(
                    f"{address:08x}" for address in undescribed
                    if address not in symbols and address not in thunks
                    and address not in ghidra
                    and not any(start <= address < start + size for start, size in stubs))

                native = score(truth, observed)
                baseline = score(truth, ghidra)
                row.update(
                    truth={"functions": native["truth"], "load_bias": f"{bias:08x}",
                           "unmapped": len(truth_export["unmapped"])},
                    provenance={"binary_sha256": entry["binary_sha256"],
                                "twin_sha256": entry["unstripped_twin_sha256"],
                                "oracle_sha256": digest(reference_path),
                                "bridge_sources_sha256": reference["bridge_sources_sha256"]},
                    metrics={"native.dwarf.fn.recall": native["recall"],
                             "ghidra.dwarf.fn.recall": baseline["recall"],
                             "native.dwarf.fn.unattributed": len(unattributed),
                             "native.functions": native["observed"],
                             "ghidra.functions": baseline["observed"],
                             "native.undescribed": len(undescribed)},
                )
                # Evidence only where there is any: an empty list is noise.
                if native["missing"] or baseline["missing"]:
                    row["missing"] = {"native": native["missing"],
                                      "ghidra": baseline["missing"]}
                if unattributed:
                    row["unattributed"] = unattributed
                row["status"] = "pass" if (
                    native["recall"] >= RECALL_THRESHOLD
                    and baseline["recall"] >= RECALL_THRESHOLD
                    and not unattributed) else "fail"
                totals["truth_functions"] += native["truth"]
                totals["native_matched"] += native["matched"]
                totals["ghidra_matched"] += baseline["matched"]
                totals["native_observed"] += native["observed"]
                totals["native.dwarf.fn.unattributed"] += len(unattributed)
                totals["undescribed"] += len(undescribed)
            except (ValueError, subprocess.CalledProcessError, OSError, KeyError) as failure:
                row["status"] = "fail"
                row["reason"] = str(failure)
            report["rows"].append(row)
            print(f"{row['status'].upper()} {identifier}: "
                  f"{row.get('metrics', {}).get('native.dwarf.fn.recall', 'n/a')} native, "
                  f"{row.get('metrics', {}).get('ghidra.dwarf.fn.recall', 'n/a')} ghidra, "
                  f"{row.get('metrics', {}).get('native.dwarf.fn.unattributed', 'n/a')} unattributed"
                  f"{'' if row['status'] != 'fail' else ' -- ' + row.get('reason', '')}",
                  flush=True)

    truth_functions = totals["truth_functions"]
    report["totals"] = dict(
        totals,
        **{"native.dwarf.fn.recall": totals["native_matched"] / truth_functions if truth_functions else 0.0,
           "ghidra.dwarf.fn.recall": totals["ghidra_matched"] / truth_functions if truth_functions else 0.0})
    report["summary"] = {
        "pass": sum(1 for row in report["rows"] if row["status"] == "pass"),
        "fail": sum(1 for row in report["rows"] if row["status"] == "fail"),
        "skipped": sum(1 for row in report["rows"] if row["status"] == "skipped"),
    }
    report["passed"] = (report["summary"]["fail"] == 0
                        and report["summary"]["pass"] == len(report["rows"])
                        and truth_functions > 0)
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"summary": report["summary"], "totals": report["totals"],
                      "passed": report["passed"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
