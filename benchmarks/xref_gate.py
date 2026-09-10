#!/usr/bin/env python3
"""m2-002: reference-triple precision/recall against the pinned bridge oracle."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from gen_oracle import bridge_command, digest, generate_reference, provenance, validate_reference, write_reference
from gen_corpus import get_load_segments

SOURCE = "native-analysis:constant-propagation"
POLICY = "code-data-references-v1"
# Fixed corpus contexts, independently checked against the native import.
# PowerPC's ELF opinion admits several variants; automatic selection is not
# a reproducible choice of analysis semantics.
CONTEXTS = {
    "x86_64": {"language": "x86:LE:64:default", "compiler": "gcc"},
    "i386": {"language": "x86:LE:32:default", "compiler": "gcc"},
    "aarch64": {"language": "AARCH64:LE:64:v8A", "compiler": "default"},
    "powerpc": {"language": "PowerPC:BE:32:default", "compiler": "default"},
}


def address(value):
    """Preserve address-space identity; do not discard stack or external refs."""
    if isinstance(value, str) and value.startswith("{"):
        value = json.loads(value)
    if isinstance(value, dict):
        space = value["space"]
        space = space["Other"] if isinstance(space, dict) else space
        offset = int(value["offset"])
    else:
        stack = re.fullmatch(r"Stack\[(-?0x[0-9a-fA-F]+)\]", value)
        if stack:
            return "stack", int(stack[1], 16)
        space, separator, offset = value.rpartition(":")
        if not separator:
            space, offset = "ram", value
        offset = int(offset.removeprefix("0x"), 16)
    space = space.lower()
    if space == "ext":
        space = "external"
    if space == "stack" and offset >= 1 << 63:
        offset -= 1 << 64
    return space, offset


def kinds(name):
    """Normalize to the five II.3 kinds without filtering reference rows."""
    name = name.upper()
    if name in ("CALL", "UNCONDITIONAL_CALL", "CONDITIONAL_CALL", "COMPUTED_CALL",
                "CONDITIONAL_COMPUTED_CALL", "CALL_TERMINATOR", "COMPUTED_CALL_TERMINATOR",
                "CONDITIONAL_CALL_TERMINATOR", "CALL_OVERRIDE_UNCONDITIONAL", "CALLOTHER_OVERRIDE_CALL"):
        return ("call",)
    if name in ("JUMP", "UNCONDITIONAL_JUMP", "CONDITIONAL_JUMP", "COMPUTED_JUMP",
                "CONDITIONAL_COMPUTED_JUMP", "JUMP_TERMINATOR", "JUMP_OVERRIDE_UNCONDITIONAL",
                "CALLOTHER_OVERRIDE_JUMP", "FALL_THROUGH"):
        return ("jump",)
    if name in ("READ_WRITE", "READ_WRITE_IND"):
        return ("read", "write")
    if name in ("READ", "READ_IND"):
        return ("read",)
    if name in ("WRITE", "WRITE_IND"):
        return ("write",)
    if name in ("DATA", "DATA_IND", "PARAM", "INDIRECTION", "THUNK", "EXTERNAL"):
        return ("data",)
    raise ValueError(f"Unclassified reference kind: {name}")


def triples(rows):
    return {(address(row["from"]), address(row["to"]), kind)
            for row in rows for kind in kinds(row["kind"])}


def data_references(reference, binary):
    """Approved task scope; bounds come from the input ELF, not native output."""
    segments = [segment for segment in get_load_segments(binary.read_bytes()) if segment[1]]
    if not segments:
        raise ValueError("Corpus ELF has no mapped memory")
    base = int(reference["image_base"], 16) - min(segment[0] for segment in segments)
    ranges = [(start + base, start + base + size) for start, size, _, _, _ in segments]
    result = set()
    for row in reference["xrefs"]:
        if not isinstance(row.get("instruction"), bool):
            raise ValueError("Oracle lacks instruction-origin evidence")
        target = address(row["to"])
        if row["instruction"] and target[0] == "ram" and any(start <= target[1] < end for start, end in ranges):
            result.update((address(row["from"]), target, kind) for kind in kinds(row["kind"])
                          if kind in ("read", "write", "data"))
    if not result:
        raise ValueError("Oracle has no task-scope data references")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--oracle-dir", type=Path, default=ROOT / "oracle/xrefs-v1")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path, default=Path(os.environ.get(
        "VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    parser.add_argument("--java", default="java")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True)
    lock = json.loads((ROOT / "tests/corpus.lock.json").read_text())
    matrix = set(lock["oracle_matrix"]["architectures"])
    required = [row for row in lock["entries"]
                if row["format"] == "elf" and row["architecture"] in matrix]
    actual, setup_error, command = {}, None, None
    try:
        manifest = json.loads((args.corpus_dir / "manifest.json").read_text())
        if manifest["sources"] != lock["sources"]:
            raise ValueError("Corpus source manifest mismatch")
        for name, info in lock["sources"].items():
            if digest(ROOT / "tests/corpus-src" / name) != info["sha256"]:
                raise ValueError(f"Corpus source changed: {name}")
        for item in manifest["entries"]:
            key = (item["architecture"], item["variant"])
            if key in actual:
                raise ValueError("Duplicate corpus row")
            actual[key] = item
        producer = provenance(args.ghidra)
        command = bridge_command(args.ghidra, args.java)
        args.oracle_dir.mkdir(parents=True, exist_ok=True)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        setup_error = str(error)
    rows = []
    with tempfile.TemporaryDirectory(prefix="xref-gate-") as temporary:
        for recipe in required:
            key = (recipe["architecture"], recipe["variant"])
            row = {"id": "_".join(key), "status": "skipped", "metrics": {},
                   "thresholds": {"data_xref.precision": 0.98, "data_xref.recall": 0.95}, "runs": 1}
            try:
                if setup_error:
                    raise ValueError(setup_error)
                item = actual.get(key)
                if not item or item.get("status") != "ok":
                    raise FileNotFoundError("Required corpus input missing or skipped")
                if item["command"] != recipe["command"] or item["binary"] != recipe["binary"]:
                    raise ValueError("Corpus recipe mismatch")
                binary = (args.corpus_dir / recipe["binary"]).resolve()
                sha = digest(binary)
                if sha != item["binary_sha256"]:
                    raise ValueError("Corpus binary hash mismatch")
                row["sha256"] = sha
                expected = {"schema_version": 1, "sha256": sha, "binary_size": binary.stat().st_size,
                            **producer, "address_basis": "ghidra",
                            "language_selection": "explicit", **CONTEXTS[key[0]]}
                row["analysis_context"] = CONTEXTS[key[0]]
                reference_path = (args.oracle_dir / "explicit-context-v1" /
                                  expected["language"].replace(":", "-") /
                                  expected["compiler"] / f"{sha}.json")
                reference_path.parent.mkdir(parents=True, exist_ok=True)
                reference = json.loads(reference_path.read_text()) if reference_path.exists() else {}
                if (any(reference.get(k) != v for k, v in expected.items()) or "xrefs" not in reference or
                        any("instruction" not in ref or "provenance" not in ref
                            for ref in reference.get("xrefs", []))):
                    reference = generate_reference(command, binary, expected, args.timeout,
                                                   include_xrefs=True)
                    write_reference(reference_path, reference)
                validate_reference(reference, expected)
                row["oracle_context"] = {key: reference[key] for key in ("language", "compiler")}
                oracle = triples(reference["xrefs"])
                if not oracle:
                    raise ValueError("Oracle exported no references")
                data_oracle = data_references(reference, binary)
                row["oracle_sha256"] = digest(reference_path)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                row["reason"] = str(error)
                rows.append(row)
                print(f"SKIPPED {row['id']}: {error}", flush=True)
                continue
            try:
                project = Path(temporary) / row["id"]
                result = subprocess.run([str(ROOT / "target/release/lre-cli"), "import", str(binary),
                    "--name", row["id"], "--project", str(project)],
                    capture_output=True, text=True, timeout=args.timeout)
                if result.returncode:
                    raise ValueError(result.stdout + result.stderr)
                with sqlite3.connect(project / "project.sqlite") as connection:
                    language = connection.execute(
                        "SELECT language FROM programs WHERE name=?", (row["id"],)).fetchone()
                    row["native_language"] = language[0] if language else None
                    if row["native_language"] != row["analysis_context"]["language"]:
                        raise ValueError("Native/oracle analysis language mismatch")
                    native_rows = [{"from": src, "to": dst, "kind": kind, "source": source,
                                    "ownership": ownership, "confidence": confidence}
                                   for src, dst, kind, source, ownership, confidence in
                                   connection.execute(
                                       "SELECT src,dst,kind,provenance,provenance_kind,confidence FROM xrefs")]
                native = triples(native_rows)
                # Score every output of this pass: do not hide false positives
                # by intersecting native targets or PCs with oracle bounds.
                data_native = triples(ref for ref in native_rows if ref["source"] == SOURCE)
                if any(ref["source"] == SOURCE and ref["ownership"] != "inferred"
                       for ref in native_rows):
                    raise ValueError("Native data-reference pass produced a non-inferred fact")
                full_matched = len(native & oracle)
                matched = len(data_native & data_oracle)
                row.update(oracle_references=len(oracle), native_references=len(native),
                           oracle_data_references=len(data_oracle), native_data_references=len(data_native),
                           matched=matched, missing=sorted(data_oracle - data_native),
                           extra=sorted(data_native - data_oracle))
                row["metrics"] = {"xref.precision": full_matched / len(native) if native else 0.0,
                                  "xref.recall": full_matched / len(oracle),
                                  "data_xref.precision": matched / len(data_native) if data_native else 0.0,
                                  "data_xref.recall": matched / len(data_oracle)}
                row["status"] = "pass" if all(row["metrics"][k] >= v for k, v in row["thresholds"].items()) else "fail"
            except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError) as error:
                row.update(status="fail", reason=str(error))
            rows.append(row)
            print(f"{row['status'].upper()} {row['id']}: {row.get('reason', row['metrics'])}", flush=True)
    summary = {status: sum(row["status"] == status for row in rows) for status in ("pass", "fail", "skipped")}
    report = {"gate": "data-xref", "milestone": "M2", "task": "m2-002", "scoring_policy": POLICY,
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "date": datetime.now(timezone.utc).date().isoformat(),
              "machine": {"os": platform.platform(), "cpu": platform.processor(), "ram_gb": 0},
              "corpus": rows, "summary": summary,
              "passed": len(rows) == 20 and summary["pass"] == 20}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    write_reference(args.report, report)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
