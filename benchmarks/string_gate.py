#!/usr/bin/env python3
"""m2-003: frozen string-address recall against defined Ghidra strings."""
import argparse
import codecs
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from gen_oracle import bridge_command, digest, generate_reference, provenance, validate_reference, write_reference
from ui_gate import physical_memory_gb
from xref_gate import CONTEXTS, address


def string_set(rows):
    result = set()
    for row in rows:
        value = row["value"]
        if not isinstance(value, str):
            raise ValueError("Oracle string could not be decoded")
        if len(value) >= 4:
            result.add((address(row["address"]), codecs.lookup(row["kind"]).name))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--oracle-dir", type=Path, default=ROOT / "oracle/strings-v1")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path, default=Path(os.environ.get(
        "ROMWRIGHT_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    parser.add_argument("--java", default="java")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"], cwd=ROOT, check=True)
    lock = json.loads((ROOT / "tests/corpus.lock.json").read_text())
    matrix = set(lock["oracle_matrix"]["architectures"])
    required = [row for row in lock["entries"]
                if row["format"] == "elf" and row["architecture"] in matrix]
    actual, setup_error = {}, None
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
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        setup_error = str(error)
    rows = []
    with tempfile.TemporaryDirectory(prefix="string-gate-") as temporary:
        for recipe in required:
            key = (recipe["architecture"], recipe["variant"])
            row = {"id": "_".join(key), "status": "skipped", "metrics": {},
                   "thresholds": {"str.recall": 0.95}, "runs": 1}
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
                            **producer, "address_basis": "ghidra", "language_selection": "explicit",
                            **CONTEXTS[key[0]]}
                row["analysis_context"] = CONTEXTS[key[0]]
                reference_path = (args.oracle_dir / "explicit-context-v1" /
                                  expected["language"].replace(":", "-") /
                                  expected["compiler"] / f"{sha}.json")
                reference_path.parent.mkdir(parents=True, exist_ok=True)
                reference = json.loads(reference_path.read_text()) if reference_path.exists() else {}
                if any(reference.get(k) != v for k, v in expected.items()) or "strings" not in reference:
                    reference = generate_reference(command, binary, expected, args.timeout,
                                                   include_strings=True)
                    write_reference(reference_path, reference)
                validate_reference(reference, expected)
                oracle = string_set(reference["strings"])
                if not oracle:
                    raise ValueError("Oracle exported no eligible strings")
                row["oracle_context"] = {key: reference[key] for key in ("language", "compiler")}
                row["oracle_sha256"] = digest(reference_path)
            except (OSError, ValueError, KeyError, TypeError, LookupError, subprocess.SubprocessError) as error:
                row["reason"] = str(error)
                rows.append(row)
                print(f"SKIPPED {row['id']}: {error}", flush=True)
                continue
            try:
                project = Path(temporary) / row["id"]
                result = subprocess.run([str(ROOT / "target/release/romwright-cli"), "import", str(binary),
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
                    native = string_set({"address": addr, "value": value, "kind": kind}
                        for addr, value, kind in connection.execute("SELECT address,value,kind FROM strings"))
                    targets = {address(dst) for (dst,) in connection.execute(
                        "SELECT DISTINCT dst FROM xrefs WHERE kind IN ('READ','WRITE','READ_WRITE','DATA')")}
                matched = len(native & oracle)
                row.update(oracle_strings=len(oracle), native_strings=len(native), matched=matched,
                           strings_with_references=sum(addr in targets for addr, _ in native),
                           missing=sorted(oracle - native), extra=sorted(native - oracle))
                row["metrics"] = {"str.recall": matched / len(oracle)}
                row["status"] = "pass" if row["metrics"]["str.recall"] >= 0.95 else "fail"
            except (OSError, ValueError, KeyError, TypeError, LookupError, sqlite3.Error,
                    subprocess.SubprocessError) as error:
                row.update(status="fail", reason=str(error))
            rows.append(row)
            print(f"{row['status'].upper()} {row['id']}: {row.get('reason', row['metrics'])}", flush=True)
    summary = {status: sum(row["status"] == status for row in rows) for status in ("pass", "fail", "skipped")}
    report = {"gate": "strings", "milestone": "M2", "task": "m2-003",
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "date": datetime.now(timezone.utc).date().isoformat(),
              "machine": {"os": platform.platform(), "cpu": platform.processor() or platform.machine(),
                          "ram_gb": physical_memory_gb()},
              "corpus": rows, "summary": summary,
              "passed": len(rows) == 20 and summary["pass"] == 20}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    detail_dir = args.report.with_name(args.report.stem + "-details")
    detail_dir.mkdir(parents=True, exist_ok=True)
    for row in rows:
        if "missing" not in row:
            continue
        differences = {"schema_version": 1, "id": row["id"],
                       "missing": row.pop("missing"), "extra": row.pop("extra")}
        detail_path = detail_dir / f"{row['id']}.json"
        write_reference(detail_path, differences)
        row.update(missing_count=len(differences["missing"]), extra_count=len(differences["extra"]),
                   differences={"path": os.path.relpath(detail_path, args.report.parent),
                                "sha256": digest(detail_path)})
    write_reference(args.report, report)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
