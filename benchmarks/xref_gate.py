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
from gen_oracle import bridge_command, digest, provenance, write_reference


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
    if "CALL" in name and name != "CALLOTHER_OVERRIDE_JUMP":
        return ("call",)
    if "JUMP" in name or name == "FALL_THROUGH":
        return ("jump",)
    if name in ("READ_WRITE", "READ_WRITE_IND"):
        return ("read", "write")
    if name in ("READ", "READ_IND"):
        return ("read",)
    if name in ("WRITE", "WRITE_IND"):
        return ("write",)
    if name in ("DATA", "DATA_IND", "PARAM", "INDIRECTION", "THUNK", "EXTERNAL_REF"):
        return ("data",)
    raise ValueError(f"Unclassified reference kind: {name}")


def triples(rows):
    return {(address(row["from"]), address(row["to"]), kind)
            for row in rows for kind in kinds(row["kind"])}


def generate_reference(command, binary, expected, timeout):
    requests = [
        {"id": 1, "method": "import", "params": {"session": "xref-oracle", "path": str(binary)}},
        {"id": 2, "method": "export_facts", "params": {"session": "xref-oracle"}},
        {"id": 3, "method": "close", "params": {"session": "xref-oracle"}},
    ]
    with tempfile.TemporaryDirectory(prefix="xref-oracle-") as project:
        result = subprocess.run(command + ["--project-dir", project],
                                input="".join(json.dumps(row) + "\n" for row in requests),
                                capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise ValueError(f"Bridge exited {result.returncode}: {result.stderr[-1000:]}")
    replies = {}
    for line in result.stdout.splitlines():
        if not line.strip().startswith("{"):
            continue
        reply = json.loads(line)
        if reply.get("id") in (1, 2, 3):
            if reply["id"] in replies or "error" in reply:
                raise ValueError(f"Invalid bridge reply: {reply}")
            replies[reply["id"]] = reply["result"]
    if set(replies) != {1, 2, 3} or replies[3].get("ok") is not True:
        raise ValueError("Incomplete bridge response")
    rows = replies[2]["xrefs"]
    if not triples(rows):
        raise ValueError("Oracle exported no references")
    return {**expected, "language": replies[1]["language"],
            "image_base": replies[1]["image_base"], "xrefs": rows}


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
    subprocess.run(["cargo", "build", "-q", "-p", "lre-cli"], cwd=ROOT, check=True)
    lock = json.loads((ROOT / "tests/corpus.lock.json").read_text())
    required = [row for row in lock["entries"] if row["format"] == "elf"]
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
                   "thresholds": {"xref.precision": 0.98, "xref.recall": 0.95}, "runs": 1}
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
                            **producer, "address_basis": "ghidra", "export": "export_facts"}
                reference_path = args.oracle_dir / f"{sha}.json"
                reference = json.loads(reference_path.read_text()) if reference_path.exists() else {}
                if any(reference.get(k) != v for k, v in expected.items()):
                    reference = generate_reference(command, binary, expected, args.timeout)
                    write_reference(reference_path, reference)
                oracle = triples(reference["xrefs"])
                if not oracle:
                    raise ValueError("Oracle exported no references")
                row["oracle_sha256"] = digest(reference_path)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                row["reason"] = str(error)
                rows.append(row)
                print(f"SKIPPED {row['id']}: {error}", flush=True)
                continue
            try:
                project = Path(temporary) / row["id"]
                result = subprocess.run([str(ROOT / "target/debug/lre-cli"), "import-native", str(binary),
                    "--name", row["id"], "--project", str(project)],
                    capture_output=True, text=True, timeout=args.timeout)
                if result.returncode:
                    raise ValueError(result.stdout + result.stderr)
                with sqlite3.connect(project / "project.sqlite") as connection:
                    native = triples({"from": src, "to": dst, "kind": kind} for src, dst, kind in
                                     connection.execute("SELECT src,dst,kind FROM xrefs"))
                matched = len(native & oracle)
                row.update(oracle_references=len(oracle), native_references=len(native), matched=matched,
                           missing=sorted(oracle - native), extra=sorted(native - oracle))
                row["metrics"] = {"xref.precision": matched / len(native) if native else 0.0,
                                  "xref.recall": matched / len(oracle)}
                row["status"] = "pass" if all(row["metrics"][k] >= v for k, v in row["thresholds"].items()) else "fail"
            except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError) as error:
                row.update(status="fail", reason=str(error))
            rows.append(row)
            print(f"{row['status'].upper()} {row['id']}: {row.get('reason', row['metrics'])}", flush=True)
    summary = {status: sum(row["status"] == status for row in rows) for status in ("pass", "fail", "skipped")}
    report = {"gate": "xref", "milestone": "M2", "task": "m2-002",
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
