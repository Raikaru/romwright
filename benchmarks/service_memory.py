#!/usr/bin/env python3
"""What a `romwright-api` session costs, for two sets of binaries side by side.

`tests/m7-003` bounds the peak resident size of a session (the service and the
decompiler it spawns) against `benchmarks/reports/session-envelope.json`. This
measures the same session -- the m7-003 request sequence, four warm-up rounds
and eight measured -- for a `before` and an `after` set of binaries, every
locked corpus entry, alternating the two and repeating, so a report can say
what a change to the service moved and whether the answers stayed the same:

  * the peak of the process tree, and of the service and the decompiler apart,
    against the frozen limit (envelope x 1.25);
  * the service's resident size at the end, split into anonymous memory and
    file-backed (code) pages;
  * `decompile_doc`'s reply parsed from both services: it must be one JSON
    value (key order aside, which a parse discards), entry by entry. The
    decompiler itself is not deterministic on some functions (it orders by
    address-derived keys: the same binary's own runs differ in variable ids and
    the types it settles on), so for such an entry the report records that the
    runs of the unchanged side differ among themselves, and the token stream
    (the text the reply exists to carry) must still be equal everywhere.

The project is imported once per entry (cold, by the `after` CLI) and each
service run gets its own copy of it.

The resident size of a binary's code depends on how its pages sit in the
page cache, not only on the binary: the kernel maps the pages around a touched
one (fault-around, 64 KiB), and a file just rsynced or copied is cached in
large folios that map more than one read in from disk. The same binary
measured 11.1 MB of mapped text after rsync, 9.1 after cp and 8.2 read back
from disk (a binary the linker just wrote measured like the last).
`--refault-binaries` drops both sets' pages (and the decompiler's) from the
page cache first, so each binary is faulted in the way a disk read does and
the two sets are measured in the same state; the report records whether it was
used.

Usage:
    python3 benchmarks/service_memory.py --before DIR --after DIR --corpus-dir DIR \\
        [--repeats N] [--only ID,ID] [--date YYYYMMDD] [--report-dir DIR] [--refault-binaries]

`DIR` holds `romwright-cli` and `romwright-api`. Writes
`service_memory_<date>.json` and `.md` into the report directory (default
`benchmarks/reports`); an existing report is never overwritten.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from memory_fix import (HEADROOM, REPORTS, SESSION_ROUNDS, SESSION_WARMUP, Sampler,  # noqa: E402
                        child_environment, descendants, entries, sha256, status_fields)

REQUESTS = ["functions", "symbols", "strings", "memory_regions", "search", "xrefs", "decompile_doc"]


def prepare(binaries: Path, entry: dict, corpus: Path, scratch: Path) -> tuple[Path, Path, str]:
    """The entry's project, imported once, and the address of `main`."""
    binary = corpus / entry["unstripped_twin"]
    cli = str(binaries / "romwright-cli")
    project = scratch / "project"
    subprocess.run([cli, "import", str(binary), "--name", "session", "--project", str(project)],
                   env=child_environment(), check=True, capture_output=True)
    listing = subprocess.run([cli, "functions", "session", "--project", str(project)],
                             capture_output=True, text=True, check=True).stdout
    address = next(line.split()[0] for line in listing.splitlines()
                   if line.split() and line.split()[-1] == "main")
    return project, binary, address


def run_session(binaries: Path, project: Path, binary: Path, address: str) -> dict:
    params = {"functions": {}, "symbols": {}, "strings": {}, "memory_regions": {},
              "search": {"term": "main"}, "xrefs": {"address": address},
              "decompile_doc": {"binary": str(binary), "address": address}}
    service = subprocess.Popen([str(binaries / "romwright-api"), "--project", str(project)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True, bufsize=1,
                               env=child_environment())
    sampler = Sampler(service.pid)
    sampler.start()
    identity, reply_bytes, document = 0, 0, None
    try:
        for _ in range(SESSION_WARMUP + SESSION_ROUNDS):
            for method in REQUESTS:
                identity += 1
                request = {"api": 2, "id": identity, "method": method,
                           "params": dict(params[method], program="session")}
                service.stdin.write(json.dumps(request) + "\n")
                service.stdin.flush()
                line = service.stdout.readline()
                answer = json.loads(line)
                assert "result" in answer, f"{method} failed: {line[:200]}"
                if method == "decompile_doc":
                    reply_bytes = len(line)
                    document = answer["result"]
        final = status_fields(service.pid) or {}
        processes = len(descendants(service.pid))
        service.stdin.close()
        service.wait(timeout=30)
    finally:
        sampler.stop.set()
        sampler.join(timeout=2)
        if service.poll() is None:
            service.kill()
    by_name = dict(sampler.by_name_peak)
    return {"tree_peak_kb": sampler.tree_peak,
            "service_peak_kb": by_name.get("romwright-api", 0),
            "decompiler_peak_kb": by_name.get("ghidra_opt", 0),
            "service_end": {key: final.get(key) for key in ("VmRSS", "RssAnon", "RssFile")},
            "processes": processes, "reply_bytes": reply_bytes, "document": document}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--only", default="")
    parser.add_argument("--date", default=date.today().strftime("%Y%m%d"))
    parser.add_argument("--report-dir", type=Path, default=REPORTS)
    parser.add_argument("--refault-binaries", action="store_true",
                        help="drop the page cache of the binaries before measuring (see below)")
    arguments = parser.parse_args()
    for name in ("json", "md"):
        target = arguments.report_dir / f"service_memory_{arguments.date}.{name}"
        assert not target.exists(), f"{target} exists; reports are never overwritten"

    if arguments.refault_binaries:
        for path in [arguments.before / "romwright-api", arguments.before / "romwright-cli",
                     arguments.after / "romwright-api", arguments.after / "romwright-cli",
                     Path(child_environment().get("ROMWRIGHT_GHIDRA_OPT", ""))]:
            if path.is_file():
                descriptor = os.open(path, os.O_RDONLY)
                os.posix_fadvise(descriptor, 0, 0, os.POSIX_FADV_DONTNEED)
                os.close(descriptor)
    envelope = json.loads((REPORTS / "session-envelope.json").read_text())["entries"]
    wanted = {entry_id for entry_id in arguments.only.split(",") if entry_id}
    rows = []
    for entry in entries(arguments.corpus_dir):
        identifier = f"{entry['architecture']}_{entry['variant']}"
        if not entry.get("unstripped_twin") or (wanted and identifier not in wanted):
            continue
        scratch = Path(tempfile.mkdtemp(prefix="service-memory-"))
        try:
            project, binary, address = prepare(arguments.after, entry, arguments.corpus_dir, scratch)
            runs = {"before": [], "after": []}
            for index in range(arguments.repeats):
                order = ("before", "after") if index % 2 == 0 else ("after", "before")
                for tag in order:
                    copy = scratch / f"{tag}{index}"
                    shutil.copytree(project, copy)
                    runs[tag].append(run_session(
                        arguments.before if tag == "before" else arguments.after, copy, binary, address))
                    shutil.rmtree(copy, ignore_errors=True)
            limit = int(envelope[identifier] * HEADROOM)
            documents = {tag: [run.pop("document") for run in runs[tag]] for tag in runs}
            every = documents["before"] + documents["after"]
            identical = all(document == every[0] for document in every)
            deterministic = all(document == documents["before"][0] for document in documents["before"])
            tokens = all(document["tokens"] == every[0]["tokens"] for document in every)
            row = {"id": identifier, "frozen_kb": envelope[identifier], "limit_kb": limit,
                   "documents_identical": identical or (not deterministic and tokens),
                   "documents_equal": identical, "decompiler_deterministic_here": deterministic,
                   "tokens_equal": tokens, "reply_bytes": runs["after"][0]["reply_bytes"]}
            for tag in ("before", "after"):
                peaks = [run["tree_peak_kb"] for run in runs[tag]]
                row[tag] = {
                    "tree_peak_kb": peaks,
                    "median_kb": int(statistics.median(peaks)),
                    "max_kb": max(peaks),
                    "service_peak_kb": int(statistics.median(run["service_peak_kb"] for run in runs[tag])),
                    "decompiler_peak_kb": int(statistics.median(run["decompiler_peak_kb"] for run in runs[tag])),
                    "service_end_kb": runs[tag][-1]["service_end"],
                    "processes": runs[tag][-1]["processes"],
                }
            row["after_all_within_limit"] = row["after"]["max_kb"] <= limit
            rows.append(row)
            print(f"{identifier}: limit {limit}, before {row['before']['tree_peak_kb']}, "
                  f"after {row['after']['tree_peak_kb']} (service {row['after']['service_peak_kb']}), "
                  f"reply {row['reply_bytes']} B, documents equal: {row['documents_equal']}, tokens equal: "
                  f"{row['tokens_equal']}, decompiler deterministic here: {row['decompiler_deterministic_here']}",
                  flush=True)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    verdict = (all(row["after_all_within_limit"] for row in rows)
               and all(row["documents_identical"] for row in rows))
    metrics = {
        "session.peak_kb.max.before": max(row["before"]["max_kb"] for row in rows),
        "session.peak_kb.max.after": max(row["after"]["max_kb"] for row in rows),
        "session.entries_over_limit.before": sum(row["before"]["max_kb"] > row["limit_kb"] for row in rows),
        "session.entries_over_limit.after": sum(not row["after_all_within_limit"] for row in rows),
        "session.margin_kb.min.after": min(row["limit_kb"] - row["after"]["max_kb"] for row in rows),
        "service.peak_kb.median.before": int(statistics.median(row["before"]["service_peak_kb"] for row in rows)),
        "service.peak_kb.median.after": int(statistics.median(row["after"]["service_peak_kb"] for row in rows)),
        "documents.entries_equal": sum(row["documents_equal"] for row in rows),
        "documents.entries_tokens_equal": sum(row["tokens_equal"] for row in rows),
    }
    document = {
        "id": "service-memory",
        "date": arguments.date,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "host": {"uname": " ".join(os.uname()), "load": os.getloadavg()},
        "before": {"dir": str(arguments.before),
                   "romwright-api": sha256(arguments.before / "romwright-api")[:12]},
        "after": {"dir": str(arguments.after),
                  "romwright-api": sha256(arguments.after / "romwright-api")[:12]},
        "repeats": arguments.repeats, "binaries_refaulted": arguments.refault_binaries, "headroom": HEADROOM, "warmup_rounds": SESSION_WARMUP,
        "rounds": SESSION_ROUNDS, "passed": verdict, "metrics": metrics, "rows": rows,
    }
    arguments.report_dir.mkdir(parents=True, exist_ok=True)
    (arguments.report_dir / f"service_memory_{arguments.date}.json").write_text(
        json.dumps(document, indent=1) + "\n")
    lines = [f"# Service memory: {arguments.date}", "",
             f"Host load at the end {document['host']['load'][0]:.2f}; before `romwright-api` "
             f"{document['before']['romwright-api']}, after {document['after']['romwright-api']}; "
             f"{arguments.repeats} alternating repeats per entry"
             f"{', binaries dropped from the page cache first' if arguments.refault_binaries else ''}. Verdict: "
             f"**{'PASS' if verdict else 'FAIL'}** (every after run inside the frozen limit, every "
             f"`decompile_doc` reply the same JSON value or, where the decompiler is "
             f"not deterministic, the same tokens).", "",
             "| entry | frozen | limit (x1.25) | before runs | after runs | after: service / decompiler peak | "
             "service at end anon / file | reply bytes | documents equal / tokens equal | pass |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for row in rows:
        end = row["after"]["service_end_kb"]
        lines.append(
            f"| {row['id']} | {row['frozen_kb']} | {row['limit_kb']} | "
            f"{', '.join(map(str, row['before']['tree_peak_kb']))} | "
            f"{', '.join(map(str, row['after']['tree_peak_kb']))} | "
            f"{row['after']['service_peak_kb']} / {row['after']['decompiler_peak_kb']} | "
            f"{end['RssAnon']} / {end['RssFile']} | {row['reply_bytes']} | "
            f"{'yes' if row['documents_equal'] else ('no, decompiler nondeterministic' if row['documents_identical'] else 'NO')}"
            f" / {'yes' if row['tokens_equal'] else 'NO'} | "
            f"{'yes' if row['after_all_within_limit'] else 'NO'} |")
    (arguments.report_dir / f"service_memory_{arguments.date}.md").write_text("\n".join(lines) + "\n")
    print("PASS" if verdict else "FAIL")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
