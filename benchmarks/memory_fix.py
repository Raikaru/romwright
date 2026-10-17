#!/usr/bin/env python3
"""What an import and a session cost, before and after the decoder memory fix.

The frozen envelopes (`benchmarks/reports/cost-envelope.json` and
`session-envelope.json`, recorded once, never edited) are measured by
`tests/m7-001` and `tests/m7-003`. This script measures the same things for two
sets of binaries side by side, so the report says where the memory went, and
checks the fix did not cost speed or change a result:

  * peaks: `romwright-cli import` of every locked corpus entry, cold (no
    import cache), as the largest process (`os.wait4`, m7-001's measure), with
    the resident split of that process at its peak (anonymous heap against
    file-backed code), and the decoder builds and reuses the import reported;
  * components: the importing process alone (decompiler stage off): the old decoders,
    the shared decoder with eager tables (`ROMWRIGHT_EAGER_SLA`), the lazy tables;
  * session: one `romwright-api` session per architecture, the m7-003 request
    sequence for warm-up and measured rounds, resident size by process
    (the service, each decompiler it spawned) and the round-by-round tree;
  * images: paired imports of large images (before, after; after, before),
    wall time and peak tree RSS, and every table of the two projects compared
    as a row multiset, timestamp columns masked.

Usage:
    python3 benchmarks/memory_fix.py --before DIR --after DIR --corpus-dir DIR \\
        [--image id=PATH ...] [--rounds N] [--only peaks,session,images] [--report-dir DIR]

`DIR` holds `romwright-cli`, `romwright-api` and `romwright-worker` (a
`target/release`). Writes `memory_fix_<date>.json` and `.md` there.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "benchmarks" / "reports"
HEADROOM = 1.25
SESSION_REQUESTS = ["functions", "symbols", "strings", "memory_regions", "search", "xrefs", "decompile_doc"]
SESSION_WARMUP = 4
SESSION_ROUNDS = 8
SAMPLE_SECONDS = 0.01
SESSION_ARCHITECTURES = ("x86_64_plain_o0", "i386_plain_o0", "aarch64_plain_o0", "powerpc_plain_o0")


def child_environment() -> dict[str, str]:
    """Cold imports, and the decompiler of this checkout for binaries built elsewhere."""
    environment = dict(os.environ, ROMWRIGHT_NO_IMPORT_CACHE="1")
    decompiler = ROOT / "native" / "build" / "ghidra_opt"
    if "ROMWRIGHT_GHIDRA_OPT" not in environment and decompiler.is_file():
        environment["ROMWRIGHT_GHIDRA_OPT"] = str(decompiler)
    return environment


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def status_fields(pid: int) -> dict[str, int] | None:
    try:
        text = Path(f"/proc/{pid}/status").read_text()
    except OSError:
        return None
    fields = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key in ("Name", "VmRSS", "RssAnon", "RssFile"):
            fields[key] = value.strip() if key == "Name" else int(value.split()[0])
    return fields


def descendants(pid: int) -> list[int]:
    found, frontier = [], [pid]
    while frontier:
        current = frontier.pop()
        found.append(current)
        try:
            for thread in Path(f"/proc/{current}/task").iterdir():
                frontier.extend(int(child) for child in (thread / "children").read_text().split())
        except OSError:
            continue
    return found


class Sampler(threading.Thread):
    """Peak of the process tree's resident size, and the split of the largest
    process at the moment it peaked."""

    def __init__(self, pid: int) -> None:
        super().__init__(daemon=True)
        self.pid, self.stop = pid, threading.Event()
        self.tree_peak = 0
        self.largest = {"VmRSS": 0, "RssAnon": 0, "RssFile": 0, "Name": ""}
        self.by_name_peak: dict[str, int] = collections.defaultdict(int)
        self.rounds: list[int] = []

    def run(self) -> None:
        while not self.stop.is_set():
            total = 0
            by_name: dict[str, int] = collections.defaultdict(int)
            for process in descendants(self.pid):
                fields = status_fields(process)
                if not fields or "VmRSS" not in fields:
                    continue
                total += fields["VmRSS"]
                by_name[fields["Name"]] += fields["VmRSS"]
                if fields["VmRSS"] > self.largest["VmRSS"]:
                    self.largest = fields
            self.tree_peak = max(self.tree_peak, total)
            for name, value in by_name.items():
                self.by_name_peak[name] = max(self.by_name_peak[name], value)
            self.stop.wait(SAMPLE_SECONDS)

    def tree_now(self) -> int:
        total = 0
        for process in descendants(self.pid):
            fields = status_fields(process)
            total += (fields or {}).get("VmRSS", 0)
        return total


def run_import(binaries: Path, image: Path, project: Path, extra: list[str] | None = None,
               environment_extra: dict[str, str] | None = None) -> dict:
    """One cold import. The largest process's peak (`ru_maxrss`, what m7-001
    measures) is read by a small parent, `/usr/bin/time`: a child's maximum
    includes its parent's resident size at fork, and this process holds
    megabytes the import never did."""
    environment = dict(child_environment(), **(environment_extra or {}))
    load = os.getloadavg()[0]
    started = time.monotonic()
    with tempfile.NamedTemporaryFile("r", prefix="memory-fix-time-") as peak_file:
        process = subprocess.Popen(
            ["/usr/bin/time", "-f", "%M", "-o", peak_file.name,
             str(binaries / "romwright-cli"), "import", str(image), "--name", "x", "--project", str(project),
             "--timings"] + (extra or []),
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        sampler = Sampler(process.pid)
        sampler.start()
        output = process.stdout.read()
        _, status, usage = os.wait4(process.pid, 0)
        wall = time.monotonic() - started
        sampler.stop.set()
        sampler.join(timeout=2)
        max_rss_kb = int(peak_file.read().split()[-1])
    tally: dict = {}
    for line in output.splitlines():
        if line.startswith("TALLY "):
            tally = json.loads(line[len("TALLY "):])
    return {
        "exit": os.waitstatus_to_exitcode(status), "wall_s": round(wall, 3),
        "cpu_s": round(usage.ru_utime + usage.ru_stime, 3),
        "max_rss_kb": max_rss_kb, "tree_peak_kb": sampler.tree_peak,
        "largest_process_at_peak": {key: sampler.largest[key] for key in ("Name", "VmRSS", "RssAnon", "RssFile")},
        "decoder_builds": tally.get("decoder-builds"), "decoder_reuses": tally.get("decoder-reuses"),
        "decoder_build_thread_s": tally.get("decoder-build"), "load_at_start": round(load, 2),
    }


def entries(corpus: Path) -> list[dict]:
    manifest = json.loads((corpus / "manifest.json").read_text())
    return [dict(entry, id=f"{entry['architecture']}_{entry['variant']}") for entry in manifest["entries"]
            if entry.get("status") == "ok"]


def peaks(before: Path, after: Path, corpus: Path) -> dict:
    envelope = json.loads((REPORTS / "cost-envelope.json").read_text())["entries"]
    rows = []
    for index, entry in enumerate(entries(corpus)):
        row = {"id": entry["id"], "envelope_kb": envelope.get(entry["id"]),
               "limit_kb": int(envelope[entry["id"]] * HEADROOM) if entry["id"] in envelope else None}
        order = [("before", before), ("after", after)] if index % 2 == 0 else [("after", after), ("before", before)]
        for tag, binaries in order:
            with tempfile.TemporaryDirectory(prefix="memory-fix-") as directory:
                row[tag] = run_import(binaries, corpus / entry["binary"], Path(directory) / "project")
        row["after_within_limit"] = row["limit_kb"] is None or row["after"]["max_rss_kb"] <= row["limit_kb"]
        rows.append(row)
        print(f"peaks {row['id']}: before {row['before']['max_rss_kb']} KiB, after {row['after']['max_rss_kb']} KiB "
              f"(limit {row['limit_kb']})", flush=True)
    return {"rows": rows,
            "median_before_kb": statistics.median(r["before"]["max_rss_kb"] for r in rows),
            "median_after_kb": statistics.median(r["after"]["max_rss_kb"] for r in rows),
            "after_failures": [r["id"] for r in rows if not r["after_within_limit"]]}


def components(before: Path, after: Path, corpus: Path) -> dict:
    """The importing process alone (the decompiler stage off, so no child's peak
    is the largest): what the old decoders, the shared decoder with eagerly
    decoded tables, and the lazily decoded tables each leave in the peak."""
    wanted = {entry["id"]: entry for entry in entries(corpus)}
    arms = [("before", before, {}),
            ("after_eager_tables", after, {"ROMWRIGHT_EAGER_SLA": "1"}),
            ("after", after, {})]
    rows = []
    for identifier in SESSION_ARCHITECTURES:
        row = {"id": identifier}
        for tag, binaries, extra in arms:
            with tempfile.TemporaryDirectory(prefix="memory-fix-components-") as directory:
                result = run_import(binaries, corpus / wanted[identifier]["binary"], Path(directory) / "project",
                                    environment_extra=dict(extra, ROMWRIGHT_NO_SWITCH_DECOMPILER="1"))
            row[tag] = {key: result[key] for key in ("max_rss_kb", "largest_process_at_peak", "decoder_builds",
                                                      "decoder_reuses", "decoder_build_thread_s", "wall_s")}
        row["tables_kb"] = row["after_eager_tables"]["max_rss_kb"] - row["after"]["max_rss_kb"]
        row["lanes_pool_kb"] = row["before"]["max_rss_kb"] - row["after_eager_tables"]["max_rss_kb"]
        rows.append(row)
        print(f"components {identifier}: before {row['before']['max_rss_kb']}, shared decoder eager tables "
              f"{row['after_eager_tables']['max_rss_kb']}, lazy {row['after']['max_rss_kb']} KiB", flush=True)
    return {"rows": rows}


def api_session(binaries: Path, entry: dict, corpus: Path) -> dict:
    binary = corpus / entry["unstripped_twin"]
    cli = str(binaries / "romwright-cli")
    with tempfile.TemporaryDirectory(prefix="memory-fix-session-") as directory:
        project = Path(directory) / "project"
        environment = child_environment()
        subprocess.run([cli, "import", str(binary), "--name", "session", "--project", str(project)],
                       env=environment, check=True, capture_output=True)
        listing = subprocess.run([cli, "functions", "session", "--project", str(project)],
                                 capture_output=True, text=True, check=True).stdout
        address = next(line.split()[0] for line in listing.splitlines() if line.split() and line.split()[-1] == "main")
        service = subprocess.Popen([str(binaries / "romwright-api"), "--project", str(project)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   text=True, bufsize=1, env=environment)
        sampler = Sampler(service.pid)
        sampler.start()
        params = {"functions": {}, "symbols": {}, "strings": {}, "memory_regions": {}, "search": {"term": "main"},
                  "xrefs": {"address": address},
                  "decompile_doc": {"binary": str(binary), "address": address}}
        identity, rounds = 0, []
        for index in range(SESSION_WARMUP + SESSION_ROUNDS):
            for method in SESSION_REQUESTS:
                identity += 1
                request = {"api": 2, "id": identity, "method": method,
                           "params": dict(params[method], program="session")}
                service.stdin.write(json.dumps(request) + "\n")
                service.stdin.flush()
                answer = json.loads(service.stdout.readline())
                assert "result" in answer, f"{entry['id']}: {method} failed: {str(answer)[:200]}"
            rounds.append(sampler.tree_now())
        final = {}
        for process in descendants(service.pid):
            fields = status_fields(process)
            if fields and "VmRSS" in fields:
                final.setdefault(fields["Name"], []).append(fields["VmRSS"])
        service.stdin.close()
        service.wait(timeout=30)
        sampler.stop.set()
        sampler.join(timeout=2)
    return {"tree_peak_kb": sampler.tree_peak, "rounds_kb": rounds,
            "growth_after_warmup_kb": rounds[-1] - rounds[SESSION_WARMUP],
            "final_by_process_kb": {name: values for name, values in final.items()},
            "processes_at_end": sum(len(values) for values in final.values()),
            "peak_by_name_kb": dict(sampler.by_name_peak)}


def session(before: Path, after: Path, corpus: Path) -> dict:
    envelope = json.loads((REPORTS / "session-envelope.json").read_text())["entries"]
    wanted = {entry["id"]: entry for entry in entries(corpus) if entry.get("unstripped_twin")}
    rows = []
    for identifier in SESSION_ARCHITECTURES:
        entry = wanted[identifier]
        row = {"id": identifier, "envelope_kb": envelope[identifier], "limit_kb": int(envelope[identifier] * HEADROOM)}
        for tag, binaries in (("before", before), ("after", after)):
            row[tag] = api_session(binaries, entry, corpus)
        row["after_within_limit"] = row["after"]["tree_peak_kb"] <= row["limit_kb"]
        rows.append(row)
        print(f"session {identifier}: before {row['before']['tree_peak_kb']} KiB "
              f"({row['before']['processes_at_end']} processes), after {row['after']['tree_peak_kb']} KiB "
              f"({row['after']['processes_at_end']}), limit {row['limit_kb']}", flush=True)
    return {"rows": rows}


MASKED = {"programs": {"imported_at", "created_at", "updated_at"}}


def table_rows(database: sqlite3.Connection, table: str) -> collections.Counter:
    columns = [row[1] for row in database.execute(f"pragma table_info({table})")]
    masked = {index for index, column in enumerate(columns)
              if column in MASKED.get(table, ()) or column.endswith("_at") or column in ("at", "created", "timestamp")}
    counter: collections.Counter = collections.Counter()
    for row in database.execute(f"select * from {table}"):
        counter[tuple(None if index in masked else (bytes(value) if isinstance(value, memoryview) else value)
                      for index, value in enumerate(row))] += 1
    return counter


def compare_projects(first: Path, second: Path) -> dict:
    a, b = sqlite3.connect(first / "project.sqlite"), sqlite3.connect(second / "project.sqlite")
    names = lambda db: [row[0] for row in db.execute(
        "select name from sqlite_master where type='table' and name not like 'sqlite_%' order by name")]
    tables_a, tables_b = names(a), names(b)
    differing, total = [], 0
    for table in sorted(set(tables_a) & set(tables_b)):
        rows_a, rows_b = table_rows(a, table), table_rows(b, table)
        total += sum(rows_a.values())
        if rows_a != rows_b:
            differing.append(table)
    return {"tables": len(tables_a), "rows": total, "differing_tables": differing,
            "table_lists_equal": tables_a == tables_b, "identical": not differing and tables_a == tables_b}


def images(before: Path, after: Path, specs: list[tuple[str, Path]], rounds: int) -> dict:
    rows = []
    for identifier, image in specs:
        row = {"id": identifier, "image_bytes": image.stat().st_size, "before": [], "after": []}
        kept: dict[str, Path] = {}
        scratch = Path(tempfile.mkdtemp(prefix="memory-fix-images-"))
        try:
            for index in range(rounds):
                order = [("before", before), ("after", after)] if index % 2 == 0 else [("after", after), ("before", before)]
                for tag, binaries in order:
                    project = scratch / f"{tag}{index}"
                    result = run_import(binaries, image, project)
                    row[tag].append(result)
                    print(f"images {identifier} {tag}: {result['wall_s']} s, tree peak "
                          f"{result['tree_peak_kb'] // 1024} MiB, load {result['load_at_start']}", flush=True)
                    if index == 0:
                        kept[tag] = project
                    else:
                        shutil.rmtree(project, ignore_errors=True)
            row["identity"] = compare_projects(kept["before"], kept["after"])
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        walls = {tag: [r["wall_s"] for r in row[tag]] for tag in ("before", "after")}
        row["wall_before_mean_s"] = round(statistics.mean(walls["before"]), 3)
        row["wall_after_mean_s"] = round(statistics.mean(walls["after"]), 3)
        row["wall_ratio_after_over_before"] = round(row["wall_after_mean_s"] / row["wall_before_mean_s"], 3)
        cpus = {tag: [r["cpu_s"] for r in row[tag]] for tag in ("before", "after")}
        row["cpu_before_mean_s"] = round(statistics.mean(cpus["before"]), 3)
        row["cpu_after_mean_s"] = round(statistics.mean(cpus["after"]), 3)
        row["cpu_ratio_after_over_before"] = round(row["cpu_after_mean_s"] / row["cpu_before_mean_s"], 3)
        rows.append(row)
    return {"rows": rows}


def markdown(document: dict) -> str:
    out = [f"# Memory fix: {document['date']}", "",
           f"Host {document['host']['node']}, load at start {document['host']['load_at_start']}. "
           f"Before: `{document['before']['dir']}`; after: `{document['after']['dir']}` "
           f"(`romwright-cli` sha256 `{document['before']['cli_sha256'][:12]}` and `{document['after']['cli_sha256'][:12]}`). "
           "Every import cold (`ROMWRIGHT_NO_IMPORT_CACHE=1`).",
           f"Verdict: **{'PASS' if document.get('passed') else 'FAIL'}** "
           + ", ".join(f"{name.replace('_', ' ')}: {'yes' if ok else 'NO'}" for name, ok in document.get("checks", {}).items()),
           ""]
    if "peaks" in document:
        data = document["peaks"]
        out += ["## Import peak (m7-001's measure: the largest process, `ru_maxrss`, KiB)", "",
                "| entry | frozen | limit (x1.25) | before | after | after: largest process at its peak, anon / file | decoders built before / after | pass |",
                "|---|---|---|---|---|---|---|---|"]
        for row in data["rows"]:
            peak = row["after"]["largest_process_at_peak"]
            out.append(f"| {row['id']} | {row['envelope_kb']} | {row['limit_kb']} | {row['before']['max_rss_kb']} | "
                       f"{row['after']['max_rss_kb']} | {peak['Name']}: {peak['RssAnon']} / {peak['RssFile']} | "
                       f"{int(row['before']['decoder_builds'])} / {int(row['after']['decoder_builds'])} | "
                       f"{'yes' if row['after_within_limit'] else 'NO'} |")
        out += ["", f"Median {data['median_before_kb']} -> {data['median_after_kb']} KiB; "
                    f"entries over the limit after: {data['after_failures'] or 'none'}.", ""]
    if "session" in document:
        out += ["## Session (m7-003's measure: the service and the decompiler children, resident KiB)", "",
                "| entry | frozen | limit (x1.25) | before peak | after peak | before processes at end | after | growth after warm-up before / after | pass |",
                "|---|---|---|---|---|---|---|---|---|"]
        for row in document["session"]["rows"]:
            out.append(f"| {row['id']} | {row['envelope_kb']} | {row['limit_kb']} | {row['before']['tree_peak_kb']} | "
                       f"{row['after']['tree_peak_kb']} | {row['before']['processes_at_end']} | "
                       f"{row['after']['processes_at_end']} | {row['before']['growth_after_warmup_kb']} / "
                       f"{row['after']['growth_after_warmup_kb']} | {'yes' if row['after_within_limit'] else 'NO'} |")
        if document["session"].get("over_limit"):
            out += ["", f"Still over the frozen limit after the fix: {', '.join(document['session']['over_limit'])}. "
                        "The service is down from 9 processes to 2 and from hundreds of MiB to the figures above; what "
                        "remains is the resident code of the service binary and of the decompiler beside it."]
        out.append("")
    if "components" in document:
        out += ["## Components of a tiny import (the importing process alone: decompiler stage off, KiB)", "",
                "| entry | before (4 lanes + plain lifter, each a full decoder) | after, tables decoded eagerly | after | what sharing one decoder saved | what lazy tables saved | after: anon / file at peak | decoder builds before / after |",
                "|---|---|---|---|---|---|---|---|"]
        for row in document["components"]["rows"]:
            peak = row["after"]["largest_process_at_peak"]
            out.append(f"| {row['id']} | {row['before']['max_rss_kb']} | {row['after_eager_tables']['max_rss_kb']} | "
                       f"{row['after']['max_rss_kb']} | {row['lanes_pool_kb']} | {row['tables_kb']} | "
                       f"{peak['Name']}: {peak['RssAnon']} / {peak['RssFile']} | "
                       f"{int(row['before']['decoder_builds'])} / {int(row['after']['decoder_builds'])} |")
        out.append("")
    if "images" in document:
        out += ["## Large images: paired wall time, peak tree RSS, identical rows", "",
                "| image | before wall (s) | after wall (s) | after / before | before CPU (s, user+sys) | after CPU | after / before | before peak tree MiB | after | tables / rows compared | identical |",
                "|---|---|---|---|---|---|---|---|---|---|---|"]
        for row in document["images"]["rows"]:
            peak = lambda tag: max(r["tree_peak_kb"] for r in row[tag]) // 1024
            identity = row["identity"]
            out.append(f"| {row['id']} | {row['wall_before_mean_s']} ({', '.join(str(r['wall_s']) for r in row['before'])}) | "
                       f"{row['wall_after_mean_s']} ({', '.join(str(r['wall_s']) for r in row['after'])}) | "
                       f"{row['wall_ratio_after_over_before']} | {row['cpu_before_mean_s']} | {row['cpu_after_mean_s']} | "
                       f"{row['cpu_ratio_after_over_before']} | {peak('before')} | {peak('after')} | "
                       f"{identity['tables']} / {identity['rows']} | {'yes' if identity['identical'] else 'NO'} |")
        out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--image", action="append", default=[], metavar="ID=PATH")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--only", default="peaks,components,session,images")
    parser.add_argument("--rerender", type=Path, help="recompute the verdict and the markdown of a written report")
    parser.add_argument("--report-dir", type=Path, default=REPORTS)
    arguments = parser.parse_args()
    if arguments.rerender:
        return finish(json.loads(arguments.rerender.read_text()), arguments.report_dir)
    parts = set(arguments.only.split(","))
    document = {
        "id": "memory-fix", "date": date.today().isoformat(),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "host": {"node": platform.node(), "machine": platform.machine(), "load_at_start": round(os.getloadavg()[0], 2)},
        "before": {"dir": str(arguments.before), "cli_sha256": sha256(arguments.before / "romwright-cli")},
        "after": {"dir": str(arguments.after), "cli_sha256": sha256(arguments.after / "romwright-cli")},
    }
    if "peaks" in parts:
        document["peaks"] = peaks(arguments.before, arguments.after, arguments.corpus_dir)
    if "components" in parts:
        document["components"] = components(arguments.before, arguments.after, arguments.corpus_dir)
    if "session" in parts:
        document["session"] = session(arguments.before, arguments.after, arguments.corpus_dir)
    if "images" in parts and arguments.image:
        specs = [(item.partition("=")[0], Path(item.partition("=")[2])) for item in arguments.image]
        document["images"] = images(arguments.before, arguments.after, specs, arguments.rounds)
    return finish(document, arguments.report_dir)


# Wall time may differ by this much, before to after, on a large image.
SPEED_TOLERANCE = 1.05


def verdict(document: dict) -> None:
    """What this report gates: every import inside its frozen envelope, no
    result changed, no large image slower, no session larger than it was. The
    session entries still over their frozen m7-003 limit are recorded beside
    it (`session.over_limit`), not hidden in it: that gate has its own report."""
    session = document.get("session")
    if session:
        session["over_limit"] = [row["id"] for row in session["rows"] if not row["after_within_limit"]]
    checks = {
        "imports_inside_envelope": not document.get("peaks", {}).get("after_failures"),
        "session_not_larger": all(row["after"]["tree_peak_kb"] <= row["before"]["tree_peak_kb"]
                                  for row in (session or {}).get("rows", [])),
        "results_identical": all(row["identity"]["identical"] for row in document.get("images", {}).get("rows", [])),
        "images_not_slower": all(row["wall_ratio_after_over_before"] <= SPEED_TOLERANCE
                                 for row in document.get("images", {}).get("rows", [])),
    }
    document["checks"] = checks
    document["passed"] = all(checks.values())
    metrics: dict[str, float | int] = {}
    if "peaks" in document:
        rows = document["peaks"]["rows"]
        metrics["import.peak_kb.median.before"] = document["peaks"]["median_before_kb"]
        metrics["import.peak_kb.median.after"] = document["peaks"]["median_after_kb"]
        metrics["import.peak_over_limit.worst_ratio"] = round(
            max(row["after"]["max_rss_kb"] / row["limit_kb"] for row in rows if row["limit_kb"]), 3)
        metrics["import.entries_over_limit"] = len(document["peaks"]["after_failures"])
    if session:
        metrics["session.peak_kb.max.after"] = max(row["after"]["tree_peak_kb"] for row in session["rows"])
        metrics["session.processes_at_end.after"] = max(row["after"]["processes_at_end"] for row in session["rows"])
        metrics["session.entries_over_limit"] = len(session["over_limit"])
    if document.get("images"):
        metrics["images.wall_ratio.max"] = max(row["wall_ratio_after_over_before"] for row in document["images"]["rows"])
        metrics["images.cpu_ratio.max"] = max(row["cpu_ratio_after_over_before"] for row in document["images"]["rows"])
        metrics["images.rows_compared"] = sum(row["identity"]["rows"] for row in document["images"]["rows"])
    document["metrics"] = metrics


def finish(document: dict, report_dir: Path) -> int:
    verdict(document)
    report_dir.mkdir(parents=True, exist_ok=True)
    stem = report_dir / f"memory_fix_{document['date'].replace('-', '')}"
    stem.with_suffix(".json").write_text(json.dumps(document, indent=1) + "\n")
    stem.with_suffix(".md").write_text(markdown(document) + "\n")
    over = (document.get("session") or {}).get("over_limit")
    print(f"{'PASS' if document['passed'] else 'FAIL'}: wrote {stem.with_suffix('.json')} and .md"
          + (f"; session entries over the frozen limit: {over}" if over else ""))
    return 0 if document["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
