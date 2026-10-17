#!/usr/bin/env python3
"""P1.7 import gate: what a user sees for MWCC-mangled functions, ours vs stock.

    ours:   python3 benchmarks/mwcc_names_gate.py ours --cli romwright-cli --image IMG
                [--map symbols.txt] --work DIR --out ours.json [--sample N]
    stock:  python3 benchmarks/mwcc_names_gate.py stock --json stock.json --out stock.json.report
                (stock.json from benchmarks/ghidra/ExportFunctionNames.java)

A function name is *mangled* when `dtk demangle` (or, for the `T`/`N`
back-reference names dtk refuses, our demangler in its extension dialect)
decodes it. Counted per image:

  * ours: functions whose store row keeps the mangled linkage name, how many
    of them carry an MWCC display symbol, how many get a prototype fact, and
    what the decompiler prints for a sample, before and after the prototype
    facts (the "before" project is the same store with those rows deleted):
    printed parameter count against the count the mangled name spells (plus
    `this` for a scoped function, which the name does not prove), and the
    functions printed `void` before that print a value after (the mangling
    carries no return type, so the prototype's return is an unknown word).
  * stock: functions whose Ghidra name is still the mangled name after
    auto-analysis, and how many the analysis renamed.
"""
import argparse
import json
import random
import re
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DEFAULT_DTK = str(Path.home() / "Projects/agent-under-fire/tools/dtk")
DISPLAY = "native-analysis:mwcc-demangle"
PROTOTYPE = "native-analysis:mwcc-prototype"


def dtk_text(dtk, name):
    r = subprocess.run([dtk, "demangle", "--", name], capture_output=True, text=True,
                       stdin=subprocess.DEVNULL)
    return r.stdout.rstrip("\n") if r.returncode == 0 and r.stdout.strip() else None


def oracle(dtk, ours_example, names, cache_path):
    """name -> (demangled text, source) for names either demangler decodes."""
    cache = {}
    if cache_path and Path(cache_path).exists():
        cache = json.loads(Path(cache_path).read_text())
    todo = [n for n in names if n not in cache and "__" in n]
    with ThreadPoolExecutor(6) as pool:
        for name, text in zip(todo, pool.map(lambda n: dtk_text(dtk, n), todo)):
            cache[name] = text
    if cache_path:
        Path(cache_path).write_text(json.dumps(cache))
    refused = [n for n in names if "__" in n and not cache.get(n)]
    extended = {}
    if ours_example and refused:
        out = subprocess.run([ours_example, "--extensions"], input="\n".join(refused) + "\n",
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            name, _, value = line.partition("\t")
            if value and value != "-":
                extended[name] = value
    result = {}
    for n in names:
        if cache.get(n):
            result[n] = (cache[n], "dtk")
        elif n in extended:
            result[n] = (extended[n], "extension")
    return result


def split_top(text):
    """Top-level comma split of a parameter list, `<>`/`()` aware."""
    parts, depth, cur = [], 0, ""
    for ch in text:
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def param_list(text):
    """The text inside the outermost trailing parameter list, or None."""
    text = re.sub(r"\s+const$", "", text)
    if not text.endswith(")"):
        return None
    depth = 0
    for i in range(len(text) - 1, -1, -1):
        if text[i] == ")":
            depth += 1
        elif text[i] == "(":
            depth -= 1
            if depth == 0:
                return text[:i], text[i + 1:-1]
    return None


def spelled_arity(text):
    """(parameters the name spells, scoped) from a demangled spelling."""
    parsed = param_list(text)
    if parsed is None:
        return None
    head, inner = parsed
    params = [] if inner.strip() in ("", "void") else split_top(inner)
    params = [p for p in params if p != "..."]
    depth, scoped = 0, False
    for i, ch in enumerate(head):
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        elif ch == ":" and depth == 0 and head[i - 1:i + 1] == "::":
            scoped = True
    return len(params), scoped, "..." in inner


def printed_header(code):
    """(return type, parameter count) of the C a decompile printed."""
    head = code.split("{", 1)[0].strip()
    parsed = param_list(head)
    if parsed is None:
        return None
    prefix, inner = parsed
    params = [] if inner.strip() in ("", "void") else split_top(inner)
    params = [p for p in params if p != "..."]
    ret = re.sub(r"[A-Za-z_][A-Za-z0-9_]*\s*$", "", prefix).strip().rstrip("*").strip()
    return ret, len(params)


def decompile(cli, image, project, name, entries, chunk=40):
    out = {}
    for i in range(0, len(entries), chunk):
        batch = entries[i:i + chunk]
        r = subprocess.run([cli, "decompile-batch", str(image), ",".join(f"{e:08x}" for e in batch),
                            "--name", name, "--project", str(project)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            continue
        try:
            answers = json.loads(r.stdout)
        except json.JSONDecodeError:
            continue
        for key, code in answers.items():
            out[int(key, 16)] = code
    return out


def ours(args):
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    project = work / "project"
    if project.exists():
        subprocess.run(["rm", "-rf", str(project)], check=True)
    project.mkdir()
    name = "img"
    cmd = [args.cli, "import", args.image, "--name", name, "--project", str(project)]
    if args.map:
        cmd += ["--map", args.map]
    run = subprocess.run(cmd, capture_output=True, text=True)
    if run.returncode != 0:
        sys.exit(f"import failed: {run.stderr[-400:]}")
    db = sqlite3.connect(project / "project.sqlite")
    functions = {int(a, 16): n for a, n in db.execute("select entry, name from functions")}
    display = {int(a, 16): n for a, n in db.execute(
        "select address, name from symbols where source = ?", (DISPLAY,))}
    protos = {int(a, 16): s for a, s in db.execute(
        "select function, signature from prototypes where provenance = ?", (PROTOTYPE,))}
    decoded = oracle(args.dtk, args.ours_example, sorted(set(functions.values())), args.cache)
    mangled = {e: n for e, n in functions.items() if n in decoded}
    report = {
        "image": Path(args.image).name,
        "functions": len(functions),
        "mangled_linkage_names": len(mangled),
        "mangled_decoded_by_dtk": sum(1 for n in mangled.values() if decoded[n][1] == "dtk"),
        "mangled_decoded_by_extension_only": sum(
            1 for n in mangled.values() if decoded[n][1] == "extension"),
        "with_display_symbol": sum(1 for e in mangled if e in display),
        "left_mangled_as_primary": sum(1 for e in mangled if e not in display),
        "with_prototype_fact": sum(1 for e in mangled if e in protos),
    }
    if args.sample is not None:
        rng = random.Random(1)
        entries = sorted(mangled)
        if args.sample and len(entries) > args.sample:
            entries = sorted(rng.sample(entries, args.sample))
        after = decompile(args.cli, args.image, project, name, entries)
        before_project = work / "project_before"
        subprocess.run(["rm", "-rf", str(before_project)], check=True)
        # The store alone differs; the captured inputs are shared, not copied.
        before_project.mkdir()
        db.close()
        subprocess.run(["cp", str(project / "project.sqlite"), str(before_project)], check=True)
        (before_project / "artifacts").symlink_to((project / "artifacts").resolve())
        bdb = sqlite3.connect(before_project / "project.sqlite")
        bdb.execute("delete from prototypes where provenance = ?", (PROTOTYPE,))
        bdb.commit()
        bdb.close()
        before = decompile(args.cli, args.image, before_project, name, entries)
        rows = []
        for e in entries:
            spelled = spelled_arity(decoded[mangled[e]][0])
            a, b = printed_header(after.get(e, "")), printed_header(before.get(e, ""))
            rows.append(dict(entry=f"{e:08x}", name=mangled[e], spelled=spelled, after=a, before=b,
                             claimed=e in protos,
                             printed_name=(after.get(e, "").split("(", 1)[0].split()[-1:] or [""])[0]))
        report["decompile_sample"] = counts(rows)
        if args.rows:
            Path(args.rows).write_text("".join(json.dumps(r) + "\n" for r in rows))
        report["sample_rows"] = rows[: args.keep]
        report["printed_as_mangled_name"] = [
            r["name"] for r in rows if r["after"] and r["printed_name"] == r["name"]][:40]
        report["arity_mismatches_after"] = [
            r for r in rows if r["claimed"] and r["spelled"] and not r["spelled"][2]
            and r["after"] and r["after"][1] != expected_arity(r)][:40]
    Path(args.out).write_text(json.dumps(report, indent=2))
    print(json.dumps({k: v for k, v in report.items() if k != "sample_rows"}, indent=2))


def expected_arity(row):
    """Parameters the mangled name proves: spelled, plus `this` for a scoped
    function, plus a destructor's delete flag (MWCC passes one)."""
    want, scoped, _ = row["spelled"]
    return want + (1 if scoped else 0) + (1 if row["name"].startswith("__dt__") else 0)


def counts(rows):
    """Arity is scored over the functions a prototype fact speaks for (free
    functions, constructors, destructors, const members); the rest are left
    to the decompiler's recovery and only counted."""
    claimed = [r for r in rows if r["claimed"] and r["spelled"] and not r["spelled"][2]
               and r["before"] and r["after"]]

    def matches(row, which):
        return row[which][1] == expected_arity(row)

    scoped = [r for r in claimed if r["spelled"][1]]
    return {
        "sampled": len(rows),
        "decompiled_before": sum(1 for r in rows if r["before"] is not None),
        "decompiled_after": sum(1 for r in rows if r["after"] is not None),
        "with_prototype_fact": sum(1 for r in rows if r["claimed"]),
        "scored": len(claimed),
        "arity_matches_before": sum(1 for r in claimed if matches(r, "before")),
        "arity_matches_after": sum(1 for r in claimed if matches(r, "after")),
        "scoped_scored": len(scoped),
        "scoped_arity_matches_before": sum(1 for r in scoped if matches(r, "before")),
        "scoped_arity_matches_after": sum(1 for r in scoped if matches(r, "after")),
        # The return value is the decompiler's: a function it printed `void`
        # before must still print `void` (the prototype locks parameters only).
        "void_before_valued_after": sum(
            1 for r in rows if r["claimed"] and r["before"] and r["after"]
            and r["before"][0] == "void" and r["after"][0] != "void"),
        "return_type_changed": sum(
            1 for r in rows if r["claimed"] and r["before"] and r["after"]
            and r["before"][0] != r["after"][0]),
        # The decompiler printed something other than the mangled linkage name.
        "printed_with_demangled_identifier": sum(
            1 for r in rows if r["after"] and r["printed_name"] and r["printed_name"] != r["name"]),
    }


def stock(args):
    data = json.loads(Path(args.json).read_text())
    names = sorted({f["name"] for f in data["functions"]})
    decoded = oracle(args.dtk, args.ours_example, names, args.cache)
    still = [f for f in data["functions"] if f["name"] in decoded]
    qualified_changed = [f for f in still if f["qualified"] != f["name"]]
    report = {
        "program": data["program"],
        "functions": len(data["functions"]),
        "mangled_names_after_analysis": len(still),
        "mangled_names_decoded_by_dtk": sum(1 for f in still if decoded[f["name"]][1] == "dtk"),
        "renamed_or_namespaced_by_stock": len(qualified_changed),
        "stock_examples": [f["name"] for f in still[:5]],
    }
    Path(args.out).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    o = sub.add_parser("ours")
    o.add_argument("--cli", required=True)
    o.add_argument("--image", required=True)
    o.add_argument("--map")
    o.add_argument("--work", required=True)
    o.add_argument("--out", required=True)
    o.add_argument("--sample", type=int, help="functions to decompile (0 = all mangled)")
    o.add_argument("--keep", type=int, default=40)
    o.add_argument("--rows", help="write every sampled row here as JSON lines")
    s = sub.add_parser("stock")
    s.add_argument("--json", required=True)
    s.add_argument("--out", required=True)
    for p in (o, s):
        p.add_argument("--dtk", default=DEFAULT_DTK)
        p.add_argument("--ours-example", help="built mwcc_demangle example (T/N names)")
        p.add_argument("--cache", default="/tmp/mwcc_names_dtk.json")
    args = ap.parse_args()
    {"ours": ours, "stock": stock}[args.mode](args)


if __name__ == "__main__":
    main()
