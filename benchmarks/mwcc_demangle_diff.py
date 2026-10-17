#!/usr/bin/env python3
"""P1.7 differential: romwright's MWCC demangler vs `dtk demangle`.

Every symbol name that contains `__` from the GC/Wii sources on disk is fed to
both demanglers. Agreement = identical text, over the names either side
demangles. A name only we demangle, or only dtk demangles, is a disagreement.

    python3 benchmarks/mwcc_demangle_diff.py --dtk <dtk> --ours <mwcc_demangle example> \
        [--names FILE ...] [--cache DIR] [--min-agreement 0.99] [--out report.json]

Name sources default to the corpora the plan gate was measured on
(`--list-sources` prints them). dtk (MIT/Apache) is only run, never linked.
"""

import argparse
import collections
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HOME = Path.home()
AUF = HOME / "Projects/agent-under-fire"
# ACreTeam/ac-decomp config/ (CC0); override with AC_DECOMP_CONFIG.
AC_CONFIG = Path(os.environ.get("AC_DECOMP_CONFIG", HOME / "opt/ac-decomp/config"))

NIGHTFIRE = HOME / "Projects/nightfire-ps2"
ELF_SOURCES = [AUF / "orig/GQFE78/files" / n for n in
               ("base.elf", "Bond.elf", "Movie.elf", "boot.elf", "driving.elf")] + [
    NIGHTFIRE / "original" / n for n in ("ACTION.ELF", "BASE.ELF", "DRIVING.ELF")]
SYMBOL_LISTS = [
    AUF / "dtk-template/config/GQFE78/symbols.txt",
    AUF / "analysis/symbols.txt",
    *sorted((NIGHTFIRE / "config").glob("*/symbol_addrs.txt")),
    *sorted(AC_CONFIG.glob("*/symbols.txt")),
    *sorted(AC_CONFIG.glob("*/*/symbols.txt")),
]
TOKEN_FILES = [HOME / "Projects/nightfire-ps2/build/action.map",
               HOME / "Projects/nightfire-ps2/build/driving.map"]
TOKEN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$<>,.@:\-]*")


def elf_names(path):
    out = subprocess.run(["readelf", "-sW", str(path)], capture_output=True, text=True).stdout
    names = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[0].endswith(":") and parts[1] != "Value":
            names.add(parts[7])
    return names


def list_names(path):
    names = set()
    for line in Path(path).read_text(errors="replace").splitlines():
        head = line.split(" = ", 1)[0].strip()
        if head and not head.startswith("//"):
            names.add(head)
    return names


def token_names(path):
    return set(TOKEN.findall(Path(path).read_text(errors="replace")))


def collect(extra):
    sources = {}
    for p in ELF_SOURCES:
        if p.exists():
            sources[p.name] = elf_names(p)
    for p in SYMBOL_LISTS:
        if Path(p).exists():
            sources[f"{Path(p).parent.name}/symbols.txt"] = list_names(p)
    for p in TOKEN_FILES:
        if p.exists():
            sources[p.name] = token_names(p)
    for p in extra:
        sources[Path(p).name] = list_names(p)
    return sources


def run_dtk(dtk, names, jobs):
    def one(name):
        r = subprocess.run([dtk, "demangle", "--", name], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL)
        return name, (r.stdout.rstrip("\n") if r.returncode == 0 and r.stdout.strip() else None)

    with ThreadPoolExecutor(jobs) as pool:
        return dict(pool.map(one, names, chunksize=64))


def run_ours(ours, names, extensions=False):
    out = subprocess.run([ours, *(["--extensions"] if extensions else [])], input="\n".join(names) + "\n", capture_output=True,
                         text=True, check=True).stdout
    res = {}
    for line in out.splitlines():
        name, _, value = line.partition("\t")
        res[name] = None if value == "-" else value
    return res


def classify(name):
    if name.startswith("__vt__"):
        return "vtable"
    if name.startswith("__RTTI__"):
        return "rtti"
    if name.startswith("__ct__"):
        return "ctor"
    if name.startswith("__dt__"):
        return "dtor"
    if name.startswith("__op"):
        return "conversion-op"
    if re.match(r"^__[a-z]{1,3}__", name):
        return "operator"
    if "@" in name:
        return "thunk"
    if "<" in name:
        return "template"
    if "__Q" in name:
        return "qualified-scope"
    if re.search(r"__\d", name):
        return "member"
    if "__F" in name:
        return "free-fn"
    return "other"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dtk", default=str(AUF / "tools/dtk"))
    ap.add_argument("--ours", required=True, help="built `mwcc_demangle` example binary")
    ap.add_argument("--names", action="append", default=[], help="extra dtk symbols.txt-style list")
    ap.add_argument("--cache", default="/tmp/mwcc_demangle_dtk.json")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--min-agreement", type=float, default=0.99,
                    help="gate on agreement over the names either side demangles")
    ap.add_argument("--out")
    ap.add_argument("--examples", type=int, default=4)
    ap.add_argument("--list-sources", action="store_true")
    args = ap.parse_args()

    sources = collect(args.names)
    if args.list_sources:
        for k, v in sources.items():
            print(k, len(v))
        return 0
    names = sorted({n for v in sources.values() for n in v if "__" in n and "\n" not in n})
    cache = {}
    if Path(args.cache).exists():
        cache = json.loads(Path(args.cache).read_text())
    todo = [n for n in names if n not in cache]
    if todo:
        cache.update(run_dtk(args.dtk, todo, args.jobs))
        Path(args.cache).write_text(json.dumps(cache))
    theirs = {n: cache[n] for n in names}
    mine = run_ours(args.ours, names)

    stats = collections.defaultdict(collections.Counter)
    examples = collections.defaultdict(list)
    total = collections.Counter()
    for n in names:
        d, o = theirs[n], mine.get(n)
        if d is None and o is None:
            continue
        cls = classify(n)
        if d == o:
            verdict = "agree"
        elif d is None:
            verdict = "ours-only"
        elif o is None:
            verdict = "ours-refuses"
        else:
            verdict = "differs"
        stats[cls][verdict] += 1
        total[verdict] += 1
        if verdict != "agree" and len(examples[(cls, verdict)]) < args.examples:
            examples[(cls, verdict)].append({"name": n, "dtk": d, "ours": o})
    denom = sum(total.values())
    rate = total["agree"] / denom if denom else 0.0
    per_source = {}
    for src, ns in sources.items():
        c = collections.Counter()
        for n in ns:
            if n not in theirs:
                continue
            d, o = theirs[n], mine.get(n)
            if d is None and o is None:
                continue
            c["agree" if d == o else "disagree"] += 1
        per_source[src] = dict(c)

    print(f"names with '__': {len(names)}; dtk demangles {sum(1 for v in theirs.values() if v)}; "
          f"ours demangles {sum(1 for v in mine.values() if v)}")
    for cls, c in sorted(stats.items()):
        print(f"  {cls:16s} " + " ".join(f"{k}={v}" for k, v in sorted(c.items())))
    print(f"agreement {total['agree']}/{denom} = {rate:.4f}  {dict(total)}")
    for (cls, verdict), ex in sorted(examples.items()):
        print(f"  [{cls}/{verdict}]")
        for e in ex:
            print(f"    {e['name']}\n      dtk : {e['dtk']}\n      ours: {e['ours']}")
    # Extension dialect (T/N back-references): names dtk refuses that we decode.
    extended = run_ours(args.ours, names, extensions=True)
    extra = [n for n in names if theirs[n] is None and mine.get(n) is None and extended.get(n)]
    changed = [n for n in names if theirs[n] is not None and extended.get(n) != theirs[n]]
    print(f"extension dialect: decodes {len(extra)} more names dtk refuses "
          f"(e.g. {extra[0]} -> {extended[extra[0]]})" if extra else "extension dialect: no extra names")
    print(f"extension dialect changes {len(changed)} names dtk demangles")
    if args.out:
        Path(args.out).write_text(json.dumps({
            "extension_names": len(extra), "extension_changed": len(changed),
            "extension_examples": [{"name": n, "ours": extended[n]} for n in extra[:args.examples]],
            "names": len(names), "compared": denom, "agree": total["agree"],
            "agreement": rate, "classes": {k: dict(v) for k, v in stats.items()},
            "per_source": per_source,
            "examples": {f"{c}/{v}": e for (c, v), e in examples.items()},
        }, indent=2))
    return 0 if rate >= args.min_agreement else 1


if __name__ == "__main__":
    sys.exit(main())
