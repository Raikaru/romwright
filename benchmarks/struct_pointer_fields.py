#!/usr/bin/env python3
"""How inferred struct pointer fields are typed in the printed C: pointee struct, scalar pointee, or `void *`.

For every address of a list, `romwright-cli export-c --address` is run on its own copy of a project (the struct pass writes
layouts to the store) and the `struct fn_<entry>_arg<n> { ... };` definitions the printed text carries are read. A field line
is `    <type> field_0x<offset>; /* +0x<offset> */`; a field is a pointer when its type ends in `*`. Per run:

  structs            definitions printed (a struct is counted once per function that prints it)
  pointer fields     fields whose type is a pointer, by kind:
    struct pointee   `fn_<entry>_arg<n>_p<offset> *` (a second inferred struct holds what was accessed through it)
    scalar pointee   `float *`, `int *`, `unsigned short *`, ... (`ROMWRIGHT_STRUCT_POINTEE_RUNS` types a run of one scalar this way)
    void *           a pointer nothing proved a pointee of

    python3 benchmarks/struct_pointer_fields.py --cli CLI --project DIR --binary IMAGE --program NAME --addresses FILE \
        --env KEY=VALUE ... --jobs 4 --out OUT.json
"""
import argparse
import collections
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

STRUCT = re.compile(r"^struct (fn_[0-9a-f]+_arg\d+(?:_p\d+)?) \{\n(.*?)^\};", re.S | re.M)
FIELD_NAMED = re.compile(r"^\s+(.+?)\s*(field_0x[0-9a-f]+);")
POINTER_CAST_OF_FIELD = re.compile(r"\(\s*[A-Za-z_][\w ]*\*+\s*\)\s*[\(\w\s\*\)]{0,60}?->\s*field_0x([0-9a-f]+)")


def kind(spelled: str) -> str | None:
    spelled = spelled.strip()
    if not spelled.endswith("*"):
        return None
    if re.fullmatch(r"fn_[0-9a-f]+_arg\d+_p\d+ \*", spelled):
        return "struct pointee"
    if spelled in ("void *", "code *"):
        return "void *"
    return "scalar pointee"


def one(cli, project, binary, program, address, env):
    with tempfile.TemporaryDirectory(prefix="ptrfields-") as temporary:
        copy = Path(temporary) / "project"
        shutil.copytree(project, copy)
        out = Path(temporary) / "out"
        result = subprocess.run([str(cli), "export-c", binary, program, str(out), "--address", f"{address:x}", "--project", str(copy)],
                                capture_output=True, text=True, timeout=900, env=env)
        files = sorted(out.glob("*.c")) if out.exists() else []
        if result.returncode != 0 or not files:
            return None
        return "\n".join(f.read_text(errors="replace") for f in files)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--program", required=True)
    parser.add_argument("--addresses", type=Path, required=True, help="one hex address per line")
    parser.add_argument("--env", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROMWRIGHT_") or k in ("ROMWRIGHT_GHIDRA", "ROMWRIGHT_WORKER", "ROMWRIGHT_GHIDRA_OPT")}
    env.update(ROMWRIGHT_NO_IMPORT_CACHE="1", ROMWRIGHT_NO_FACT_PACK="1")
    env.update(item.split("=", 1) for item in args.env)
    addresses = [int(line.strip(), 16) for line in args.addresses.read_text().split() if line.strip()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        texts = list(pool.map(lambda a: one(args.cli, args.project, args.binary, args.program, a, env), addresses))
    counts: collections.Counter[str] = collections.Counter()
    types: collections.Counter[str] = collections.Counter()
    structs = 0
    functions_with_pointer_field = 0
    cast_uses: set = set()
    for text in texts:
        if text is None:
            counts["failed"] += 1
            continue
        found = False
        for match in STRUCT.finditer(text):
            structs += 1
            declared = {}
            for line in match.group(2).splitlines():
                field = FIELD_NAMED.match(line)
                if field:
                    declared[field.group(2)] = field.group(1).strip()
            for spelled in declared.values():
                counts["fields"] += 1
                k = kind(spelled)
                if k:
                    counts[k] += 1
                    found = True
                    if k == "scalar pointee":
                        types[spelled] += 1
            # a field not declared a pointer that the body casts to a pointer type where it reads it
            body = text[match.end():]
            for use in POINTER_CAST_OF_FIELD.finditer(body):
                name = f"field_0x{use.group(1)}"
                if name in declared and kind(declared[name]) is None:
                    cast_uses.add((match.group(1), name))
        functions_with_pointer_field += found
    counts["non-pointer fields read through a pointer cast"] = len(cast_uses)
    report = {"addresses": len(addresses), "env": args.env, "structs_printed": structs, "pointer_fields": dict(counts),
              "functions_with_a_pointer_field": functions_with_pointer_field, "scalar_pointee_types": dict(types.most_common(12))}
    args.out.write_text(json.dumps(report, indent=1))
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
