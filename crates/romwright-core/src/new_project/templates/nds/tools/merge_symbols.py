#!/usr/bin/env python3
"""Merge romwright's symbols into dsd's: merge_symbols.py

dsd's `init` wrote config/dsd/arm9/**/symbols.txt from its own analysis (and
delinks.txt, relocs.txt: the sections of every module and the relocations). romwright's
function inventory for the same ROM is in config/romwright/<module>.symbols.txt, in the
same grammar. This script, run once after `dsd init`:

* gives a dsd function the name romwright found for it (an imported symbol, a fact pack
  name) when dsd only has its default `func_...` name and romwright's is not a default
  too; the same for a data symbol;
* adds a function dsd did not find (unless `--no-add`), when it lies in a `.text` section, inside no
  dsd function, with no dsd symbol inside it, and keeps the mode romwright decoded;
* drops every relocation dsd could not attribute to one module (`module:overlays(...)`:
  an address that exists in several overlays). Left in, the linker would pick one of them
  and the rebuilt ROM would point a pointer table at the wrong overlay; without it the
  delinked object keeps the retail bytes.

The originals are kept as `*.dsd` next to the files and always the starting point, so
the script can be run again. It prints what it did as JSON.
"""
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DSD = ROOT / "config" / "dsd" / "arm9"
RW = ROOT / "config" / "romwright"
ADD = "--no-add" not in sys.argv
# The arguments may nest parentheses (`dsprot_range=(0x..,0x..)`), so they run to the last `)` before ` addr:`.
ROW = re.compile(r"^(?P<name>\S+) kind:(?P<kind>\w+)(?:\((?P<args>.*)\))? addr:0x(?P<addr>[0-9a-fA-F]+)(?P<rest>.*)$")
DEFAULT = re.compile(r"^(FUN|SUB|DAT|LAB|PTR|UNK|func|data|sub|thunk|sym|lab)[_0-9a-fA-F]*(_ov\d+)?(_[0-9a-fA-F]{6,8})?$|^(func|data|FUN|DAT)_(ov\d+_)?[0-9a-fA-F]{6,8}$")


def backup(path):
    original = path.with_name(path.name + ".dsd")
    if not original.exists():
        shutil.copyfile(path, original)
    return original.read_text()


def modules():
    """(name, symbols.txt, delinks.txt, relocs.txt) of every dsd module, in the order main, autoloads, overlays."""
    found = [("main", DSD / "symbols.txt", DSD / "delinks.txt", DSD / "relocs.txt")]
    for kind in ("itcm", "dtcm"):
        if (DSD / kind / "symbols.txt").exists():
            found.append((kind, DSD / kind / "symbols.txt", DSD / kind / "delinks.txt", DSD / kind / "relocs.txt"))
    for path in sorted(DSD.glob("autoload_*/symbols.txt")):
        found.append((path.parent.name, path, path.parent / "delinks.txt", path.parent / "relocs.txt"))
    for path in sorted((DSD / "overlays").glob("ov*/symbols.txt")):
        found.append((path.parent.name, path, path.parent / "delinks.txt", path.parent / "relocs.txt"))
    return found


def code_ranges(delinks_text):
    ranges = []
    for line in delinks_text.splitlines():
        match = re.match(r"^\s+\.\w+\s+start:0x([0-9a-f]+)\s+end:0x([0-9a-f]+)\s+kind:code", line)
        if match:
            ranges.append((int(match.group(1), 16), int(match.group(2), 16)))
    return ranges


def all_ranges(delinks_text):
    ranges = []
    for line in delinks_text.splitlines():
        match = re.match(r"^\s+\.\w+\s+start:0x([0-9a-f]+)\s+end:0x([0-9a-f]+)", line)
        if match:
            ranges.append((int(match.group(1), 16), int(match.group(2), 16)))
    return ranges


def parse_rows(text):
    rows = []
    for line in text.splitlines():
        match = ROW.match(line)
        if match:
            rows.append({"name": match["name"], "kind": match["kind"], "args": match["args"] or "", "addr": int(match["addr"], 16), "rest": match["rest"]})
        elif line.strip():
            # Never drop what we cannot read: a lost symbol changes how dsd delinks.
            raise SystemExit(f"merge_symbols: cannot parse symbol row: {line}")
    return rows


def render(row):
    args = f"({row['args']})" if row["args"] else ""
    return f"{row['name']} kind:{row['kind']}{args} addr:{row['addr']:#010x}{row['rest']}"


def main():
    report = {"renamed_functions": 0, "renamed_data": 0, "added_functions": 0, "skipped_mode_conflict": 0, "skipped_inside_dsd_function": 0,
              "skipped_not_code": 0, "skipped_conflict": 0, "dropped_ambiguous_relocations": 0, "dsd_functions": 0, "romwright_functions": 0,
              "romwright_functions_dsd_also_has": 0, "added": [], "candidates_not_added": 0}
    mods = modules()
    state = {}
    taken_names = set()
    for name, symbols, delinks, relocs in mods:
        rows = parse_rows(backup(symbols))
        state[name] = {"path": symbols, "rows": rows, "delinks": delinks.read_text() if delinks.exists() else "", "by_addr": {}}
        for row in rows:
            state[name]["by_addr"].setdefault(row["addr"], row)
            taken_names.add(row["name"])
        report["dsd_functions"] += sum(1 for r in rows if r["kind"] == "function")
        # Ambiguous relocations.
        if relocs.exists():
            text = backup(relocs)
            lines = text.splitlines(keepends=True)
            kept = [l for l in lines if "module:overlays(" not in l]
            report["dropped_ambiguous_relocations"] += len(lines) - len(kept)
            relocs.write_text("".join(kept))
    # romwright rows, by module: main's go to whichever of main/itcm/dtcm/autoloads covers the address.
    for rw_file in sorted(RW.glob("*.symbols.txt")):
        module = rw_file.name[: -len(".symbols.txt")]
        if module == "arm7" or module.startswith("arm7"):
            continue  # dsd has no ARM7 support: the program stays a binary in the extract
        targets = [module] if module != "main" else [n for n in state if not n.startswith("ov")]
        for row in parse_rows(rw_file.read_text()):
            target = None
            for candidate in targets:
                if candidate in state and any(a <= row["addr"] < b for a, b in all_ranges(state[candidate]["delinks"])):
                    target = candidate
                    break
            if target is None:
                report["skipped_not_code"] += 1
                continue
            module_state = state[target]
            rows = module_state["rows"]
            by_addr = module_state["by_addr"]
            if row["kind"] == "function":
                report["romwright_functions"] += 1
                size = int(re.search(r"size=0x([0-9a-f]+)", row["args"]).group(1), 16)
                mode = row["args"].split(",")[0]
                existing = by_addr.get(row["addr"])
                if existing is not None:
                    if existing["kind"] != "function":
                        report["skipped_conflict"] += 1
                        continue
                    report["romwright_functions_dsd_also_has"] += 1
                    if existing["args"].split(",")[0] != mode:
                        report["skipped_mode_conflict"] += 1
                        continue
                    if DEFAULT.match(existing["name"]) and not DEFAULT.match(row["name"]) and row["name"] not in taken_names:
                        taken_names.discard(existing["name"])
                        existing["name"] = row["name"]
                        taken_names.add(row["name"])
                        report["renamed_functions"] += 1
                    continue
                if not any(a <= row["addr"] < b for a, b in code_ranges(module_state["delinks"])):
                    report["skipped_not_code"] += 1
                    continue
                # Inside a dsd function, or a dsd symbol inside this one: leave it to dsd.
                inside = any(r["kind"] == "function" and r["addr"] < row["addr"] < r["addr"] + int(re.search(r"size=0x([0-9a-f]+)", r["args"]).group(1), 16) for r in rows if "size=" in r["args"])
                if inside:
                    report["skipped_inside_dsd_function"] += 1
                    continue
                if any(row["addr"] < r["addr"] < row["addr"] + size for r in rows):
                    report["skipped_conflict"] += 1
                    continue
                if not ADD:
                    report["candidates_not_added"] += 1
                    continue
                name = row["name"]
                if name in taken_names:
                    name = f"{name}_{row['addr']:08x}"
                if name in taken_names:
                    report["skipped_conflict"] += 1
                    continue
                new = {"name": name, "kind": "function", "args": row["args"], "addr": row["addr"], "rest": ""}
                rows.append(new)
                by_addr[row["addr"]] = new
                taken_names.add(name)
                report["added_functions"] += 1
                report["added"].append(name)
            else:
                existing = by_addr.get(row["addr"])
                if existing is not None and existing["kind"] == "data" and DEFAULT.match(existing["name"]) and not DEFAULT.match(row["name"]) and row["name"] not in taken_names:
                    taken_names.discard(existing["name"])
                    existing["name"] = row["name"]
                    taken_names.add(row["name"])
                    report["renamed_data"] += 1
    for name, module_state in state.items():
        rows = sorted(module_state["rows"], key=lambda r: r["addr"])
        module_state["path"].write_text("".join(render(r) + "\n" for r in rows))
    print(json.dumps(report))


if __name__ == "__main__":
    main()
