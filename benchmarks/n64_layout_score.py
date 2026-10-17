#!/usr/bin/env python3
"""N64 layout discovery score: an import of a staged N64 ROM against its matching-decomp truth.

Truth is scoring-only; it never reaches the importer. For one staged image `<corpus>/n64-<slug>/`
this reads

* `truth/layout.json` -- every resident segment and overlay (ROM range, codec, vram, decoded size);
* `truth/functions.tsv` -- function starts (VRAM link addresses) with their module (`main` = the
  resident segments, else an overlay name);

and an import project (`romwright-cli import ROM --name n64 --project DIR`: the main program `n64`
and, for overlays that share addresses, one program `n64.<overlay>` each), and reports

layout recovery, per truth segment, by the segment of the import that carries its ROM start:

* `found`       the import places it at the truth's vram (exact: the import's segment starts at the
                truth's ROM start; linear: the import maps the ROM linearly and the truth range lies
                inside that mapping at the same offset);
* `size_exact`  found, and the import's segment has the truth's decoded size;
* `wrong_vram`  an import segment starts at the truth's ROM start at another vram. Must be 0;
* `extra`       segments of the import that start where no truth segment does (reported, and kept
                out of recall; their functions count against precision);

function recall and precision per module class, `main` (truth module `main`) and `overlay`:

* a truth function is recalled when the import has a function at its address in a segment that
  places the truth segment the function belongs to;
* precision is, over the functions of the import's segments of that class, the share the truth
  lists at that address (`overlay`: in the truth overlay the segment places). The linear view's one
  code segment is class `main`: every function it finds counts, in or out of a truth range.

The importer's own classification is not trusted: class comes from the truth segment a segment
places, else from the module `kind`.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path


def hexint(text) -> int:
    return text if isinstance(text, int) else int(text, 16)


def load_truth(truth_dir: Path):
    layout = json.loads((truth_dir / "layout.json").read_text())
    meta = json.loads((truth_dir / "meta.json").read_text())
    # A segment the truth places at "boot" runs where the truth's `main` module is loaded.
    boot = hexint(next(m["load_address"] for m in meta["modules"] if m["name"] == "main"))
    segments = []
    for segment in layout["segments"]:
        place = segment["place"]
        vram = hexint(place["at"]) if isinstance(place, dict) and "at" in place else boot if place == "boot" else None
        parts = segment["parts"]
        segments.append({
            "name": segment["name"],
            "vram": vram,
            "boot": place == "boot",
            "size": hexint(segment["size"]),
            "rom": (hexint(parts[0]["rom"][0]), hexint(parts[-1]["rom"][1])),
            "codec": parts[0]["codec"],
            "overlay": segment.get("kind") == "overlay",
        })
    functions = []
    for line in (truth_dir / "functions.tsv").read_text(errors="replace").splitlines()[1:]:
        if line.strip():
            start, size, name, module, _verified = line.split("\t")
            functions.append({"start": int(start, 16), "size": int(size), "name": name, "module": module})
    return segments, functions


def read_project(project: Path):
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    programs = {pid: name for pid, name in db.execute("SELECT id, name FROM programs")}
    modules = []
    for pid, name, kind, load, size, off in db.execute(
            "SELECT program_id, name, kind, load_vaddr, size, file_off FROM modules"):
        if kind in ("code", "overlay"):
            modules.append({"program": pid, "name": name, "kind": kind, "vram": int(load, 16), "size": size,
                            "off": off})
    functions: dict[int, set[int]] = {}
    for pid, entry in db.execute("SELECT program_id, entry FROM functions"):
        try:
            functions.setdefault(pid, set()).add(int(entry, 16))
        except ValueError:
            pass
    return programs, modules, functions


def place(seg: dict, mod: dict, packed_ok: bool = True):
    """How `mod` carries `seg`: ('exact'|'linear', vram_ok), or None when it does not carry its start."""
    if mod["off"] == seg["rom"][0]:
        return "exact", mod["vram"] == seg["vram"]
    if seg["codec"] == "raw" and mod["off"] < seg["rom"][0] < mod["off"] + mod["size"]:
        # mapped linearly from the ROM: the segment lies inside at the same offset
        return "linear", mod["vram"] + (seg["rom"][0] - mod["off"]) == seg["vram"]
    return None


def score(corpus: Path, slug: str, project: Path) -> dict:
    image_dir = corpus / f"n64-{slug}"
    truth_segments, truth_functions = load_truth(image_dir / "truth")
    programs, modules, functions = read_project(project)

    layout = {"truth": len(truth_segments), "found": 0, "size_exact": 0, "wrong_vram": 0,
              "truth_resident": 0, "found_resident": 0, "truth_overlay": 0, "found_overlay": 0,
              "partial_linear": 0, "wrong_list": []}
    placements: dict[str, list[tuple[dict, str]]] = {}  # truth segment name -> [(module, how)]
    carried: set[int] = set()  # id()s of modules that place some truth segment
    shifted: dict[str, list[tuple[dict, int]]] = {}  # truth segment name -> [(module, vram offset)]
    for seg in truth_segments:
        klass = "overlay" if seg["overlay"] else "resident"
        layout["truth_" + klass] += 1
        found = None
        wrong: list[str] = []
        shifted_here: list[tuple[dict, int]] = []
        for mod in modules:
            how = place(seg, mod)
            if how is None:
                continue
            kind, vram_ok = how
            if kind == "exact" and not vram_ok:
                wrong.append(f"{seg['name']}: {mod['vram']:#x} (truth {seg['vram']:#x})")
                shifted_here.append((mod, mod["vram"] - seg["vram"]))
            elif vram_ok:
                if kind == "linear" and mod["off"] + mod["size"] < seg["rom"][1]:
                    # starts right, the mapping stops short: found when it covers 90% or more
                    covered = (mod["off"] + mod["size"] - seg["rom"][0]) / (seg["rom"][1] - seg["rom"][0])
                    if covered < 0.9:
                        layout["partial_linear"] += 1
                        placements.setdefault(seg["name"], []).append((mod, kind))
                        carried.add(id(mod))
                        continue
                found = (mod, kind)
                placements.setdefault(seg["name"], []).append((mod, kind))
                carried.add(id(mod))
        if not found and wrong:  # another module may carry it right (PD's lib-boot copy at the raw address)
            layout["wrong_vram"] += len(wrong)
            layout["wrong_list"].extend(wrong)
            shifted.setdefault(seg["name"], []).extend(shifted_here)
        if found:
            layout["found"] += 1
            layout["found_" + klass] += 1
            mod, kind = found
            if kind == "exact" and mod["size"] == seg["size"]:
                layout["size_exact"] += 1
    extra = [m for m in modules if id(m) not in carried]
    layout["extra_segments"] = len(extra)
    layout["extra_sample"] = [f"{m['name']}@{m['vram']:#x}" for m in extra[:6]]

    # --- functions -----------------------------------------------------------------------
    resident_names = [s["name"] for s in truth_segments if not s["overlay"]]
    seg_by_name = {s["name"]: s for s in truth_segments}
    truth_by_module: dict[str, list[dict]] = {}
    for fn in truth_functions:
        truth_by_module.setdefault(fn["module"], []).append(fn)

    def hit(fn: dict, names: list[str]) -> bool:
        for name in names:
            seg = seg_by_name.get(name)
            if seg is None:
                continue
            for mod, _how in placements.get(name, []):
                if mod["vram"] <= fn["start"] < mod["vram"] + mod["size"] and fn["start"] in functions.get(mod["program"], ()):
                    return True
        return False

    recall = {"main": {"truth": 0, "found": 0}, "overlay": {"truth": 0, "found": 0}}
    for module, rows in truth_by_module.items():
        klass = "main" if module == "main" else "overlay"
        names = resident_names if module == "main" else [module]
        for fn in rows:
            recall[klass]["truth"] += 1
            recall[klass]["found"] += hit(fn, names)

    # Truth function addresses by the truth segment that a module places.
    truth_addr_main = {fn["start"] for fn in truth_by_module.get("main", [])}
    owner: dict[int, str] = {}
    for name, items in placements.items():
        for mod, _ in items:
            owner[id(mod)] = name
    precision = {"main": {"total": 0, "true": 0}, "overlay": {"total": 0, "true": 0}}
    extra_functions = 0
    for mod in modules:
        addrs = [a for a in functions.get(mod["program"], ()) if mod["vram"] <= a < mod["vram"] + mod["size"]]
        name = owner.get(id(mod))
        if name is None:
            # a segment that places no truth segment: its functions are reported, not scored
            extra_functions += len(addrs)
            continue
        klass = "overlay" if seg_by_name[name]["overlay"] else "main"
        truth_set = {fn["start"] for fn in truth_by_module.get(name, [])} if klass == "overlay" else truth_addr_main
        precision[klass]["total"] += len(addrs)
        precision[klass]["true"] += sum(1 for a in addrs if a in truth_set)

    rebased = None
    if shifted:
        # Segments the import places at another vram than the truth lists (a truth built from another
        # revision of the game than the ROM: Star Fox 64's overlays). The ROM's bytes decide the
        # address; score the functions at the truth address plus that offset, and say what the
        # offsets are.
        recall_r = {"truth": 0, "found": 0}
        precision_r = {"total": 0, "true": 0}
        deltas = set()
        for name, items in shifted.items():
            for mod, delta in items:
                deltas.add(delta)
                rows = truth_by_module.get(name, [])
                found_here = functions.get(mod["program"], set())
                recall_r["truth"] += len(rows)
                recall_r["found"] += sum(1 for fn in rows if (fn["start"] + delta) in found_here
                                         and mod["vram"] <= fn["start"] + delta < mod["vram"] + mod["size"])
                truth_set = {fn["start"] + delta for fn in rows}
                addrs = [a for a in found_here if mod["vram"] <= a < mod["vram"] + mod["size"]]
                precision_r["total"] += len(addrs)
                precision_r["true"] += sum(1 for a in addrs if a in truth_set)
        rebased = {
            "segments": sum(len(v) for v in shifted.values()),
            "offsets": sorted(f"{d:+#x}" for d in deltas),
            "recall": {**recall_r, "recall": round(recall_r["found"] / recall_r["truth"], 4) if recall_r["truth"] else None},
            "precision": {**precision_r, "precision": round(precision_r["true"] / precision_r["total"], 4) if precision_r["total"] else None},
        }
    return {
        "slug": slug,
        "programs": len(programs),
        "functions_total": sum(len(v) for v in functions.values()),
        "segments_in_import": len(modules),
        "extra_functions": extra_functions,
        "layout": layout,
        "recall": {k: {**v, "recall": round(v["found"] / v["truth"], 4) if v["truth"] else None} for k, v in recall.items()},
        "precision": {k: {**v, "precision": round(v["true"] / v["total"], 4) if v["total"] else None} for k, v in precision.items()},
        "rebased_wrong_vram": rebased,
    }


def timing(directory: Path | None, slug: str) -> dict | None:
    """The wall time and load average `n64_layout_run.py` recorded for one import (`<slug>.json`)."""
    path = directory / f"{slug}.json" if directory else None
    if path is None or not path.is_file():
        return None
    row = json.loads(path.read_text())
    return {"wall_s": row["wall_s"], "load_before": round(row["load_before"], 1),
            "load_after": round(row["load_after"], 1), "degraded": row["degraded"]}


def table(report: list[dict]) -> str:
    """One row per game: before / after, as markdown."""
    fmt = lambda x: "-" if x is None else f"{x:.3f}"
    head = ("| game | segments found (resident+overlay) / truth, size exact | wrong vram | main R / P | overlay R / P "
            "| functions | import s (load before→after) |\n|---|---|---|---|---|---|---|\n")
    lines = []
    for row in report:
        cells = []
        for side in ("before", "after"):
            r = row[side]
            if r is None:
                cells.append(None)
                continue
            lay = r["layout"]
            t = row.get("timing_" + side)
            cells.append((
                f"{lay['found']} ({lay['found_resident']}+{lay['found_overlay']}) / {lay['truth']}, {lay['size_exact']}",
                str(lay["wrong_vram"]),
                f"{fmt(r['recall']['main']['recall'])} / {fmt(r['precision']['main']['precision'])}",
                f"{fmt(r['recall']['overlay']['recall'])} / {fmt(r['precision']['overlay']['precision'])}",
                str(r["functions_total"]),
                f"{t['wall_s']:.0f} ({t['load_before']}→{t['load_after']})" if t else "-",
            ))
        joined = " | ".join(f"{b} → {a}" for b, a in zip(cells[0], cells[1]))
        lines.append(f"| {row['slug']} | {joined} |")
    return head + "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True, help="directory holding n64-<slug>/ staged images")
    parser.add_argument("--projects", type=Path, required=True,
                        help="directory holding one import project per slug (the 'after' side)")
    parser.add_argument("--before", type=Path, help="the same, for the baseline importer: score both and compare")
    parser.add_argument("--timings", type=Path, help="directory of `<slug>.json` timing files for --projects")
    parser.add_argument("--timings-before", type=Path, help="the same for --before")
    parser.add_argument("slugs", nargs="+")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--table", action="store_true", help="with --before, print the markdown table")
    args = parser.parse_args()
    if args.table and args.before is None:
        parser.error("--table compares two imports: give --before")
    rows = []
    for slug in args.slugs:
        after = score(args.corpus, slug, args.projects / slug)
        if args.before is None:
            rows.append(after)
            print(json.dumps(after))
            continue
        rows.append({
            "slug": slug,
            "before": score(args.corpus, slug, args.before / slug),
            "after": after,
            "timing_before": timing(args.timings_before, slug),
            "timing_after": timing(args.timings, slug),
        })
    if args.table:
        print(table(rows))
    if args.out:
        args.out.write_text(json.dumps(rows, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
