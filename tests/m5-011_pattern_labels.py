#!/usr/bin/env python3
"""m5-011: a function proven by a labelled pattern carries that label.

The pinned install ships byte patterns with names attached, for example

    <pattern><data>0x8b 0x1c 0x24 0xc3</data>
      <funcstart label="__i686.get_pc_thunk.bx" validcode="function"/></pattern>

in `Ghidra/Processors/x86/data/patterns/x86gcc_patterns.xml`. Ventris already
matches those patterns and already uses their labels to install call fixups in
the decompiler console (`ConsoleSession::send_reference_fixups`) -- it just
never wrote the name into the store, which left eleven `__i686.get_pc_thunk.*`
rows pinned in `tests/m5-010_initializer_names.py`.

The gate reads the labelled patterns out of the install, reads the bytes at
each of our function entries out of the binary, and requires the two to agree
in both directions:

  * bytes match a labelled pattern and no symbol names the address -> the
    function must carry the label (`missing` = 0);
  * function carries a pattern label -> the bytes at its entry must match that
    label's pattern (`spurious` = 0).

Stock Ghidra's name at the same address must agree, so the label is checked
against the tool that ships the pattern as well as against the bytes.

Usage:
    python3 tests/m5-011_pattern_labels.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

THRESHOLDS = {"pattern.label.missing": 0, "pattern.label.spurious": 0}

# Which processor's pattern files apply to a corpus architecture.
PROCESSORS = {"x86_64": "x86", "i386": "x86", "aarch64": "AARCH64",
              "powerpc": "PowerPC"}
HEX = re.compile(r"^0x[0-9a-fA-F]{2}$")


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def labelled_patterns(install: Path, processor: str) -> list[tuple[bytes, str]]:
    """Every fully specified byte pattern that names the function it starts."""
    found: list[tuple[bytes, str]] = []
    directory = install / "Ghidra" / "Processors" / processor / "data" / "patterns"
    for path in sorted(directory.glob("*.xml")):
        try:
            tree = ElementTree.parse(path)
        except ElementTree.ParseError:
            continue
        for pattern in tree.iter("pattern"):
            action = pattern.find("funcstart")
            if action is None:
                continue
            label = action.get("label")
            if not label or action.get("validcode") != "function":
                continue
            data = pattern.find("data")
            if data is None or data.text is None:
                continue
            tokens = data.text.split()
            # A masked token cannot be compared byte for byte; a labelled
            # pattern with one would need the matcher itself, so it is skipped
            # and counted rather than approximated.
            if not tokens or not all(HEX.match(token) for token in tokens):
                continue
            found.append((bytes(int(token, 16) for token in tokens), label))
    return found


def image_reader(binary: Path):
    """Map a link-time virtual address to the bytes at that address."""
    data = binary.read_bytes()
    width = 8 if data[4] == 2 else 4
    order = ">" if data[5] == 2 else "<"
    pack = "Q" if width == 8 else "I"
    if width == 8:
        phoff = struct.unpack_from(f"{order}Q", data, 32)[0]
        phentsize = struct.unpack_from(f"{order}H", data, 54)[0]
        phnum = struct.unpack_from(f"{order}H", data, 56)[0]
    else:
        phoff = struct.unpack_from(f"{order}I", data, 28)[0]
        phentsize = struct.unpack_from(f"{order}H", data, 42)[0]
        phnum = struct.unpack_from(f"{order}H", data, 44)[0]
    entry = struct.unpack_from(f"{order}{pack}", data, 24)[0]
    loads = []
    for index in range(phnum):
        header = phoff + index * phentsize
        if struct.unpack_from(f"{order}I", data, header)[0] != 1:
            continue
        if width == 8:
            offset = struct.unpack_from(f"{order}Q", data, header + 8)[0]
            vaddr = struct.unpack_from(f"{order}Q", data, header + 16)[0]
            size = struct.unpack_from(f"{order}Q", data, header + 32)[0]
        else:
            offset = struct.unpack_from(f"{order}I", data, header + 4)[0]
            vaddr = struct.unpack_from(f"{order}I", data, header + 8)[0]
            size = struct.unpack_from(f"{order}I", data, header + 16)[0]
        loads.append((vaddr, offset, size))

    def read(vaddr: int, count: int) -> bytes | None:
        for start, offset, size in loads:
            if start <= vaddr and vaddr - start + count <= size:
                position = offset + (vaddr - start)
                return data[position:position + count]
        return None

    return entry, read


def score(identifier: str, binary: Path, patterns: list[tuple[bytes, str]],
          native: dict, stock: dict[int, str]) -> dict:
    entry, read = image_reader(binary)
    bias = next((address for address, name in native["functions"].items()
                 if name == "entry"), None)
    assert bias is not None, f"{identifier}: no entry function to anchor the bias"
    bias -= entry
    by_label: dict[str, list[bytes]] = {}
    for shape, label in patterns:
        by_label.setdefault(label, []).append(shape)

    applied, missing, spurious, disagreed = [], [], [], []
    for address, name in sorted(native["functions"].items()):
        symbol_named = name in native["symbols"].get(address, set())
        matched = None
        for shape, label in patterns:
            head = read(address - bias, len(shape))
            if head == shape:
                matched = label
                break
        if matched and not symbol_named:
            if name == matched:
                applied.append({"address": f"{address:08x}", "label": matched})
                if stock.get(address) not in (None, matched):
                    disagreed.append({"address": f"{address:08x}", "ours": name,
                                      "stock": stock.get(address)})
            else:
                missing.append({"address": f"{address:08x}", "label": matched,
                                "ours": name})
        elif name in by_label:
            head = read(address - bias, max(len(shape) for shape in by_label[name]))
            if not any(head is not None and head.startswith(shape)
                       for shape in by_label[name]):
                spurious.append({"address": f"{address:08x}", "name": name})
    return {"id": identifier, "applied": applied, "missing": missing,
            "spurious": spurious, "disagreed": disagreed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--ghidra", type=Path, default=Path(os.environ.get(
        "VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    report = {"id": "m5-011", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": THRESHOLDS, "status": "skipped"}
    if not (arguments.ghidra / "support/analyzeHeadless").is_file():
        report["reason"] = f"no pinned Ghidra install at {arguments.ghidra}"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    helpers = load_module("m5_010", ROOT / "tests" / "m5-010_initializer_names.py")
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/lre-cli"
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())

    rows, totals = [], {"applied": 0, "missing": 0, "spurious": 0, "disagreed": 0}
    for entry in manifest["entries"]:
        if entry.get("status") != "ok":
            continue
        identifier = f"{entry['architecture']}_{entry['variant']}"
        processor = PROCESSORS.get(entry["architecture"])
        assert processor, f"{identifier}: no pattern directory mapped"
        patterns = labelled_patterns(arguments.ghidra, processor)
        binary = arguments.corpus_dir / entry["binary"]
        with tempfile.TemporaryDirectory(prefix="m5-011-") as temporary:
            work = Path(temporary)
            native = helpers.native_facts(cli, binary, work, arguments.timeout)
            stock = helpers.stock_names(arguments.ghidra, binary, work, arguments.timeout)
        row = score(identifier, binary, patterns, native, stock)
        rows.append(row)
        for key in ("applied", "missing", "spurious", "disagreed"):
            totals[key] += len(row[key])

        assert not row["missing"], (
            f"{identifier}: bytes match a labelled pattern but the function does not "
            f"carry its name: {row['missing']}")
        assert not row["spurious"], (
            f"{identifier}: functions carry a pattern label their bytes do not "
            f"match: {row['spurious']}")
        assert not row["disagreed"], (
            f"{identifier}: applied a label stock Ghidra does not use: "
            f"{row['disagreed']}")

    assert len(rows) >= 20, f"only {len(rows)} corpus entries were scored"
    assert totals["applied"] >= 11, (
        f"only {totals['applied']} pattern labels were applied; the corpus carries "
        f"eleven get_pc_thunk functions, so a lower number means the pass is not "
        f"running")
    metrics = {"pattern.label.applied": totals["applied"],
               "pattern.label.missing": totals["missing"],
               "pattern.label.spurious": totals["spurious"],
               "pattern.label.disagreed": totals["disagreed"]}
    for name, threshold in THRESHOLDS.items():
        assert metrics[name] <= threshold, f"{name} is {metrics[name]}"

    # The class this task closes must be gone from m5-010's pinned set.
    pinned = getattr(helpers, "PATTERN_LABELS", {})
    assert not pinned, (
        f"tests/m5-010_initializer_names.py still pins pattern-label rows: {pinned}")

    summary = (f"{len(rows)} corpus entries: {totals['applied']} pattern labels "
               f"applied and agreed with stock, 0 missing, 0 spurious")
    if arguments.report:
        report.update(status="pass", passed=True, summary=summary, metrics=metrics,
                      totals=totals, corpus=rows)
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"m5-011: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
