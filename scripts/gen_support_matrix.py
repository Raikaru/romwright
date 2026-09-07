#!/usr/bin/env python3
"""Generate or check the README support matrix from committed gate files.

Usage:
    python scripts/gen_support_matrix.py          # Updates README.md in-place
    python scripts/gen_support_matrix.py --check  # Fails if README matrix is stale
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
REPORTS_DIR = ROOT / "benchmarks" / "reports"
CATALOG = ROOT / "docs" / "platform-tiers.json"

# The generated block is delimited so two tables can be regenerated together
# without a regex guessing where the hand-written prose starts.
BEGIN = "<!-- support-matrix:begin -->"
END = "<!-- support-matrix:end -->"


def load_json(path: Path) -> dict | list | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def generate_matrix() -> str:
    # Read available gate files
    stage4 = load_json(REPORTS_DIR / "stage4-gate.json")
    ui_gate = load_json(REPORTS_DIR / "ui-gate.json")
    discovery_gate = load_json(REPORTS_DIR / "discovery-gate.json")
    pe_gate = load_json(REPORTS_DIR / "m8-001.json")
    parity_gate = load_json(REPORTS_DIR / "parity-gate.json")

    # x86-64 ELF is verified if stage4 or ui_gate passed
    elf_x86_gated = bool(
        (stage4 and stage4.get("functional_pass"))
        or (ui_gate and ui_gate.get("passed"))
    )

    # PE32+ x86-64 is scored against DWARF truth read from the PE container.
    pe_status = "in progress"
    if pe_gate and pe_gate.get("passed"):
        recall = pe_gate["totals"]["pe.dwarf.fn.recall"]
        functions = sum(row["truth"] for row in pe_gate["gated"])
        pe_status = (f"**gated**: DWARF recall {recall:.4f} over {functions} "
                     f"functions, {pe_gate['totals']['pe.runtime_functions']} "
                     f"`RUNTIME_FUNCTION` records (`tests/m8-001_pe_unwind.py`)")
    elif stage4 and stage4.get("functional_pass"):
        pe_status = "supported and exercised; not scored against truth"

    # PE32 x86 has no exception directory: it is gated on precision and on
    # beating stock Ghidra, which reads the same absent evidence.
    pe32_status = "structural import only; no gate"
    pe32_gate = load_json(REPORTS_DIR / "m8-002.json")
    pe32_recorded = next((row for row in (pe_gate or {}).get("recorded", [])
                          if row["id"] == "tiny_pe32.exe"), None)
    if pe32_gate and pe32_gate.get("passed"):
        pe32_metrics = pe32_gate["metrics"]
        stock = pe32_metrics.get("ghidra.dwarf.fn.recall")
        pe32_status = (
            f"**gated**: DWARF recall "
            f"{pe32_metrics['pe32.dwarf.fn.recall']:.4f} over "
            f"{pe32_gate['truth']} functions, 0 unattributed"
            + (f", stock Ghidra {stock:.4f} on the same image" if stock else "")
            + " (`tests/m8-002_pe32_roots.py`)")
    elif pe32_recorded:
        pe32_status = (
            f"recorded, not gated: DWARF recall "
            f"{pe32_recorded['metrics']['pe.dwarf.fn.recall']:.4f} over "
            f"{pe32_recorded['truth']} functions with no exception directory "
            f"to prove starts (`benchmarks/reports/m8-001.json`)")

    # Generic architectures (M1/M2 gates)
    aarch64_status = "selected SLEIGH bundle required; not parity-gated"
    arm_status = "selected SLEIGH bundle required; not parity-gated"
    mips_status = "selected SLEIGH bundle required; not parity-gated"
    riscv_status = "no spec bundle in native/specs and no corpus row; unmeasured"
    ppc_status = (
        "e500 BE32 parity verified on Agent Under Fire; broader targets not gated"
    )

    if parity_gate and parity_gate.get("passed"):
        aarch64_status = "**supported and gated**"
        arm_status = "**supported and gated**"
        mips_status = "**supported and gated**"
        riscv_status = "**supported and gated**"
        ppc_status = "**supported and gated**"
    elif discovery_gate and discovery_gate.get("passed"):
        aarch64_status = "discovery gated; decompile parity pending"
        ppc_status = "BE32 discovery gated; e500 parity verified; other configurations not gated"

    # Token identity against the JVM oracle, per language (m4-003).
    language_parity = load_json(REPORTS_DIR / "m4-003.json")
    x86_status = "**supported and gated**" if elf_x86_gated else "in progress"
    x86_32_status = "supported; parity unmeasured"
    if language_parity and language_parity.get("passed"):
        def parity(language: str) -> str | None:
            row = next((item for item in language_parity["measured"]
                        if item["language"] == language), None)
            if row is None:
                note = language_parity["blocked"].get(language)
                return f"no oracle comparison: {note['reason']}" if note else None
            compared = len(row["identical"]) + len(row["attributed"])
            return (f"**parity measured**: {len(row['identical'])} of {compared} "
                    f"functions token-identical to the JVM oracle, the rest "
                    f"attributed to named facts "
                    f"(`tests/m4-003_language_parity.py`)")
        x86_status = f"{x86_status}; {parity('x86:LE:64:default')}"
        x86_32_status = parity("x86:LE:32:default") or x86_32_status
        aarch64_status = parity("AARCH64:LE:64:v8A") or aarch64_status
        arm_status = parity("ARM:LE:32:v4t") or arm_status
        mips_status = parity("MIPS:LE:32:default") or mips_status
        ppc_status = f"{parity('PowerPC:BE:32:default')}; e500 verified on Agent Under Fire"

    rows = [
        ("ELF x86-64", "supported", x86_status),
        ("ELF x86-32", "supported", x86_32_status),
        ("PE32+ x86-64", "supported", pe_status),
        ("PE32 x86", "supported", pe32_status),
        ("ELF AARCH64 LE64", "supported", aarch64_status),
        ("ELF ARM LE32", "supported", arm_status),
        ("ELF MIPS LE32", "supported", mips_status),
        ("ELF RISC-V LE64", "supported", riscv_status),
        ("ELF PowerPC", "supported", ppc_status),
    ] + console_rows()

    header = [
        "| Input | Structural native import | Native flow/decode/decompile |",
        "|---|---|---|",
    ]
    table_lines = header + [f"| {r[0]} | {r[1]} | {r[2]} |" for r in rows]
    return "\n".join(table_lines) + "\n" + blocked_table()


def console_reports() -> list[tuple[str, dict, dict]]:
    """Committed console gate reports, oldest id first.

    A report qualifies by carrying a `platform` block: the row is rendered
    from those fields, so a platform with no report gets no row.
    """
    found = []
    for path in sorted(REPORTS_DIR.glob("m5-*.json")):
        report = load_json(path)
        if not isinstance(report, dict):
            continue
        platform = report.get("platform")
        if isinstance(platform, dict) and platform.get("family") == "console":
            found.append((path.stem, report, platform))
    return found


def console_rows() -> list[tuple[str, str, str]]:
    rows = []
    for report_id, report, platform in console_reports():
        rows.append((platform["input"], "supported", console_status(report_id, report, platform)))
    return rows


def console_status(report_id: str, report: dict, platform: dict) -> str:
    """Render one console platform's claim from its measurement."""
    test = platform.get("test", "")
    citation = f"`{test}`" if test else f"`benchmarks/reports/{report_id}.json`"
    if not report.get("passed"):
        return (
            f"import supported; the gate report `{report_id}.json` records "
            f"status {report.get('status', 'unknown')}, so no claim is made "
            f"({citation})"
        )

    programs = platform.get("programs", [])
    if not programs:
        return f"import supported; the gate report records no programs ({citation})"

    measured = []
    for program in programs:
        # One program per platform is the common case, and naming it there
        # would only repeat the input column.
        label = f"{program['name']} " if len(programs) > 1 else ""
        piece = (
            f"{label}{program['dwarf.fn.recall']:.4f} over "
            f"{program['dwarf.functions']} functions on `{program['language']}`"
        )
        deficits = program.get("recorded_deficits") or []
        if deficits:
            plural = "s" if len(deficits) > 1 else ""
            piece += f" with {len(deficits)} recorded deficit{plural}"
        measured.append(piece)
    return f"**gated**: DWARF recall {'; '.join(measured)} ({citation})"


def catalog_platforms() -> list[dict]:
    catalog = load_json(CATALOG)
    if not isinstance(catalog, dict) or not isinstance(catalog.get("platforms"), list):
        raise ValueError(f"platform tier catalog missing or unreadable: {CATALOG}")
    return catalog["platforms"]


def blocked_table() -> str:
    """Platforms that are not supported, each with its blocker."""
    blocked = [p for p in catalog_platforms() if p.get("tier") == 2]
    lines = [
        "",
        "**Not supported.** Each row names the fact that blocks it, and where",
        "that fact was checked.",
        "",
        "| Platform | Blocker | Checked |",
        "|---|---|---|",
    ]
    for platform in sorted(blocked, key=lambda p: p["input"]):
        lines.append(
            f"| {platform['input']} | {platform['blocker']} | {platform['evidence']} |"
        )
    return "\n".join(lines)


def unproven_claims() -> list[str]:
    """Tier-1 catalog entries whose gate report is not committed."""
    measured = {report_id for report_id, report, _ in console_reports() if report.get("passed")}
    unproven = []
    for platform in catalog_platforms():
        if platform.get("tier") != 1:
            continue
        gate = platform.get("gate")
        if gate not in measured:
            unproven.append(
                f"{platform.get('input')!r} claims tier-1 support but its gate "
                f"report {gate!r} is not committed or did not pass"
            )
    return unproven


def update_readme(check: bool) -> bool:
    if not README.is_file():
        raise FileNotFoundError(f"README not found at {README}")

    content = README.read_text(encoding="utf-8")
    generated_table = generate_matrix()

    pattern = re.compile(
        re.escape(BEGIN) + r"\n.*?\n" + re.escape(END),
        re.DOTALL,
    )
    match = pattern.search(content)
    if not match:
        raise ValueError(
            f"README.md has no generator markers ({BEGIN} ... {END}); the "
            f"support matrix cannot be regenerated without hand editing"
        )

    expected_section = f"{BEGIN}\n{generated_table}\n{END}"
    current_section = match.group(0)

    if current_section != expected_section:
        if check:
            print("Support matrix in README.md is stale!", file=sys.stderr)
            print("Run 'python scripts/gen_support_matrix.py' to regenerate it.", file=sys.stderr)
            return False
        new_content = content.replace(current_section, expected_section, 1)
        README.write_text(new_content, encoding="utf-8")
        print("Updated README.md support matrix successfully.")
        return True

    if check:
        print("Support matrix in README.md is up to date.")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check if README matrix is up to date without modifying",
    )
    args = parser.parse_args()

    # A support claim with no committed measurement is never printed.
    unproven = unproven_claims()
    if unproven:
        for problem in unproven:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    ok = update_readme(check=args.check)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
