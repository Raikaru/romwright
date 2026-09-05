#!/usr/bin/env python3
"""m2-002g0: real oracle imports must honor explicit analysis contexts."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from gen_oracle import bridge_command, digest, generate_reference, provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path,
                        default=Path.home() / "ghidra_12.1.3_PUBLIC")
    args = parser.parse_args()
    binary = args.corpus_dir / "powerpc_plain_o0.bin"
    command = bridge_command(args.ghidra, "java")
    expected = {"schema_version": 1, "sha256": digest(binary),
                "binary_size": binary.stat().st_size, **provenance(args.ghidra),
                "address_basis": "ghidra", "language_selection": "explicit",
                "compiler": "default"}
    references = []
    for language in ("PowerPC:BE:32:default", "PowerPC:BE:32:e500"):
        reference = generate_reference(command, binary, {**expected, "language": language},
                                       180, include_xrefs=True)
        references.append({(row["from"], row["to"], row["kind"])
                           for row in reference["xrefs"]})
        print(f"PASS explicit {reference['language']} / {reference['compiler']}", flush=True)
    assert references[0] != references[1], "language selection must affect real reference analysis"
    try:
        generate_reference(command, binary,
                           {**expected, "language": "PowerPC:BE:32:default",
                            "compiler": "ventris-invalid-compiler"}, 180, include_xrefs=True)
    except ValueError as error:
        assert "Bridge RPC error" in str(error), error
    else:
        raise AssertionError("unsupported compiler silently fell back to automatic selection")
    print("PASS invalid compiler rejected without automatic fallback")


if __name__ == "__main__":
    main()
