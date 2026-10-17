#!/usr/bin/env python3
"""m6-004: a release is produced, described and verified from this checkout.

There was no release document -- STATUS.md's own "next task" said `RELEASING.md`
described the steps, and no such file exists. What existed was three CI steps:
an SBOM, an update manifest over `LICENSE` alone, and a verification of that
one-file manifest. Nothing produced a release artifact set, nothing checked the
SBOM against the crates it claims to cover, and nothing checked that a
tampered artifact fails verification.

`docs/releasing.md` now documents the procedure, and this gate runs the
commands on that page -- so a step that is documented and broken fails here --
then checks the results:

  * the artifact set holds the real release binaries and the desktop package
    (`romwright-<version>-<system>-<machine>.tar.gz`);
  * the manifest records size and SHA-256 for every artifact, and
    `verify_update.py` accepts it;
  * a flipped byte and a truncation each make verification fail;
  * the SBOM is SPDX 2.3, names **every** workspace crate, and every package
    carries a declared licence;
  * the staged `romwright-cli` writes a project from what it embeds (the
    platform list, the repository scripts and the pinned tool manifest need
    nothing from this checkout), and the desktop archive ships that CLI.

Usage:
    python3 tests/m6-004_release_artifacts.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "releasing.md"
BLOCK = re.compile(r"```console\n(.*?)```", re.DOTALL)
# The binaries a release ships beside the desktop package.
BINARIES = ("romwright-cli", "romwright-api", "romwright-worker")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def documented_blocks(text: str) -> list[list[str]]:
    blocks = []
    for match in BLOCK.finditer(text):
        commands = [line[2:].strip() for line in match.group(1).splitlines()
                    if line.startswith("$ ")]
        assert commands, "console block with no command"
        blocks.append(commands)
    return blocks


def workspace_crates() -> set[str]:
    metadata = json.loads(subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    return {package["name"] for package in metadata["packages"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=2400)
    arguments = parser.parse_args()

    assert DOC.is_file(), f"{DOC.relative_to(ROOT)} does not exist"
    blocks = documented_blocks(DOC.read_text(encoding="utf-8"))
    assert blocks, "the release document contains no runnable command"

    report = {"id": "m6-004", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "status": "skipped",
              "platform": {"system": platform.system(),
                           "machine": platform.machine()}}
    executed = 0

    with tempfile.TemporaryDirectory(prefix="m6-004-") as temporary:
        stage = Path(temporary)
        environment = dict(os.environ, ROMWRIGHT_RELEASE_DIR=str(stage))
        for commands in blocks:
            for command in commands:
                result = subprocess.run(
                    shlex.split(command.replace("$RELEASE", str(stage))),
                    cwd=ROOT, capture_output=True, text=True,
                    timeout=arguments.timeout, env=environment)
                assert result.returncode == 0, (
                    f"documented release command failed: {command}\n"
                    f"{(result.stderr.strip() or result.stdout.strip())[-600:]}")
                executed += 1

        # 1. The artifact set holds the real binaries.
        artifacts = sorted(path for path in stage.rglob("*") if path.is_file())
        names = {path.name for path in artifacts}
        for binary in BINARIES:
            candidates = [name for name in names
                          if name in (binary, f"{binary}.exe")]
            assert candidates, (
                f"the release set has no {binary}; it holds {sorted(names)}")
        suffix = f"-{platform.system()}-{platform.machine()}.tar.gz"
        assert any(name.startswith("romwright-") and name.endswith(suffix)
                   for name in names), (
            f"the release set has no desktop package: {sorted(names)}")

        # 2. The manifest covers them, and verification accepts it.
        manifest_path = stage / "update.json"
        assert manifest_path.is_file(), (
            f"the documented steps produced no update manifest in {stage}")
        manifest = json.loads(manifest_path.read_text())
        assert manifest.get("schema") == 1, f"manifest schema {manifest.get('schema')}"
        recorded = {entry["path"]: entry for entry in manifest["artifacts"]}
        payload = [path for path in artifacts if path != manifest_path]
        assert len(recorded) == len(payload), (
            f"manifest records {sorted(recorded)} but the set holds "
            f"{sorted(path.name for path in payload)}")
        for path in payload:
            relative = str(path.relative_to(stage))
            entry = recorded.get(relative)
            assert entry, f"{relative} is not in the manifest"
            assert entry["size"] == path.stat().st_size, f"{relative}: size"
            assert entry["sha256"] == sha256(path), f"{relative}: digest"
        verify = subprocess.run(
            [sys.executable, str(ROOT / "packaging/verify_update.py"),
             str(manifest_path), "--root", str(stage)],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        assert verify.returncode == 0, (
            f"verification rejected an untouched release: {verify.stdout.strip()}")

        # 3. Tampering must be caught. Both a same-size edit and a truncation.
        target = max(payload, key=lambda path: path.stat().st_size)
        original = target.read_bytes()
        try:
            flipped = bytearray(original)
            flipped[len(flipped) // 2] ^= 0xFF
            target.write_bytes(bytes(flipped))
            edited = subprocess.run(
                [sys.executable, str(ROOT / "packaging/verify_update.py"),
                 str(manifest_path), "--root", str(stage)],
                cwd=ROOT, capture_output=True, text=True)
            assert edited.returncode != 0 and "SHA-256" in edited.stdout, (
                f"a flipped byte in {target.name} passed verification: "
                f"{edited.stdout.strip()}")
            target.write_bytes(original[: len(original) // 2])
            truncated = subprocess.run(
                [sys.executable, str(ROOT / "packaging/verify_update.py"),
                 str(manifest_path), "--root", str(stage)],
                cwd=ROOT, capture_output=True, text=True)
            assert truncated.returncode != 0 and "size" in truncated.stdout, (
                f"a truncated {target.name} passed verification: "
                f"{truncated.stdout.strip()}")
        finally:
            target.write_bytes(original)

        # 4. The SBOM covers every crate this release is built from.
        sbom_path = next((path for path in artifacts
                          if path.name.endswith(".spdx.json")), None)
        assert sbom_path is not None, (
            f"the documented steps produced no SBOM in {stage}")
        sbom = json.loads(sbom_path.read_text())
        assert sbom.get("spdxVersion") == "SPDX-2.3", sbom.get("spdxVersion")
        described = {package["name"] for package in sbom["packages"]}
        missing = sorted(workspace_crates() - described)
        assert not missing, f"the SBOM omits workspace crates: {missing}"
        unlicensed = sorted(package["name"] for package in sbom["packages"]
                            if not package.get("licenseDeclared")
                            or package["licenseDeclared"] == "NOASSERTION")
        assert not unlicensed, f"SBOM packages with no declared licence: {unlicensed}"

        # 5. The shipped binaries carry what a repository is written from.
        cli = next(path for path in payload if path.name in ("romwright-cli", "romwright-cli.exe"))
        listing = subprocess.run([str(cli), "new-project", "--list-platforms", "--json"], cwd=stage,
                                 capture_output=True, text=True, timeout=arguments.timeout)
        assert listing.returncode == 0, f"new-project --list-platforms: {listing.stderr.strip()[-400:]}"
        ids = {row["id"] for row in json.loads(listing.stdout)}
        wanted = {"ps2", "gc", "wii", "n64", "psx", "psp", "gba", "nds", "3ds", "switch", "ps3", "ps4",
                  "vita", "x360", "pe"}
        assert wanted <= ids, f"the shipped CLI lists no plugin for {sorted(wanted - ids)}"
        fixture = ROOT / "tests" / "fixtures-src" / "tiny_pe32.exe"
        with tempfile.TemporaryDirectory(prefix="m6-004-project-") as scratch:
            repository = Path(scratch) / "repository"
            made = subprocess.run([str(cli), "new-project", str(fixture), str(repository), "--decompile", "none"],
                                  cwd=scratch, capture_output=True, text=True, timeout=arguments.timeout)
            assert made.returncode == 0, f"the shipped CLI wrote no project: {made.stderr.strip()[-600:]}"
            for name in ("README.md", "configure.py", "build.py", "tools/download_tool.py",
                         "config/project.json", "config/toolchain.json"):
                assert (repository / name).is_file(), f"the shipped CLI wrote no {name}"
            tools = json.loads((repository / "config" / "toolchain.json").read_text())["tools"]
            assert tools, "the project's toolchain manifest pins no tool"
            for tool in tools:
                assert tool.get("license") and tool.get("provenance") and tool.get("assets"), (
                    f"tool {tool.get('id')} is pinned without a licence, provenance or asset")
                for host, asset in tool["assets"].items():
                    assert re.fullmatch(r"[0-9a-f]{64}", asset.get("sha256", "")) and asset.get("size", 0) > 0, (
                        f"tool {tool['id']} ({host}) has no sha256 and size pin")
            pinned = sorted(tool["id"] for tool in tools)
        archive = next(path for path in payload if path.name.endswith(".tar.gz"))
        with tarfile.open(archive) as bundle:
            members = {Path(member.name).name for member in bundle.getmembers()}
        assert cli.name in members, f"{archive.name} ships no {cli.name} for Create project to run"

        recorded_artifacts = sorted(str(path.relative_to(stage)) for path in payload)
        packages = len(sbom["packages"])

    summary = (f"{executed} documented release commands run on "
               f"{platform.system()}/{platform.machine()}: "
               f"{len(recorded_artifacts)} artifacts manifested and verified, "
               f"tampering and truncation both rejected, SBOM covers "
               f"{packages} packages including every workspace crate; the shipped CLI wrote a "
               f"project from its embedded templates pinning {len(pinned)} tools "
               f"({', '.join(pinned)})")
    if arguments.report:
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"commands": executed,
                               "artifacts": len(recorded_artifacts),
                               "sbom_packages": packages,
                               "project_pinned_tools": len(pinned),
                               "listed_platforms": len(ids)},
                      artifacts=recorded_artifacts)
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=1) + "\n")
    print(f"m6-004: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
