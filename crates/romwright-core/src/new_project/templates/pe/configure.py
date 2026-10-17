#!/usr/bin/env python3
"""Fetch the pinned tools of this project and write build/config.json for build.py.

    python3 configure.py                        # the compiler config/project.json names, wibo, objdiff-cli
    python3 configure.py --compiler msvc6.0     # another era from config/toolchain.json (kept in config/compiler.local.json)
    python3 configure.py --flags "/O2 /G5"      # other compiler flags (kept in config/compiler.local.json)
    python3 configure.py --no-fetch             # only write build/config.json (tools already installed, or a profile)

Every download is sha256-checked against config/toolchain.json before it is extracted (tools/download_tool.py). A toolchain
profile, `config/toolchain.local.json`, names tools you already have instead:

    {"wibo": "/usr/local/bin/wibo", "cl": "/opt/msvc6/Bin/CL.EXE", "include": ["/opt/msvc6/Include"],
     "objdiff-cli": "/usr/local/bin/objdiff-cli"}

Standard library only. The compilers are proprietary; use one only if you are entitled to.
"""
import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"
TOOLS = BUILD / "tools"


def load_json(path, default=None):
    path = Path(path)
    return json.loads(path.read_text()) if path.exists() else default


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--compiler", help="a compiler id of config/toolchain.json")
    parser.add_argument("--flags", help="compiler flags (replaces the project's)")
    parser.add_argument("--no-fetch", action="store_true")
    args = parser.parse_args()

    project = load_json(ROOT / "config" / "project.json")
    manifest = {tool["id"]: tool for tool in load_json(ROOT / "config" / "toolchain.json")["tools"]}
    local = load_json(ROOT / "config" / "compiler.local.json", {})
    if args.compiler:
        local["tool"] = args.compiler
    if args.flags is not None:
        local["flags"] = shlex.split(args.flags)
    if local:
        (ROOT / "config" / "compiler.local.json").write_text(json.dumps(local, indent=2) + "\n")
    tool_id = local.get("tool") or project["compiler"]["tool"]
    if tool_id not in manifest:
        raise SystemExit(f"{tool_id}: not in config/toolchain.json (known: {', '.join(sorted(manifest))})")
    entry = manifest[tool_id]
    family = entry.get("family") or "clang"
    flags = local.get("flags") or project["compiler"]["flags"]
    if family == "msvc" and not local.get("flags") and tool_id != project["compiler"]["tool"]:
        flags = ["/O2", "/Gd", "/W0"]

    profile = load_json(ROOT / "config" / "toolchain.local.json", {})
    ids = [tool_id, "objdiff-cli"] + (["wibo"] if family == "msvc" else [])
    if not args.no_fetch and not profile:
        done = subprocess.call([sys.executable, str(ROOT / "tools" / "download_tool.py"), *ids, "--dest", str(TOOLS)], cwd=ROOT)
        if done != 0:
            raise SystemExit(done)

    def installed(tool, member):
        return str(TOOLS / tool / member)

    include = []
    if profile:
        wibo, cl, include, objdiff = profile.get("wibo"), profile.get("cl"), profile.get("include", []), profile.get("objdiff-cli")
    else:
        wibo = installed("wibo", "wibo") if family == "msvc" else None
        cl = installed(tool_id, entry["entry"]) if family == "msvc" else None
        include = [installed(tool_id, value) for key, value in (entry.get("provides") or {}).items() if "include" in key]
        objdiff = installed("objdiff-cli", "objdiff-cli")
    config = {"tool": tool_id, "family": family, "flags": flags, "wibo": wibo, "cl": cl, "include": include, "objdiff": objdiff,
              "clang": profile.get("clang")}
    BUILD.mkdir(exist_ok=True)
    (BUILD / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    print(f"configured: {tool_id} ({family}), flags {' '.join(flags)}")
    print("next: python3 build.py && python3 build.py report")


if __name__ == "__main__":
    main()
