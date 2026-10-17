#!/usr/bin/env python3
"""Compile one C unit with Metrowerks' mwccarm: cc.py OUT SRC

mwccarm.exe is a Windows program: it runs through wibo, with the license file
the archive ships (`mwccarm/license.dat`) next to the executable and named in
LM_LICENSE_FILE. Paths come from build/tools.json, flags and the compiler build
(`compiler.mw_version`, a directory of the pinned archive) from config/project.json.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    out, source = sys.argv[1:3]
    paths = json.loads((ROOT / "build" / "tools.json").read_text())
    project = json.loads((ROOT / "config" / "project.json").read_text())
    compiler = project["compiler"]
    exe = Path(paths["mwccarm_root"]) / compiler["mw_version"] / "mwccarm.exe"
    env = dict(os.environ, LM_LICENSE_FILE=str(exe.parent / "license.dat"))
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    # The unit is compiled with romwright's names mapped onto dsd's (include/romwright_names.h).
    text = Path(source).read_text()
    unit = Path(out).with_suffix(".unit.c")
    unit.write_text('#include "romwright_names.h"\n' + text)
    argv = [paths["wibo"], str(exe), *compiler["cflags"], "-i", "include", "-c", str(unit), "-o", out]
    result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True)
    sys.stderr.write(result.stdout + result.stderr)
    return result.returncode


sys.exit(main())
