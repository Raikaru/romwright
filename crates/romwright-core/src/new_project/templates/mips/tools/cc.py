#!/usr/bin/env python3
"""Compile one C unit: cc.py SOURCE OUTPUT

The compile command of this project (see tools/toolchain.py and config/project.json),
so `ninja` and `romwright-cli match` build a unit identically. Tools must be installed
(`python3 configure.py`) or named by a toolchain profile.
"""
import sys

import toolchain


def main():
    source, output = sys.argv[1:3]
    tools = toolchain.resolve_tools(download=False)
    result = toolchain.compile_unit(tools, source, output)
    sys.stdout.write(result.stdout.decode(errors="replace"))
    sys.stderr.write(result.stderr.decode(errors="replace"))
    return result.returncode


sys.exit(main())
