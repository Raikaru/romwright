#!/usr/bin/env python3
"""Interactive Romwright script console backed by romwright-api."""
from __future__ import annotations

import argparse
import code
import pathlib
import runpy
import sys

from romwright_sdk import Client, ApiError


def main() -> int:
    parser = argparse.ArgumentParser(description="Romwright Core API script console")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("-c", "--command", help="execute one Python expression/block")
    source.add_argument("-f", "--file", type=pathlib.Path, help="execute a Python script")
    parser.add_argument("--project", default=".romwright", help="project directory for romwright-api stdio")
    parser.add_argument("--api-url", help="use an existing HTTP API endpoint instead")
    parser.add_argument("--api-executable", default="romwright-api", help="romwright-api executable")
    args = parser.parse_args()

    client = Client.http(args.api_url) if args.api_url else Client.stdio(args.project, args.api_executable)
    namespace = {"romwright": client, "client": client}
    try:
        if args.command is not None:
            exec(compile(args.command, "<romwright-console>", "exec"), namespace, namespace)
        elif args.file is not None:
            runpy.run_path(str(args.file), init_globals=namespace)
        else:
            banner = "Romwright API console. `romwright` and `client` are the live Core client."
            code.InteractiveConsole(namespace).interact(banner=banner)
    except ApiError as error:
        print(f"romwright: {error}", file=sys.stderr)
        return 1
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
