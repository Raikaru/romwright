#!/usr/bin/env python3
"""Fetch every fact-pack donor repo at its pinned commit: a shallow, blobless,
sparse checkout of headers and C/C++ sources only (maintainer tool; the
repos are data, nothing here is shipped).

    fetch_donors.py [--licenses licenses.json] [--out DIR] [--jobs 4] [GAME...]

Reruns are idempotent: a repo whose HEAD already is the pinned commit is left
alone. A repo whose matching sources would exceed MAX_BYTES (judged from the
GitHub tree listing) is skipped and reported.
"""
import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SCRATCH = Path.home() / "romwright-scratch" / "factpack"
MAX_BYTES = 2 * 1024**3
EXTENSIONS = (".h", ".hpp", ".hh", ".hxx", ".c", ".cpp", ".cc", ".cxx")
PATTERNS = [f"*{e}" for e in EXTENSIONS]
ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0")


def run(args, cwd=None, check=True):
    return subprocess.run(args, cwd=cwd, env=ENV, check=check, text=True,
                          capture_output=True)


def tree_bytes(repo, commit):
    """Sum of matching blob sizes, or None when the listing is unavailable."""
    out = run(["gh", "api", f"repos/{repo}/git/trees/{commit}?recursive=1"], check=False)
    if out.returncode:
        return None
    tree = json.loads(out.stdout)
    if tree.get("truncated"):
        return None
    return sum(e.get("size", 0) for e in tree["tree"]
               if e["type"] == "blob" and e["path"].endswith(EXTENSIONS))


def fetch_one(entry, out):
    game, repo, commit = entry["game"], entry["repo"], entry["commit"]
    path = out / game
    head = run(["git", "rev-parse", "HEAD"], cwd=path, check=False) if path.exists() else None
    if head and head.returncode == 0 and head.stdout.strip() == commit:
        return game, "ok", "already at pinned commit"
    size = tree_bytes(repo, commit)
    if size is not None and size > MAX_BYTES:
        return game, "skipped", f"{size / 1e9:.1f} GB of sources exceeds the limit"
    try:
        path.mkdir(parents=True, exist_ok=True)
        if not (path / ".git").exists():
            run(["git", "init", "-q", str(path)])
            run(["git", "remote", "add", "origin", f"https://github.com/{repo}.git"], cwd=path)
        run(["git", "config", "extensions.partialClone", "origin"], cwd=path)
        run(["git", "config", "remote.origin.promisor", "true"], cwd=path)
        run(["git", "config", "remote.origin.partialclonefilter", "blob:none"], cwd=path)
        run(["git", "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", commit], cwd=path)
        run(["git", "sparse-checkout", "init", "--no-cone"], cwd=path)
        run(["git", "sparse-checkout", "set", "--no-cone", *PATTERNS], cwd=path)
        run(["git", "checkout", "-q", "--detach", commit], cwd=path)
    except subprocess.CalledProcessError as error:
        return game, "failed", (error.stderr or str(error)).strip().splitlines()[-1]
    return game, "ok", "" if size is None else f"{size / 1e6:.0f} MB of sources"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--licenses", default=str(SCRATCH / "licenses.json"))
    parser.add_argument("--out", default=str(SCRATCH / "repos"))
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("games", nargs="*")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    donors = [d for d in json.load(open(args.licenses))
              if not args.games or d["game"] in args.games]
    failed = False
    with ThreadPoolExecutor(args.jobs) as pool:
        for game, status, note in pool.map(lambda d: fetch_one(d, out), donors):
            print(f"{status:8} {game} {note}", flush=True)
            failed |= status == "failed"
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
