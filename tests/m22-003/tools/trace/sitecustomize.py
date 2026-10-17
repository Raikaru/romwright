"""Record every subprocess a python build spawns (m22-003).

For repos whose build is a python script with no dry-run mode: run it with PYTHONPATH pointing at this directory and
M22_003_TRACE=<file>; every `subprocess.Popen` appends one JSON line (argv, cwd) to the file. The harness then takes the
compile commands out of that log, so each unit's command is the one the repo's own build ran. Loaded by every python
child too (the variables are inherited), one O_APPEND write per line so parallel children do not interleave.
"""
import json
import os
import subprocess

_LOG = os.environ.get("M22_003_TRACE")
if _LOG:
    _original = subprocess.Popen.__init__

    def _init(self, args, *rest, **kwargs):
        try:
            argv = list(args) if isinstance(args, (list, tuple)) else [str(args)]
            row = {"argv": [os.fspath(a) if not isinstance(a, bytes) else a.decode() for a in argv],
                   "cwd": os.fspath(kwargs.get("cwd") or os.getcwd()), "shell": bool(kwargs.get("shell"))}
            fd = os.open(_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            os.write(fd, (json.dumps(row) + "\n").encode())
            os.close(fd)
        except Exception:  # tracing must never break the build
            pass
        _original(self, args, *rest, **kwargs)

    subprocess.Popen.__init__ = _init
