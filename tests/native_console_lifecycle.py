#!/usr/bin/env python3
"""A managed native console must terminate when its owning process is killed."""
import argparse
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

PARENT = r'''
import os, subprocess, sys
child = subprocess.Popen([sys.argv[1], '-s', sys.argv[2]],
    env=dict(os.environ, ROMWRIGHT_PARENT_PID=str(os.getpid())),
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    start_new_session=True)
response = bytearray()
while not response.endswith(b'[decomp]> '):
    byte = child.stdout.read(1)
    if not byte:
        raise RuntimeError('console exited before its prompt: ' + child.stderr.read().decode())
    response.extend(byte)
child.stdin.write(('source ' + sys.argv[3] + '\n').encode())
child.stdin.flush()
print(child.pid, flush=True)
sys.stdin.read()
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--console', type=Path, required=True)
    parser.add_argument('--specs', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux':
        raise SystemExit('This process-identity regression requires Linux pidfds')
    temporary = tempfile.TemporaryDirectory(prefix='native-lifetime-')
    fifo = Path(temporary.name) / 'commands'
    os.mkfifo(fifo)
    writer = None
    parent = subprocess.Popen([sys.executable, '-u', '-c', PARENT,
        str(args.console.resolve()), str(args.specs.resolve()), str(fifo)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    child_fd = None
    started = time.monotonic()
    try:
        import select
        ready, _, _ = select.select([parent.stdout], [], [], 15)
        if not ready:
            raise AssertionError('console startup exceeded 15 seconds')
        line = parent.stdout.readline().strip()
        if not line:
            raise AssertionError('console parent failed: ' + parent.stderr.read())
        child = int(line)
        child_fd = os.pidfd_open(child)
        # Establish that the console entered a real blocking command. An idle
        # old console exits on stdin EOF too, which would be a false regression.
        deadline = time.monotonic() + 5
        while writer is None:
            try:
                writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as error:
                if error.errno != errno.ENXIO or time.monotonic() >= deadline:
                    raise AssertionError('console did not enter source command') from error
                time.sleep(0.01)
        killed = time.monotonic()
        parent.kill()
        parent.wait(timeout=5)
        exited, _, _ = select.select([child_fd], [], [], 2)
        if not exited:
            raise AssertionError(f'native console {child} survived its parent')
        print(json.dumps({'passed': True, 'parent_death_ms':
            round((time.monotonic() - killed) * 1000),
            'elapsed_ms': round((time.monotonic() - started) * 1000)}))
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)
        if child_fd is not None:
            try:
                signal.pidfd_send_signal(child_fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(child_fd)
        if writer is not None:
            os.close(writer)
        temporary.cleanup()


if __name__ == '__main__':
    main()
