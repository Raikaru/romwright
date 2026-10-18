#!/usr/bin/env python3
"""m6-008: the Ghidra data fetch `setup.py` and the release workflow share.

`packaging/ghidra_data.py` downloads a release zip once, refuses one whose
SHA-256 is not the pinned digest, and extracts only what romwright reads. This
gate exercises that against a local `file://` zip (no network): a verified
download is cached and not repeated, a wrong digest is refused and leaves
nothing behind, the extraction keeps `Ghidra/Processors/*/data/**` (minus
`data/manuals`) and the licence and nothing else, a second extraction is
skipped, and a damaged marker or missing sentinel makes it run again. A zip
with the wrong digest is refused before anything is extracted or run (also when
the data is already extracted), and a `.part` file that is already complete, or
that a server answers with HTTP 416, is verified and promoted or discarded
rather than requested again. The release's architecture check
(`packaging/check_archive_arch.py`) and the macOS make arguments of
`native/build_*.sh` (a fake `uname`) are exercised here too.

Usage:
    python3 tests/m6-008_ghidra_data.py
"""
from __future__ import annotations

import hashlib
import http.server
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))
import ghidra_data  # noqa: E402
import check_archive_arch  # noqa: E402
import languages  # noqa: E402
import smoke_fixtures  # noqa: E402

P = f"{ghidra_data.ZIP_ROOT}/Ghidra/Processors"
MEMBERS = {
    f"{ghidra_data.ZIP_ROOT}/LICENSE": b"licence",
    f"{ghidra_data.ZIP_ROOT}/ghidraRun": b"launcher",
    f"{ghidra_data.ZIP_ROOT}/Ghidra/Framework/Utility/lib/Utility.jar": b"jar",
    f"{P}/x86/data/languages/x86-64.sla": b"sla",
    f"{P}/x86/data/languages/x86.ldefs": b"ldefs",
    f"{P}/x86/data/patterns/x86_patterns.xml": b"patterns",
    f"{P}/x86/data/manuals/x86.idx": b"manual",
    f"{P}/x86/lib/x86.jar": b"jar",
    f"{P}/x86/Module.manifest": b"manifest",
}
KEPT = {
    "LICENSE",
    "Ghidra/Processors/x86/data/languages/x86-64.sla",
    "Ghidra/Processors/x86/data/languages/x86.ldefs",
    "Ghidra/Processors/x86/data/patterns/x86_patterns.xml",
}


def make_zip(path: Path) -> str:
    with zipfile.ZipFile(path, "w") as bundle:
        for name, data in MEMBERS.items():
            bundle.writestr(name, data)
    return hashlib.sha256(path.read_bytes()).hexdigest()


class GhidraData(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.root = Path(self.scratch.name)
        self.source = self.root / "source.zip"
        self.digest = make_zip(self.source)

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def test_wanted_keeps_only_processor_data(self) -> None:
        kept = {ghidra_data.wanted(name) for name in MEMBERS} - {None}
        self.assertEqual(kept, KEPT)
        self.assertIsNone(ghidra_data.wanted(f"{ghidra_data.ZIP_ROOT}/../evil"))
        self.assertIsNone(ghidra_data.wanted("other_root/Ghidra/Processors/x86/data/a"))

    def test_download_is_verified_then_cached(self) -> None:
        cache = self.root / "cache"
        url = self.source.as_uri()
        first = ghidra_data.download(cache, url, self.digest, self.source.stat().st_size, "g.zip")
        self.assertEqual(first.read_bytes(), self.source.read_bytes())
        self.source.unlink()  # a second call that downloaded again would fail
        second = ghidra_data.download(cache, url, self.digest, 1, "g.zip")
        self.assertEqual(second, first)

    def test_a_wrong_digest_is_refused_and_leaves_nothing(self) -> None:
        cache = self.root / "cache"
        with self.assertRaises(ghidra_data.SetupError):
            ghidra_data.download(cache, self.source.as_uri(), "0" * 64,
                                 self.source.stat().st_size, "g.zip", attempts=2)
        self.assertEqual(list(cache.iterdir()), [])

    def test_a_cached_copy_with_the_wrong_digest_is_discarded(self) -> None:
        cache = self.root / "cache"
        cache.mkdir()
        (cache / "g.zip").write_bytes(b"truncated")
        path = ghidra_data.download(cache, self.source.as_uri(), self.digest,
                                    self.source.stat().st_size, "g.zip")
        self.assertEqual(ghidra_data.sha256_of(path), self.digest)

    def test_extract_keeps_the_subset_and_is_not_repeated(self) -> None:
        dest = self.root / "ghidra"
        # The sentinel is the real x86-64 path, which MEMBERS holds.
        self.assertFalse(ghidra_data.is_installed(dest, self.digest))
        count = ghidra_data.extract(self.source, dest, self.digest)
        self.assertEqual(count, len(KEPT))
        on_disk = {path.relative_to(dest).as_posix() for path in dest.rglob("*") if path.is_file()}
        self.assertEqual(on_disk, KEPT | {ghidra_data.MARKER})
        self.assertTrue(ghidra_data.is_installed(dest, self.digest))
        self.assertFalse(ghidra_data.is_installed(dest, "1" * 64))
        (dest / ghidra_data.SENTINEL).unlink()
        self.assertFalse(ghidra_data.is_installed(dest, self.digest))

    def test_a_zip_that_is_not_ghidra_is_refused(self) -> None:
        other = self.root / "other.zip"
        with zipfile.ZipFile(other, "w") as bundle:
            bundle.writestr("readme.txt", "nothing")
        other_digest = hashlib.sha256(other.read_bytes()).hexdigest()
        with self.assertRaises(ghidra_data.SetupError):
            ghidra_data.extract(other, self.root / "ghidra", other_digest)
        self.assertFalse((self.root / "ghidra").exists())

    def test_a_wrong_digest_zip_is_rejected_before_anything_is_extracted(self) -> None:
        dest = self.root / "ghidra"
        with self.assertRaisesRegex(ghidra_data.SetupError, "SHA-256"):
            ghidra_data.extract(self.source, dest, "0" * 64)
        self.assertFalse(dest.exists())
        self.assertEqual([path.name for path in self.root.iterdir() if ".partial" in path.name], [])
        with self.assertRaisesRegex(ghidra_data.SetupError, "SHA-256"):
            ghidra_data.provision(dest, self.root / "cache", self.source)  # not the pinned digest
        self.assertFalse(dest.exists())
        with self.assertRaises(ghidra_data.SetupError):
            ghidra_data.verify_zip(self.root / "missing.zip")

    def test_a_supplied_zip_is_verified_even_when_the_data_is_already_installed(self) -> None:
        dest = self.root / "ghidra"
        ghidra_data.extract(self.source, dest, self.digest)
        marker = dest / ghidra_data.MARKER
        record = json.loads(marker.read_text(encoding="utf-8"))
        record["sha256"] = ghidra_data.SHA256  # as if the pinned release had been extracted
        marker.write_text(json.dumps(record), encoding="utf-8")
        self.assertEqual(ghidra_data.provision(dest, self.root / "cache"), "kept")
        with self.assertRaisesRegex(ghidra_data.SetupError, "SHA-256"):
            ghidra_data.provision(dest, self.root / "cache", self.source)

    def test_a_wrong_digest_zip_never_gives_up_its_sleigh(self) -> None:
        # The zip carries a `sleigh` that, if it were extracted and run, leaves
        # a file behind; find_sleigh must refuse the zip before either happens.
        ran = self.root / "sleigh-ran"
        os_dir = "linux_x86_64"
        member = f"{ghidra_data.ZIP_ROOT}/Ghidra/Features/Decompiler/os/{os_dir}/sleigh{languages.EXE}"
        evil = self.root / "evil.zip"
        with zipfile.ZipFile(evil, "w") as bundle:
            bundle.writestr(member, f"#!/bin/sh\ntouch '{ran}'\n")
        cache = self.root / "cache"
        ghidra = self.root / "ghidra"
        ghidra.mkdir()
        with mock.patch.object(languages, "host_os_dir", return_value=os_dir), \
                self.assertRaisesRegex(ghidra_data.SetupError, "SHA-256"):
            languages.find_sleigh(ghidra, cache, None, evil, 1)
        self.assertFalse(ran.exists())
        self.assertFalse(cache.exists(), "nothing may be extracted from an unverified zip")


BODY = bytes(range(256)) * 64


class Server(http.server.ThreadingHTTPServer):
    """Serves BODY; a Range that starts at or past its end draws HTTP 416, as
    GitHub's release CDN does for a download already complete."""

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        self.requests: list = []


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:
        header = self.headers.get("Range")
        self.server.requests.append(header)
        start = int(header.split("=")[1].rstrip("-")) if header else 0
        if start >= len(BODY):
            self.send_response(416)
            self.send_header("Content-Range", f"bytes */{len(BODY)}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(206 if header else 200)
        self.send_header("Content-Length", str(len(BODY) - start))
        self.end_headers()
        self.wfile.write(BODY[start:])


class ResumedDownload(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.cache = Path(self.scratch.name)
        self.part = self.cache / "g.zip.part"
        self.digest = hashlib.sha256(BODY).hexdigest()
        self.server = Server()
        self.url = f"http://127.0.0.1:{self.server.server_port}/g.zip"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.scratch.cleanup()

    def fetch(self, size: int) -> Path:
        return ghidra_data.download(self.cache, self.url, self.digest, size, "g.zip", attempts=3)

    def test_a_complete_part_file_is_promoted_without_asking_the_server(self) -> None:
        self.part.write_bytes(BODY)
        path = self.fetch(len(BODY))
        self.assertEqual(path.read_bytes(), BODY)
        self.assertFalse(self.part.exists())
        self.assertEqual(self.server.requests, [])

    def test_a_complete_but_corrupt_part_file_is_discarded_and_fetched_afresh(self) -> None:
        self.part.write_bytes(b"\x01" * len(BODY))
        path = self.fetch(len(BODY))
        self.assertEqual(path.read_bytes(), BODY)
        self.assertEqual(self.server.requests, [None])

    def test_http_416_on_a_complete_part_file_verifies_it_instead_of_retrying(self) -> None:
        self.part.write_bytes(BODY)
        # size is what the pin says; here it is larger than the file, so only the
        # server's 416 can tell the download is already over.
        path = self.fetch(len(BODY) + 10)
        self.assertEqual(path.read_bytes(), BODY)
        self.assertEqual(self.server.requests, [f"bytes={len(BODY)}-"])

    def test_http_416_on_a_corrupt_part_file_restarts_the_download(self) -> None:
        self.part.write_bytes(b"\x01" * len(BODY))
        path = self.fetch(len(BODY) + 10)
        self.assertEqual(path.read_bytes(), BODY)
        self.assertEqual(self.server.requests, [f"bytes={len(BODY)}-", None])
        self.assertFalse(self.part.exists())


def elf(machine: int) -> bytes:
    return b"\x7fELF\x02\x01\x01" + bytes(11) + machine.to_bytes(2, "little") + bytes(64)


def pe(machine: int) -> bytes:
    return b"MZ" + bytes(0x3A) + (0x80).to_bytes(4, "little") + bytes(0x40) + b"PE\0\0" + \
        machine.to_bytes(2, "little") + bytes(64)


def macho(cpu: int) -> bytes:
    return b"\xcf\xfa\xed\xfe" + cpu.to_bytes(4, "little") + bytes(64)


def fat(*cpus: int) -> bytes:
    return b"\xca\xfe\xba\xbe" + len(cpus).to_bytes(4, "big") + b"".join(
        cpu.to_bytes(4, "big") + bytes(16) for cpu in cpus) + bytes(64)


MACHO_ARM64, MACHO_X64 = 0x0100000C, 0x01000007


class ArchiveArchitecture(unittest.TestCase):
    """packaging/check_archive_arch.py: the archive's name must not lie about its binaries."""

    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.root = Path(self.scratch.name)

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def pack(self, name: str, files: dict) -> Path:
        path = self.root / name
        top = name.split(".")[0]
        if name.endswith(".zip"):
            with zipfile.ZipFile(path, "w") as bundle:
                for member, data in files.items():
                    bundle.writestr(f"{top}/{member}", data)
        else:
            with tarfile.open(path, "w:gz") as bundle:
                for member, data in files.items():
                    info = tarfile.TarInfo(f"{top}/{member}")
                    info.size = len(data)
                    bundle.addfile(info, io.BytesIO(data))
        return path

    def test_binaries_of_the_archives_architecture_pass(self) -> None:
        for name, binary in (("romwright-1-macos-aarch64.tar.gz", macho(MACHO_ARM64)),
                             ("romwright-1-macos-x86_64.tar.gz", macho(MACHO_X64)),
                             ("romwright-1-macos-aarch64.tar.gz", fat(MACHO_ARM64)),
                             ("romwright-1-linux-x86_64.tar.gz", elf(62)),
                             ("romwright-1-linux-aarch64.tar.gz", elf(183)),
                             ("romwright-1-windows-x86_64.zip", pe(0x8664)),
                             ("romwright-1-windows-aarch64.zip", pe(0xAA64))):
            archive = self.pack(name, {"bin/romwright-cli": binary, "bin/ghidra_opt": binary,
                                       "share/romwright/x.sla": b"data"})
            self.assertEqual(check_archive_arch.check(archive), [], name)

    def test_an_intel_binary_in_an_arm64_macos_archive_is_refused(self) -> None:
        # What the vendored Makefile's hard-coded `-arch x86_64` produced on an arm64 runner.
        archive = self.pack("romwright-1-macos-aarch64.tar.gz",
                            {"bin/romwright-cli": macho(MACHO_ARM64),
                             "bin/ghidra_opt": macho(MACHO_X64)})
        problems = check_archive_arch.check(archive)
        self.assertEqual(len(problems), 1)
        self.assertIn("ghidra_opt", problems[0])
        command = [sys.executable, str(ROOT / "packaging" / "check_archive_arch.py"), str(archive)]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)

    def test_a_universal_binary_must_hold_only_the_archives_architecture(self) -> None:
        archive = self.pack("romwright-1-macos-aarch64.tar.gz",
                            {"bin/romwright-cli": fat(MACHO_ARM64, MACHO_X64)})
        self.assertEqual(len(check_archive_arch.check(archive)), 1)

    def test_the_wrong_format_machine_or_missing_binary_is_refused(self) -> None:
        for name, files in (
                ("romwright-1-windows-x86_64.zip", {"bin/romwright-cli.exe": pe(0xAA64)}),
                ("romwright-1-linux-x86_64.tar.gz", {"bin/romwright-cli": elf(183)}),
                ("romwright-1-linux-x86_64.tar.gz", {"bin/romwright-cli": macho(MACHO_X64)}),
                ("romwright-1-linux-x86_64.tar.gz", {"bin/romwright-cli": b"#!/bin/sh\n"}),
                ("romwright-1-linux-x86_64.tar.gz", {"README.txt": b"no binary"}),
                ("romwright-1-linux-riscv64.tar.gz", {"bin/romwright-cli": elf(243)})):
            self.assertTrue(check_archive_arch.check(self.pack(name, files)), (name, files))


@unittest.skipIf(os.name == "nt", "the build scripts are bash scripts; they run on Linux/macOS CI")
class DarwinMakeArguments(unittest.TestCase):
    """native/build_*.sh pass the host architecture to make on macOS; the vendored
    Makefile (which must stay unedited) hard-codes `-arch x86_64`. A fake `uname`
    reports Darwin and a fake `make` records its arguments."""

    def run_script(self, script: str, machine: str) -> list[str]:
        with tempfile.TemporaryDirectory() as scratch:
            tools = Path(scratch) / "bin"
            tools.mkdir()
            log = Path(scratch) / "make.log"
            (tools / "uname").write_text(
                '#!/bin/sh\ncase "$1" in -m) echo "%s";; *) echo Darwin;; esac\n' % machine,
                encoding="utf-8")
            # make: record the arguments, then leave behind the products the script copies.
            (tools / "make").write_text(
                '#!/bin/sh\nfor a in "$@"; do printf "%%s\\n" "$a"; done > "%s"\n'
                'touch sleigh_opt ghidra_opt\n' % log, encoding="utf-8")
            # c++ builds the hash self-test on the ghidra_opt path: stand in for it.
            (tools / "c++").write_text(
                '#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done\n'
                'printf "#!/bin/sh\\nexit 0\\n" > "$out"; chmod +x "$out"\n', encoding="utf-8")
            for tool in tools.iterdir():
                tool.chmod(0o755)
            env = dict(os.environ, PATH=f"{tools}{os.pathsep}{os.environ['PATH']}", TMPDIR=scratch)
            result = subprocess.run(["bash", str(ROOT / "native" / script), "--jobs", "1",
                                     str(Path(scratch) / "out")], env=env, capture_output=True,
                                    text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return log.read_text(encoding="utf-8").splitlines()

    def test_arm64_hosts_build_arm64_with_a_deployment_target_arm64_supports(self) -> None:
        for script in ("build_sleigh.sh", "build_ghidra_opt.sh"):
            arguments = self.run_script(script, "arm64")
            self.assertIn("ARCH_TYPE=-arch arm64", arguments, script)
            self.assertIn("ADDITIONAL_FLAGS=-mmacosx-version-min=11.0 -w", arguments, script)
            self.assertFalse([a for a in arguments if "x86_64" in a], script)

    def test_intel_hosts_build_x86_64(self) -> None:
        for script in ("build_sleigh.sh", "build_ghidra_opt.sh"):
            arguments = self.run_script(script, "x86_64")
            self.assertIn("ARCH_TYPE=-arch x86_64", arguments, script)
            self.assertFalse([a for a in arguments if "arm64" in a], script)

    def test_an_unknown_macos_architecture_fails_instead_of_guessing(self) -> None:
        with self.assertRaises(AssertionError):
            self.run_script("build_sleigh.sh", "ppc")


class Languages(unittest.TestCase):
    def test_every_language_has_sources_and_installs_a_module(self) -> None:
        chosen = languages.specs()
        self.assertEqual({spec.name for spec in chosen},
                         {"psx", "r5900", "rsp", "vu", "xenon", "gekko"})
        for spec in chosen:
            for source, _ in spec.copy_to_stage:
                self.assertTrue(source.is_file(), source)
            for source, name in spec.install:
                self.assertTrue(source == "stage" or source.is_file(), name)
            self.assertTrue(any(name.endswith(".ldefs") for _, name in spec.install), spec.name)

    def test_unknown_language_is_refused_and_nothing_is_current_in_an_empty_install(self) -> None:
        with self.assertRaises(ghidra_data.SetupError):
            languages.select(["nonesuch"])
        with tempfile.TemporaryDirectory() as scratch:
            self.assertFalse(languages.is_current(Path(scratch)))
            with self.assertRaises(ghidra_data.SetupError):
                languages.install(Path(scratch), Path(scratch) / "cache")

    def test_the_ps2_fixture_is_a_little_endian_mips_elf_with_the_ee_flags(self) -> None:
        image = smoke_fixtures.ps2_elf()
        self.assertEqual(image[:4], b"\x7fELF")
        self.assertEqual(int.from_bytes(image[18:20], "little"), 8)  # EM_MIPS
        self.assertEqual(int.from_bytes(image[36:40], "little") >> 28, 2)  # EF_MIPS_ARCH_3


if __name__ == "__main__":
    unittest.main(verbosity=2)
