"""Tool resolution and the compile commands of a romwright MIPS project (N64, PlayStation, PSP).

`configure.py` and `tools/cc.py` both import this, so the build and
`romwright-cli match` compile a unit the same way. The tools come from
`config/toolchain.json` (a pinned manifest, fetched into build/tools/ by
`tools/download_tool.py`) or from a toolchain profile that replaces them one by one.
"""
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import download_tool  # noqa: E402

PROJECT = json.loads((ROOT / "config" / "project.json").read_text())
BUILD = ROOT / "build"
LOCAL_PROFILE = ROOT / "config" / "toolchain.local.json"


class Tools:
    """Every executable the build runs, resolved once."""

    def __init__(self):
        self.paths = {}      # as / ld / objcopy / objdump / wibo / objdiff-cli
        self.dirs = {}       # manifest tool id -> install directory
        self.cc = []         # argv prefix of the C compiler driver
        self.env = {}        # environment for compiles
        self.compile_template = None
        self.given = {}      # tools the profile supplied, by name
        self.launcher = []   # profile recipe launcher (+ arguments)

    def need(self, name):
        if name not in self.paths:
            raise SystemExit(f"tool `{name}` is not available (neither in a profile nor the manifest)")
        return self.paths[name]


def load_profile(path):
    profile = json.loads(Path(path).read_text())
    for key, entry in (profile.get("tools") or {}).items():
        digest = (entry.get("digest") or "").lower()
        if digest and len(digest) == 64:
            actual = download_tool.sha256_file(entry["path"])
            if actual != digest:
                raise SystemExit(f"{path}: tool `{key}` ({entry['path']}) sha256 {actual} != profile digest {digest}")
    return profile


def resolve_tools(args=None, download=True):
    """`args` carries `manifest`, `toolchain` and `no_tools` (any may be missing)."""
    manifest_path = getattr(args, "manifest", None) or ROOT / "config" / "toolchain.json"
    no_tools = getattr(args, "no_tools", False) or not download
    manifest = download_tool.load_manifest(manifest_path)
    spec = PROJECT["tools"]
    profile_path = getattr(args, "toolchain", None) or (LOCAL_PROFILE if LOCAL_PROFILE.exists() else None)
    profile = load_profile(profile_path) if profile_path else {}
    given = {key: entry["path"] for key, entry in (profile.get("tools") or {}).items()}
    recipe = profile.get("recipe") or {}
    tools = Tools()
    tools.env = dict(recipe.get("environment") or {})
    tools.compile_template = profile.get("compile_arguments")
    tools.given = given

    def where(tool_id):
        """Install directory of a manifest tool (downloaded unless --no-tools)."""
        if tool_id not in tools.dirs:
            if no_tools:
                tools.dirs[tool_id] = BUILD / "tools" / tool_id
            else:
                tools.dirs[tool_id] = download_tool.install(manifest[tool_id], BUILD / "tools", BUILD / "tools" / ".cache")
        return tools.dirs[tool_id]

    tools.where = where
    binutils = manifest[spec["binutils"]]
    installed = None
    for key, member in binutils["provides"].items():
        if key in given:
            tools.paths[key] = given[key]
            continue
        installed = installed or where(binutils["id"])
        tools.paths[key] = str(installed / member)
    compiler = manifest[spec["compiler"]]
    windows_exe = given["compiler"].lower().endswith(".exe") if "compiler" in given else compiler.get("runtime") == "wibo"
    if recipe.get("compiler"):
        launcher = [recipe["compiler"], *recipe.get("arguments", [])]
    elif windows_exe:
        launcher = [given.get("wibo") or str(where("wibo") / "wibo")]
    else:
        launcher = []
    tools.launcher = launcher
    if launcher:
        tools.paths["wibo"] = launcher[0]
    elif spec.get("runtime") == "wibo" and "wibo" in given:
        tools.paths["wibo"] = given["wibo"]
    elif spec.get("runtime") == "wibo":
        tools.paths["wibo"] = str(where("wibo") / "wibo")
    for tool_id in spec.get("extra", []):
        where(tool_id)
    if "compiler" in given:
        tools.cc = [*launcher, given["compiler"]]
    else:
        tools.cc = [*launcher, str(where(compiler["id"]) / compiler["entry"])]
        if compiler.get("runtime") == "i386-linux" and not Path("/lib/ld-linux.so.2").exists():
            print(
                f"warning: {compiler['id']} is a 32-bit Linux build and /lib/ld-linux.so.2 is missing; "
                "install your distribution's 32-bit libc (libc6-i386 / glibc.i686).",
                file=sys.stderr,
            )
    if "objdiff-cli" in given:
        tools.paths["objdiff-cli"] = given["objdiff-cli"]
    elif spec.get("report") and not no_tools:
        try:
            tools.paths["objdiff-cli"] = str(where(spec["report"]) / "objdiff-cli")
        except SystemExit as error:
            print(f"warning: objdiff-cli unavailable ({error}); `ninja progress` is disabled", file=sys.stderr)
    elif spec.get("report") and (BUILD / "tools" / spec["report"] / "objdiff-cli").exists():
        tools.paths["objdiff-cli"] = str(BUILD / "tools" / spec["report"] / "objdiff-cli")
    return tools


def quote(argv):
    return " ".join(shlex.quote(str(a)).replace("$", "$$") for a in argv)


def compile_environment(tools):
    scratch = BUILD / "tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    return {"TMPDIR": str(scratch), "TMP": str(scratch), "TEMP": str(scratch), **tools.env}


def template_argv(tools, source, output):
    """A profile's `compile_arguments` expanded for one unit, or None."""
    if not (tools.compile_template and any("{source}" in arg for arg in tools.compile_template)):
        return None
    argv = list(tools.launcher)
    for arg in tools.compile_template:
        import re
        tool = re.fullmatch(r"\{tool:([^}]+)\}", arg)
        if tool:
            argv.append(tools.given[tool.group(1)])
            continue
        argv.append(arg.replace("{root}", str(ROOT)).replace("{source}", str(source)).replace("{output}", str(output)))
    return argv


def tool_member(tools, tool_id, member):
    return str(tools.where(tool_id) / member)


def run(argv, env, **kwargs):
    return subprocess.run(argv, cwd=ROOT, env={**os.environ, **env}, **kwargs)


def trim_text(path):
    """Shrinks `.text` to the end of the last function when the rest is zero padding.

    IDO (and some other assemblers) round a unit's `.text` up to 16 bytes. A C unit is
    linked into the slot of the function it replaces, which is the function plus the
    padding the retail linker left, so trailing padding would overrun the slot and the
    link stops with "cannot move location counter backwards". Only the section size in
    the header changes; relocation offsets and symbols are untouched."""
    data = bytearray(Path(path).read_bytes())
    if data[:4] != b"\x7fELF" or data[4] != 1:
        return
    order = "big" if data[5] == 2 else "little"
    u16 = lambda at: int.from_bytes(data[at:at + 2], order)
    u32 = lambda at: int.from_bytes(data[at:at + 4], order)
    shoff, shentsize, shnum, shstrndx = u32(0x20), u16(0x2E), u16(0x30), u16(0x32)
    sections = [tuple(u32(shoff + i * shentsize + at) for at in (0, 4, 16, 20, 24)) for i in range(shnum)]  # name, type, offset, size, link
    names = sections[shstrndx][2]
    def name_of(section):
        start = names + section[0]
        return data[start:data.index(b"\0", start)].decode()
    text = next((i for i, s in enumerate(sections) if name_of(s) == ".text"), None)
    symtab = next((s for s in sections if s[1] == 2), None)
    if text is None or symtab is None:
        return
    end = 0
    for at in range(symtab[2], symtab[2] + symtab[3], 16):
        value, size, info, shndx = u32(at + 4), u32(at + 8), data[at + 12], u16(at + 14)
        if info & 0xF == 2 and shndx == text and size:
            end = max(end, value + size)
    _, _, offset, size, _ = sections[text]
    if 0 < end < size and not any(data[offset + end:offset + size]):
        data[shoff + text * shentsize + 20:shoff + text * shentsize + 24] = end.to_bytes(4, order)
        Path(path).write_bytes(bytes(data))


def compile_unit(tools, source, output):
    """Compiles one C file to an ELF object the way this project's compiler is driven
    and trims the trailing `.text` padding. Returns the last step's process result."""
    result = compile_unit_raw(tools, source, output)
    if result is not None and result.returncode == 0 and Path(output).exists():
        trim_text(output)
    return result


def compile_unit_raw(tools, source, output):
    env = compile_environment(tools)
    flags = list(PROJECT["compiler"]["cflags"])
    kind = PROJECT["compiler"]["kind"]
    argv = template_argv(tools, source, output)
    if argv:
        return run(argv, env, capture_output=True)
    if kind == "ido":
        return run([*tools.cc, "-c", *flags, "-Iinclude", "-o", str(output), str(source)], env, capture_output=True)
    if kind == "gcc-mips":
        dirs = [str(tools.where(t)) + "/" for t in PROJECT["tools"]["compiler_dirs"]]
        prefixes = [arg for d in dirs for arg in ("-B", d)]
        return run([*tools.cc, "-c", *prefixes, *flags, "-Iinclude", "-o", str(output), str(source)], env, capture_output=True)
    if kind == "psyq":
        return compile_psyq(tools, source, output, env, flags)
    if kind == "psp-gcc":
        return compile_psp_gcc(tools, source, output, env, flags)
    if kind == "mwcc-psp":
        return run([*tools.cc, *flags, "-Iinclude", "-c", str(source), "-o", str(output)], env, capture_output=True)
    raise SystemExit(f"unknown compiler kind {kind!r}")


def scratch_file(source, suffix):
    return BUILD / "tmp" / (Path(source).name + "." + str(os.getpid()) + suffix)


def chain(steps):
    """Runs argv steps in order; stops at the first failure and returns its result."""
    result = None
    for argv, env, kwargs in steps:
        result = run(argv, env, capture_output=True, **kwargs)
        if result.returncode:
            return result
    return result


def compile_psyq(tools, source, output, env, flags):
    """PSY-Q: CPPPSX -> CC1PSX -> maspsx (-> GNU as). The preprocessor and compiler are
    Windows executables run through wibo; maspsx rewrites ASPSX-isms for GNU as."""
    psyq = Path(tools.cc[-1]).parent
    wibo = [tools.paths["wibo"]]
    maspsx_dir = tools.where("maspsx")
    maspsx = next(maspsx_dir.glob("*/maspsx.py"))
    pre, asm = scratch_file(source, ".i"), scratch_file(source, ".s")
    cpp_flags = [f for f in flags if f.startswith(("-D", "-I", "-U"))]
    cc_flags = [f for f in flags if not f.startswith(("-D", "-I", "-U", "-aspsx="))]
    aspsx_flag = next((f.split("=", 1)[1] for f in flags if f.startswith("-aspsx=")), None)
    gcc_g = next((f for f in flags if f.startswith("-G")), "-G0")
    steps = [
        ([*wibo, str(psyq / "CPPPSX.EXE"), "-undef", "-D__GNUC__=2", "-D__OPTIMIZE__", "-Iinclude", *cpp_flags, "-lang-c", str(source), str(pre)], env, {}),
        ([*wibo, str(psyq / "CC1PSX.EXE"), "-quiet", *cc_flags, "-o", str(asm), str(pre)], env, {}),
    ]
    result = chain(steps)
    if result.returncode:
        return result
    # CC1PSX stamps the ASPSX it was built to feed (`SDevTC ASPSX version 2.77`); maspsx
    # emulates that version unless the flags say otherwise.
    import re
    stamp = re.search(r"ASPSX version (\d+\.\d+)", asm.read_text(errors="replace"))
    aspsx = aspsx_flag or (stamp.group(1) if stamp else PROJECT["compiler"].get("aspsx", "2.77"))
    return chain([(
        [sys.executable, str(maspsx), "--run-assembler", "--force-stdin", "--gnu-as-path", tools.need("as"), f"--aspsx-version={aspsx}",
         *PROJECT["compiler"]["asflags"], gcc_g, "-o", str(output)],
        env, {"input": asm.read_bytes()},
    )])


def compile_psp_gcc(tools, source, output, env, flags):
    """psp-gcc: the i386 `cc1` writes assembly, GNU as (the project's own binutils) assembles it."""
    asm = scratch_file(source, ".s")
    gcc = [*tools.cc]
    # The driver looks for `cc1` under the prefix it was built for; the archive keeps it in lib/gcc-lib/psp/<version>/.
    prefix = []
    if "compiler" not in tools.given:
        for libdir in sorted((tools.where(PROJECT["tools"]["compiler"]) / "lib" / "gcc-lib" / "psp").glob("*/")):
            prefix = ["-B", str(libdir) + "/"]
    steps = [
        ([*gcc, "-S", *prefix, *flags, "-Iinclude", "-o", str(asm), str(source)], env, {}),
        ([tools.need("as"), *PROJECT["compiler"]["asflags"], "-o", str(output), str(asm)], env, {}),
    ]
    return chain(steps)
