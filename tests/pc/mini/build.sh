#!/bin/sh
# Builds the PcProject mini fixture (original code, no third-party source) into a truth-contract directory.
# usage: build.sh MSVC60_DIR OUTDIR     MSVC60_DIR: the pinned `msvc6.0` tree (Bin/, Include/)
set -e
M=$1; O=$2; mkdir -p "$O/truth"; cp mini.c "$O/"
cd "$O"
INCLUDE="Z:$M/Include" wibo "$M/Bin/CL.EXE" /nologo /c /O2 /Gd /Fomini.obj mini.c
wibo "$M/Bin/LINK.EXE" /nologo /NODEFAULTLIB /ENTRY:start /SUBSYSTEM:CONSOLE /FIXED /OPT:NOREF /MAP:mini.map /OUT:mini.exe mini.obj
# truth/functions.tsv: the map's function symbols, each size = the gap to the next symbol less the int3 fill
python3 - <<'PY'
import re, struct, json, hashlib
d = open('mini.exe', 'rb').read(); m = open('mini.map').read()
rows = sorted((int(g.group(3), 16), g.group(2)) for g in (re.match(r'\s*0001:([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+) f', l) for l in m.splitlines()) if g)
pe = struct.unpack_from('<I', d, 0x3c)[0]; nsec = struct.unpack_from('<H', d, pe + 6)[0]; opt = struct.unpack_from('<H', d, pe + 20)[0]
for i in range(nsec):
    n, vs, va, rs, ro = struct.unpack_from('<8sIIII', d, pe + 24 + opt + 40 * i)
    if n.startswith(b'.text'): tva, tvs, tro = va + 0x400000, vs, ro
out = ['start\tsize\tname\tmodule\tverified']
for i, (a, n) in enumerate(rows):
    nxt = rows[i + 1][0] if i + 1 < len(rows) else tva + tvs
    out.append(f'0x{a:08x}\t{len(d[tro + a - tva: tro + nxt - tva].rstrip(bytes([0xcc])))}\t{n}\tmain\t1')
open('truth/functions.tsv', 'w').write('\n'.join(out) + '\n')
json.dump({'id': 'pc-pcproject-mini', 'image': 'mini.exe', 'truth_kind': 'tsv', 'platform': 'pc', 'compiler': 'msvc6.0', 'flags': '/O2 /Gd',
           'repo': 'romwright tests/pc/mini', 'version_match': True, 'sha1_expected': hashlib.sha1(d).hexdigest()}, open('truth/meta.json', 'w'), indent=1)
PY
