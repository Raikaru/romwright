#!/bin/bash
# Quake 2 (GPL) client+server with null video/sound/input, MSVC 8.0 under wine. usage: scripts_q2_msvc8.sh OUTDIR
. ~/runs/PcImport/wenv.sh
S=~/runs/PcImport/src/Quake-2; O=${1:-~/runs/PcImport/build/q2-msvc8}; mkdir -p $O; cd $O
export INCLUDE="Z:$T8/include;Z:$T8/PlatformSDK/Include;Z:$HOME/runs/PcImport/shim" LIB="Z:$T8/lib;Z:$T8/PlatformSDK/Lib"
SRC="$S/client/*.c $S/qcommon/*.c $(ls $S/server/*.c | grep -v sv_null) $S/game/q_shared.c $S/game/m_flash.c $S/null/snddma_null.c $S/win32/cd_win.c $S/win32/conproc.c $S/win32/in_win.c $S/win32/net_wins.c $S/win32/q_shwin.c $S/win32/sys_win.c $S/win32/vid_dll.c $S/win32/vid_menu.c /home/raikaru/runs/PcImport/shim/snd_shim.c"
FILES=$(ls $SRC | sed "s#^#Z:#")
echo "$FILES" | tr "\n" " " > files.rsp
$WINE $T8/bin/cl.exe /nologo /O2 /MT /Zi /Fd:q2.pdb /D WIN32 /D NDEBUG /D _WINDOWS /D _CRT_SECURE_NO_DEPRECATE /D _CRT_NONSTDC_NO_DEPRECATE /W1 /c @files.rsp 2>&1 | grep -v "^[a-z_0-9]*\.c$" | head -60
$WINE $T8/bin/link.exe /nologo /DEBUG /PDB:quake2.pdb /MAP /OUT:quake2.exe /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /MACHINE:X86 *.obj winmm.lib wsock32.lib kernel32.lib user32.lib gdi32.lib advapi32.lib 2>&1 | head -40
ls -la quake2.exe quake2.pdb
