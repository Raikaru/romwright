#!/bin/bash
# Quake 2 game DLL as a Debug build: /Od /Zi /RTC1 /MTd, incremental link (incremental link table thunks). usage: scripts_q2game_msvc8_debug.sh OUTDIR
. ~/runs/PcImport/wenv.sh
S=~/runs/PcImport/src/Quake-2; O=${1:-~/runs/PcImport/build/q2game-msvc8-debug}; mkdir -p $O; cd $O
export INCLUDE="Z:$T8/include;Z:$T8/PlatformSDK/Include;Z:$HOME/runs/PcImport/shim" LIB="Z:$T8/lib;Z:$T8/PlatformSDK/Lib"
ls $S/game/*.c | sed "s#^#Z:#" | tr "\n" " " > files.rsp
$WINE $T8/bin/cl.exe /nologo /Od /RTC1 /MTd /Zi /D WIN32 /D _DEBUG /D _WINDOWS /D _CRT_SECURE_NO_DEPRECATE /D _CRT_NONSTDC_NO_DEPRECATE /W1 /Fd:game.pdb /c @files.rsp 2>&1 | grep -i " error" | head
$WINE $T8/bin/link.exe /nologo /DLL /DEBUG /PDB:gamex86.pdb /MAP /OUT:gamex86.dll /DEF:Z:$S/game/game.def /INCREMENTAL /MACHINE:X86 *.obj 2>&1 | head
ls -la gamex86.dll gamex86.pdb
