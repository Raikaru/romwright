#!/bin/bash
# GLQuake (Quake 1 GPL, WinQuake/ GL Release target, C only: no .s/.asm) with MSVC 4.2 (itsmattkc/msvc420) under wine. usage: scripts_wq_msvc42.sh OUTDIR
. ~/runs/PcImport/wenv.sh
T4=$HOME/runs/PcImport/tc/msvc420
O=${1:-~/runs/PcImport/build/wq-msvc42}; mkdir -p $O; cd $O
# C-only build (the engine supports it for non-x86 hosts): a copy of WinQuake/ with the x86-assembly switch turned off
S=$O/WinQuake; rm -rf $S; cp -r ~/runs/PcImport/src/Quake/WinQuake $S
sed -i "s/^#if defined(_M_IX86)/#if 0 \/\* C-only build, id386 = 0 \*\//" $S/quakedef.h $S/quakeasm.h
sed -i "273s/^#ifndef _M_IX86/#if 1 \/\* C-only build: the FPU control-word stubs \*\//" $S/sys_win.c
export INCLUDE="Z:$T4/include;Z:$HOME/runs/PcImport/shim" LIB="Z:$T4/lib"
FILES=$(python3 ~/runs/PcImport/glquake_files.py $S/WinQuake.dsp | tr " " "\n" | sed "s#^#Z:$S/#" | tr "\n" " ")
$WINE $T4/bin/cl.exe /nologo /O2 /G5 /ML /Z7 /D WIN32 /D NDEBUG /D _WINDOWS /D GLQUAKE /W1 /c $FILES 2>&1 | grep -i "error" | head -30
LIBS="comctl32.lib winmm.lib wsock32.lib opengl32.lib glu32.lib kernel32.lib user32.lib gdi32.lib advapi32.lib"
$WINE $T4/bin/link.exe /nologo /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /OPT:REF /MACHINE:I386 /MAP:glquake.map /OUT:glquake.exe *.obj $LIBS 2>&1 | head
$WINE $T4/bin/link.exe /nologo /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /OPT:REF /MACHINE:I386 /DEBUG /DEBUGTYPE:COFF /MAP:glquake-debug.map /OUT:glquake-debug.exe *.obj $LIBS 2>&1 | head
ls -la glquake.exe glquake-debug.exe
