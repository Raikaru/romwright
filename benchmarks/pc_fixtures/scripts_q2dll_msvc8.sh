#!/bin/bash
# Quake 2 game DLL and ref_gl DLL, MSVC 8.0 under wine. usage: scripts_q2dll_msvc8.sh OUTDIR
. ~/runs/PcImport/wenv.sh
S=~/runs/PcImport/src/Quake-2; O=${1:-~/runs/PcImport/build/q2dll-msvc8}; mkdir -p $O/game $O/refgl; 
export INCLUDE="Z:$T8/include;Z:$T8/PlatformSDK/Include;Z:$HOME/runs/PcImport/shim" LIB="Z:$T8/lib;Z:$T8/PlatformSDK/Lib"
CF="/nologo /O2 /MT /Zi /D WIN32 /D NDEBUG /D _WINDOWS /D _CRT_SECURE_NO_DEPRECATE /D _CRT_NONSTDC_NO_DEPRECATE /W1"
cd $O/game
ls $S/game/*.c | sed "s#^#Z:#" | tr "\n" " " > files.rsp
$WINE $T8/bin/cl.exe $CF /Fd:game.pdb /c @files.rsp 2>&1 | grep -i "error" | head
$WINE $T8/bin/link.exe /nologo /DLL /DEBUG /PDB:gamex86.pdb /MAP /OUT:gamex86.dll /DEF:Z:$S/game/game.def /INCREMENTAL:NO /MACHINE:X86 *.obj 2>&1 | head
cd $O/refgl
ls $S/ref_gl/*.c $S/game/q_shared.c $S/win32/q_shwin.c $S/win32/glw_imp.c $S/win32/qgl_win.c | sed "s#^#Z:#" | tr "\n" " " > files.rsp
$WINE $T8/bin/cl.exe $CF /Fd:refgl.pdb /c @files.rsp 2>&1 | grep -i "error" | head
$WINE $T8/bin/link.exe /nologo /DLL /DEBUG /PDB:ref_gl.pdb /MAP /OUT:ref_gl.dll /DEF:Z:$S/ref_gl/ref_gl.def /INCREMENTAL:NO /MACHINE:X86 *.obj winmm.lib kernel32.lib user32.lib gdi32.lib opengl32.lib glu32.lib 2>&1 | head
ls -la $O/game/gamex86.dll $O/refgl/ref_gl.dll
