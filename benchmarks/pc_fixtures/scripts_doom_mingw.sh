#!/bin/bash
# doomgeneric (GPL-2.0 port of id Software DOOM) Win32 GDI frontend with MinGW-w64. usage: scripts_doom_mingw.sh ARCH(i686|x86_64) OUTDIR EXTRA_CFLAGS...
ARCH=$1; O=$2; shift 2
export PATH=$HOME/runs/PcImport/mingw/usr/bin:$PATH
S=~/runs/PcImport/src/doomgeneric/doomgeneric; mkdir -p $O; cd $S
SRCS=$(grep "^SRC_DOOM" -A5 Makefile.win | tr " \\\\" "\n\n" | grep "\.o$" | sed "s/\.o$/.c/" | tr "\n" " ")
$ARCH-w64-mingw32-gcc -g -DSNDSERV -D_DEFAULT_SOURCE -w -I$HOME/runs/PcImport/shim/mingw "$@" -o $O/doomgeneric.exe $SRCS -lm -lgdi32 -Wl,-Map,$O/doomgeneric.map
ls -la $O/doomgeneric.exe
