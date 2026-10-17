#!/bin/sh
args=""
for a in "$@"; do case "$a" in -DWINDOWS_ICON_PATH=*) ;; *) args="$args $a";; esac; done
exec $HOME/runs/PcImport/mingw/usr/bin/x86_64-w64-mingw32-windres -I $HOME/runs/PcImport/src/ioq3/misc/windows $args
