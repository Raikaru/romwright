# Layout the fixture scripts expect under $HOME/runs/PcImport (all unpacked without root; see docs/console-research.md "Windows PC"):
#   mingw/usr/bin/{i686,x86_64}-w64-mingw32-gcc ...   Fedora 44 mingw32-/mingw64-{gcc,binutils,crt,headers,winpthreads} RPMs, rpm2cpio | cpio
#   wine/usr/bin/{wine64,wineserver64}, wine/usr/share/wine   wine-core 11.0-3.fc44 + wine-filesystem RPMs (new WoW64)
#   tc/msvc8.0 (widberg/msvc8.0 @ 936f93b9), tc/msvc420 (itsmattkc/msvc420 @ df2c13aa), tc/mingw{32,64}.cmake, tc/windres-wrap*.sh
#   src/{Quake-2,Quake,ioq3,doomgeneric}   the game sources (commits in the fixtures' meta.json)
#   shim/   the shim headers of this directory;  build/   outputs;  pc_truth.py, glquake_files.py   from this directory
export WINEPREFIX=$HOME/runs/PcImport/wp WINEDEBUG=-all WINEDLLOVERRIDES="mscoree,mshtml=" DISPLAY= WINESERVER=$HOME/runs/PcImport/wine/usr/bin/wineserver64
WINE=$HOME/runs/PcImport/wine/usr/bin/wine64
T8=$HOME/runs/PcImport/tc/msvc8.0
