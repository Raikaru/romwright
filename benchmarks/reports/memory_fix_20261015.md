# Memory fix: 2026-10-15

Host vultr.guest, load at start 0.66. Before: `/home/raikaru/runs/MemoryFix/basebin`; after: `/home/raikaru/runs/MemoryFix/ventris/target/release` (`romwright-cli` sha256 `42a5aee43acf` and `76aa82f05271`). Every import cold (`ROMWRIGHT_NO_IMPORT_CACHE=1`).
Verdict: **PASS** imports inside envelope: yes, session not larger: yes, results identical: yes, images not slower: yes

## Import peak (m7-001's measure: the largest process, `ru_maxrss`, KiB)

| entry | frozen | limit (x1.25) | before | after | after: largest process at its peak, anon / file | decoders built before / after | pass |
|---|---|---|---|---|---|---|---|
| x86_64_plain_o0 | 40568 | 50710 | 299204 | 40212 | ghidra_opt: 32268 / 5604 | 7 / 1 | yes |
| x86_64_plain_o2 | 40612 | 50765 | 298844 | 40236 | ghidra_opt: 33040 / 6496 | 7 / 1 | yes |
| x86_64_plain_pie | 40648 | 50810 | 299024 | 40164 | ghidra_opt: 32820 / 5640 | 7 / 1 | yes |
| x86_64_cpp_o2 | 40752 | 50940 | 297416 | 40164 | ghidra_opt: 33048 / 5636 | 7 / 1 | yes |
| x86_64_many_o2 | 42892 | 53615 | 298872 | 40112 | ghidra_opt: 33068 / 6568 | 7 / 1 | yes |
| i386_plain_o0 | 33704 | 42130 | 244536 | 32880 | ghidra_opt: 25904 / 6560 | 7 / 1 | yes |
| i386_plain_o2 | 33576 | 41970 | 244476 | 33064 | ghidra_opt: 25904 / 6744 | 7 / 1 | yes |
| i386_plain_pie | 33696 | 42120 | 243568 | 33040 | ghidra_opt: 25900 / 7184 | 7 / 1 | yes |
| i386_cpp_o2 | 33780 | 42225 | 243360 | 32928 | ghidra_opt: 25128 / 5644 | 7 / 1 | yes |
| i386_many_o2 | 35792 | 44740 | 245168 | 33056 | ghidra_opt: 25932 / 5836 | 7 / 1 | yes |
| aarch64_plain_o0 | 36284 | 45355 | 249156 | 35524 | ghidra_opt: 28560 / 6980 | 6 / 1 | yes |
| aarch64_plain_o2 | 36284 | 45355 | 248768 | 35696 | ghidra_opt: 25208 / 5716 | 6 / 1 | yes |
| aarch64_plain_pie | 36428 | 45535 | 248948 | 35716 | ghidra_opt: 28564 / 7204 | 6 / 1 | yes |
| aarch64_cpp_o2 | 36388 | 45485 | 249600 | 35684 | ghidra_opt: 28564 / 5788 | 6 / 1 | yes |
| aarch64_many_o2 | 36412 | 45515 | 251104 | 35708 | ghidra_opt: 28592 / 6472 | 6 / 1 | yes |
| powerpc_plain_o0 | 18736 | 23420 | 90336 | 20084 | romwright-cli: 7308 / 11984 | 7 / 1 | yes |
| powerpc_plain_o2 | 18736 | 23420 | 90432 | 20364 | romwright-cli: 6476 / 12452 | 7 / 1 | yes |
| powerpc_plain_pie | 18736 | 23420 | 90268 | 19964 | romwright-cli: 8104 / 12072 | 7 / 1 | yes |
| powerpc_cpp_o2 | 18736 | 23420 | 92504 | 20648 | romwright-cli: 8560 / 12404 | 7 / 1 | yes |
| powerpc_many_o2 | 18736 | 23420 | 91904 | 21596 | romwright-cli: 8784 / 11892 | 7 / 1 | yes |

Median 246968.0 -> 34294.0 KiB; entries over the limit after: none.

## Session (m7-003's measure: the service and the decompiler children, resident KiB)

| entry | frozen | limit (x1.25) | before peak | after peak | before processes at end | after | growth after warm-up before / after | pass |
|---|---|---|---|---|---|---|---|---|
| x86_64_plain_o0 | 47568 | 59460 | 344060 | 54376 | 9 | 2 | 123348 / 20 | yes |
| i386_plain_o0 | 40184 | 50230 | 286440 | 47320 | 9 | 2 | 101716 / 32 | yes |
| aarch64_plain_o0 | 43192 | 53990 | 307492 | 50080 | 9 | 2 | 109812 / 20 | yes |
| powerpc_plain_o0 | 23756 | 29695 | 152004 | 30488 | 9 | 2 | 51372 / 24 | NO |

Still over the frozen limit after the fix: powerpc_plain_o0. The service is down from 9 processes to 2 and from hundreds of MiB to the figures above; what remains is the resident code of the service binary and of the decompiler beside it.

## Components of a tiny import (the importing process alone: decompiler stage off, KiB)

| entry | before (4 lanes + plain lifter, each a full decoder) | after, tables decoded eagerly | after | what sharing one decoder saved | what lazy tables saved | after: anon / file at peak | decoder builds before / after |
|---|---|---|---|---|---|---|---|
| x86_64_plain_o0 | 298496 | 55236 | 22468 | 243260 | 32768 | romwright-cli: 11224 / 10880 | 7 / 1 |
| i386_plain_o0 | 244228 | 46168 | 21552 | 198060 | 24616 | romwright-cli: 10464 / 11104 | 7 / 1 |
| aarch64_plain_o0 | 248964 | 49996 | 23700 | 198968 | 26296 | romwright-cli: 11556 / 10900 | 6 / 1 |
| powerpc_plain_o0 | 90096 | 24948 | 19664 | 65148 | 5284 | romwright-cli: 7140 / 11672 | 7 / 1 |

## Large images: paired wall time, peak tree RSS, identical rows

| image | before wall (s) | after wall (s) | after / before | before CPU (s, user+sys) | after CPU | after / before | before peak tree MiB | after | tables / rows compared | identical |
|---|---|---|---|---|---|---|---|---|---|---|
| gc-melee | 19.261 (19.261, 19.29, 19.233) | 18.776 (18.727, 18.843, 18.759) | 0.975 | 39.375 | 38.554 | 0.979 | 2085 | 2043 | 42 / 386925 | yes |
| gba-pokeemerald | 15.74 (15.733, 15.671, 15.816) | 15.075 (15.115, 15.044, 15.065) | 0.958 | 34.388 | 33.253 | 0.967 | 1461 | 1430 | 42 / 231818 | yes |
| ps2-persona-4 | 24.986 (24.933, 24.989, 25.036) | 18.543 (18.492, 18.636, 18.502) | 0.742 | 41.716 | 34.748 | 0.833 | 1549 | 1520 | 42 / 165812 | yes |

