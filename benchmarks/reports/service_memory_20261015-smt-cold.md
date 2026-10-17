# Service memory: 20261015-smt-cold

Host load at the end 0.68; before `romwright-api` afcb97b98668, after 008cdb1bf56e; 3 alternating repeats per entry, binaries dropped from the page cache first. Verdict: **PASS** (every after run inside the frozen limit, every `decompile_doc` reply the same JSON value or, where the decompiler is not deterministic, the same tokens).

| entry | frozen | limit (x1.25) | before runs | after runs | after: service / decompiler peak | service at end anon / file | reply bytes | documents equal / tokens equal | pass |
|---|---|---|---|---|---|---|---|---|---|
| x86_64_plain_o0 | 47568 | 59460 | 54388, 54224, 54376 | 52368, 52368, 52292 | 12292 / 40076 | 1896 / 10280 | 17382 | yes / yes | yes |
| x86_64_plain_o2 | 47540 | 59425 | 54520, 54300, 54500 | 52328, 52184, 52272 | 12272 / 39988 | 1884 / 10372 | 11296 | yes / yes | yes |
| x86_64_plain_pie | 47452 | 59315 | 54124, 54276, 54312 | 52412, 52752, 52412 | 12364 / 40068 | 1892 / 10444 | 11296 | yes / yes | yes |
| x86_64_cpp_o2 | 47816 | 59770 | 55392, 55256, 55324 | 53068, 52748, 52564 | 12668 / 40056 | 2116 / 10328 | 85020 | no, decompiler nondeterministic / yes | yes |
| x86_64_many_o2 | 79828 | 99785 | 95304, 95504, 95304 | 77708, 79244, 78600 | 21280 / 57320 | 5992 / 10364 | 2113453 | yes / yes | yes |
| i386_plain_o0 | 40184 | 50230 | 47100, 47108, 47192 | 44980, 45328, 45284 | 12392 / 32936 | 1916 / 10444 | 17374 | yes / yes | yes |
| i386_plain_o2 | 40496 | 50620 | 46968, 47236, 47092 | 45508, 45492, 45080 | 12592 / 32900 | 1892 / 10224 | 11298 | yes / yes | yes |
| i386_plain_pie | 40496 | 50620 | 47164, 47196, 47056 | 45436, 45172, 45144 | 12276 / 32928 | 1916 / 10288 | 11295 | yes / yes | yes |
| i386_cpp_o2 | 40632 | 50790 | 48184, 48176, 48432 | 45764, 45284, 45852 | 12860 / 32924 | 2060 / 10792 | 85116 | no, decompiler nondeterministic / yes | yes |
| i386_many_o2 | 65308 | 81635 | 79996, 79980, 79976 | 65884, 65412, 66600 | 23800 / 42108 | 11000 / 10700 | 2125478 | yes / yes | yes |
| aarch64_plain_o0 | 43192 | 53990 | 49592, 49884, 49804 | 47636, 47836, 47840 | 12252 / 35576 | 1840 / 10384 | 17393 | yes / yes | yes |
| aarch64_plain_o2 | 43004 | 53755 | 49740, 49540, 49908 | 47956, 47880, 48100 | 12404 / 35588 | 1840 / 10684 | 11268 | yes / yes | yes |
| aarch64_plain_pie | 43068 | 53835 | 49944, 49864, 49700 | 47672, 47740, 47792 | 12140 / 35568 | 1824 / 10388 | 11268 | yes / yes | yes |
| aarch64_cpp_o2 | 43248 | 54060 | 50664, 50688, 50728 | 48312, 48160, 48264 | 12672 / 35568 | 2036 / 10624 | 85530 | no, decompiler nondeterministic / yes | yes |
| aarch64_many_o2 | 65220 | 81525 | 81096, 81184, 81072 | 64676, 63048, 63804 | 20900 / 42916 | 5896 / 10436 | 2112873 | yes / yes | yes |
| powerpc_plain_o0 | 23756 | 29695 | 30324, 30344, 30300 | 28236, 28104, 28036 | 12112 / 15992 | 2072 / 9988 | 17436 | yes / yes | yes |
| powerpc_plain_o2 | 23508 | 29385 | 30480, 30500, 30424 | 28700, 28604, 28296 | 12708 / 15992 | 2048 / 10224 | 11326 | yes / yes | yes |
| powerpc_plain_pie | 23700 | 29625 | 30332, 30312, 30340 | 28732, 28204, 28160 | 12220 / 15968 | 2084 / 10076 | 11689 | yes / yes | yes |
| powerpc_cpp_o2 | 23828 | 29785 | 31492, 31444, 31488 | 28844, 28928, 28928 | 12892 / 16036 | 2256 / 10604 | 97437 | no, decompiler nondeterministic / yes | yes |
| powerpc_many_o2 | 44220 | 55275 | 60040, 59868, 60180 | 43304, 41040, 41264 | 19636 / 21628 | 6068 / 10236 | 2108403 | yes / yes | yes |
