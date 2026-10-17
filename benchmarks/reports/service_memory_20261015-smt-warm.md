# Service memory: 20261015-smt-warm

Host load at the end 0.80; before `romwright-api` afcb97b98668, after 008cdb1bf56e; 3 alternating repeats per entry. Verdict: **PASS** (every after run inside the frozen limit, every `decompile_doc` reply the same JSON value or, where the decompiler is not deterministic, the same tokens).

| entry | frozen | limit (x1.25) | before runs | after runs | after: service / decompiler peak | service at end anon / file | reply bytes | documents equal / tokens equal | pass |
|---|---|---|---|---|---|---|---|---|---|
| x86_64_plain_o0 | 47568 | 59460 | 54552, 54368, 54136 | 52236, 52072, 52408 | 12160 / 40040 | 1904 / 10444 | 17382 | yes / yes | yes |
| x86_64_plain_o2 | 47540 | 59425 | 54112, 54240, 54316 | 52696, 52192, 52236 | 12156 / 40080 | 1884 / 10244 | 11296 | yes / yes | yes |
| x86_64_plain_pie | 47452 | 59315 | 54524, 54444, 54040 | 52816, 52664, 52412 | 12668 / 40000 | 1888 / 10424 | 11296 | yes / yes | yes |
| x86_64_cpp_o2 | 47816 | 59770 | 55624, 55200, 55352 | 52536, 52492, 52680 | 12512 / 40056 | 2092 / 10500 | 85023 | no, decompiler nondeterministic / yes | yes |
| x86_64_many_o2 | 79828 | 99785 | 95432, 95288, 95520 | 79216, 78500, 79432 | 21868 / 57312 | 5972 / 10756 | 2113453 | yes / yes | yes |
| i386_plain_o0 | 40184 | 50230 | 46960, 47220, 47140 | 45012, 45152, 45516 | 12372 / 32888 | 1912 / 10684 | 17374 | yes / yes | yes |
| i386_plain_o2 | 40496 | 50620 | 47148, 46992, 47232 | 45016, 45040, 44880 | 12120 / 32896 | 1900 / 10064 | 11298 | yes / yes | yes |
| i386_plain_pie | 40496 | 50620 | 47500, 47016, 47220 | 44996, 45536, 45088 | 12196 / 32896 | 1904 / 10260 | 11295 | yes / yes | yes |
| i386_cpp_o2 | 40632 | 50790 | 48360, 48188, 48488 | 45524, 45800, 45252 | 12652 / 32896 | 2024 / 10224 | 85113 | no, decompiler nondeterministic / yes | yes |
| i386_many_o2 | 65308 | 81635 | 80452, 80420, 79876 | 67532, 67448, 67336 | 25336 / 42120 | 10996 / 10152 | 2125478 | yes / yes | yes |
| aarch64_plain_o0 | 43192 | 53990 | 49464, 49668, 49816 | 48008, 47740, 48048 | 12472 / 35556 | 1836 / 10628 | 17393 | yes / yes | yes |
| aarch64_plain_o2 | 43004 | 53755 | 49824, 49604, 49680 | 48144, 47868, 47824 | 12304 / 35580 | 1840 / 10372 | 11268 | yes / yes | yes |
| aarch64_plain_pie | 43068 | 53835 | 50056, 50208, 49824 | 47792, 47796, 47664 | 12228 / 35564 | 1824 / 10244 | 11268 | yes / yes | yes |
| aarch64_cpp_o2 | 43248 | 54060 | 50676, 50568, 50572 | 48200, 48184, 48116 | 12616 / 35564 | 2032 / 10508 | 85530 | no, decompiler nondeterministic / yes | yes |
| aarch64_many_o2 | 65220 | 81525 | 81076, 81196, 81224 | 62612, 62844, 64172 | 19888 / 42956 | 5904 / 10560 | 2112873 | yes / yes | yes |
| powerpc_plain_o0 | 23756 | 29695 | 30368, 30316, 30440 | 28444, 28308, 28292 | 12332 / 15968 | 2064 / 10236 | 17436 | yes / yes | yes |
| powerpc_plain_o2 | 23508 | 29385 | 30332, 30396, 30604 | 28640, 28484, 28516 | 12648 / 15956 | 2052 / 10432 | 11326 | yes / yes | yes |
| powerpc_plain_pie | 23700 | 29625 | 30492, 30412, 30516 | 28504, 28184, 28288 | 12336 / 15952 | 2076 / 10228 | 11689 | yes / yes | yes |
| powerpc_cpp_o2 | 23828 | 29785 | 31840, 31764, 31360 | 28872, 29216, 28692 | 12844 / 16056 | 2252 / 10352 | 97441 | no, decompiler nondeterministic / yes | yes |
| powerpc_many_o2 | 44220 | 55275 | 59948, 59968, 59924 | 43488, 43372, 41012 | 21692 / 21680 | 6080 / 10380 | 2108403 | yes / yes | yes |
