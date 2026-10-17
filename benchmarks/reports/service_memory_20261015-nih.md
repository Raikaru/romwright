# Service memory: 20261015-nih

Host load at the end 19.00; before `romwright-api` afcb97b98668, after 008cdb1bf56e; 3 alternating repeats per entry. Verdict: **PASS** (every after run inside the frozen limit, every `decompile_doc` reply the same JSON value or, where the decompiler is not deterministic, the same tokens).

| entry | frozen | limit (x1.25) | before runs | after runs | after: service / decompiler peak | service at end anon / file | reply bytes | documents equal / tokens equal | pass |
|---|---|---|---|---|---|---|---|---|---|
| x86_64_plain_o0 | 47568 | 59460 | 54568, 54708, 54256 | 52464, 52432, 52472 | 12428 / 40040 | 1896 / 10508 | 18975 | yes / yes | yes |
| x86_64_plain_o2 | 47540 | 59425 | 54588, 54372, 54424 | 52660, 52564, 52432 | 12432 / 40000 | 1888 / 10512 | 11146 | yes / yes | yes |
| x86_64_plain_pie | 47452 | 59315 | 54212, 54756, 54564 | 52324, 52620, 52876 | 12620 / 40152 | 1888 / 10768 | 11146 | yes / yes | yes |
| x86_64_cpp_o2 | 47816 | 59770 | 55168, 55384, 55512 | 53012, 52920, 52628 | 12748 / 40048 | 2116 / 10432 | 88795 | no, decompiler nondeterministic / yes | yes |
| x86_64_many_o2 | 79828 | 99785 | 95100, 95608, 95436 | 79012, 77060, 79256 | 21688 / 57340 | 5964 / 10440 | 2113453 | yes / yes | yes |
| i386_plain_o0 | 40184 | 50230 | 47140, 47244, 47212 | 44984, 45792, 45652 | 12656 / 32996 | 1920 / 10704 | 17224 | yes / yes | yes |
| i386_plain_o2 | 40496 | 50620 | 47312, 47208, 47172 | 44848, 45768, 45512 | 12504 / 33004 | 1896 / 10576 | 11148 | yes / yes | yes |
| i386_plain_pie | 40496 | 50620 | 47140, 47172, 47312 | 45672, 45416, 45088 | 12504 / 32912 | 1896 / 10124 | 11145 | yes / yes | yes |
| i386_cpp_o2 | 40632 | 50790 | 48564, 48032, 48052 | 45532, 45568, 45640 | 12624 / 33004 | 2088 / 10516 | 85798 | no, decompiler nondeterministic / yes | yes |
| i386_many_o2 | 65308 | 81635 | 80112, 80420, 80600 | 67312, 67776, 67724 | 25524 / 42292 | 10992 / 10496 | 2125478 | yes / yes | yes |
| aarch64_plain_o0 | 43192 | 53990 | 49980, 49696, 49864 | 48064, 48192, 48012 | 12508 / 35556 | 1844 / 10624 | 18849 | yes / yes | yes |
| aarch64_plain_o2 | 43004 | 53755 | 49836, 49796, 49884 | 47928, 47856, 48100 | 12300 / 35556 | 1828 / 10700 | 11132 | yes / yes | yes |
| aarch64_plain_pie | 43068 | 53835 | 50064, 49896, 50000 | 47780, 47812, 47812 | 12364 / 35448 | 1832 / 10500 | 11132 | yes / yes | yes |
| aarch64_cpp_o2 | 43248 | 54060 | 50768, 50760, 51032 | 48536, 48328, 48520 | 12856 / 35680 | 1988 / 10840 | 95461 | no, decompiler nondeterministic / yes | yes |
| aarch64_many_o2 | 65220 | 81525 | 81120, 81148, 80996 | 64252, 64768, 64956 | 21828 / 42940 | 5908 / 10776 | 2112873 | yes / yes | yes |
| powerpc_plain_o0 | 23756 | 29695 | 30448, 30732, 30320 | 28888, 28940, 28280 | 12788 / 16096 | 2052 / 10280 | 17436 | yes / yes | yes |
| powerpc_plain_o2 | 23508 | 29385 | 30292, 30372, 30488 | 28284, 28396, 28252 | 12320 / 16092 | 2040 / 10052 | 11326 | yes / yes | yes |
| powerpc_plain_pie | 23700 | 29625 | 30176, 30216, 30332 | 28292, 28364, 28460 | 12300 / 16064 | 2072 / 10380 | 11689 | yes / yes | yes |
| powerpc_cpp_o2 | 23828 | 29785 | 31380, 31852, 31608 | 29068, 29060, 29056 | 13012 / 16044 | 2200 / 10780 | 97441 | no, decompiler nondeterministic / yes | yes |
| powerpc_many_o2 | 44220 | 55275 | 60000, 59636, 59688 | 41376, 43480, 41480 | 19724 / 21788 | 6100 / 10244 | 2108403 | yes / yes | yes |
