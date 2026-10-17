# M23-001: PS2 `new-project`

Generated 2026-10-12 00:59 UTC by `tests/m23-001_new_project_ps2.py`.

## Compiler detection

Scored against `truth/meta.json` `compiler` over 8 PS2 games: **family 7/8**, toolchain lineage (MWCC vs GNU/SN) 8/8, version class 7/8 (in-sample), suggested manifest compiler names the meta version 6/8. Supplementary (truth from manifest/DWARF): 2/2.

| game | meta compiler | detected | class | confidence | suggested tool | family | class ok |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ps2-dark-cloud | MWCC PS2 2.3.3 (Metrowerks CodeWarrior for PS2; repo config  | mwcc-ps2 | mwcc-2.3 | high | mwcps2-2.3.3-000906 | yes | yes |
| ps2-dark-chronicle | MWCC PS2 3.0 (CodeWarrior for PS2, via Satans Fiddle/wibo; r | mwcc-ps2 | mwcc-2.4 | high | mwcps2-3.0.1b210-060308 | yes | yes |
| ps2-persona-4 | MWCC PS2 3.0.1 build 210 (-O2) for Atlus code; MWCC build 11 | mwcc-ps2 | mwcc-2.4 | high | mwcps2-3.0.1b210-060308 | yes | yes |
| ps2-digital-devil-saga | EE GCC 2.96 (ee-gcc; ee-as 2.9-ee; repo config compiler EEGC | ee-gcc | gcc-2.95-2.96 | high | ee-gcc2.96 | yes | yes |
| ps2-fatal-frame | EE GCC 2.9-991111 (ee-gcc, repo config compiler EEGCC; platf | ee-gcc | gcc-2.9-ee | high | ee-gcc2.9-991111 | yes | yes |
| ps2-god-hand | SN ProDG ee-gcc 2.95.3 (matched TUs) + EE GCC 2.96 (dvp-as,  | sn-prodg | sn-prodg | high | ee-gcc2.95.3-136 | yes | yes |
| ps2-ratchet-clank | EE GCC 2.95.2 (ee-gcc, repo config compiler EEGCC; some unit | ee-gcc | gcc-2.9x | medium | ee-gcc2.95.2-273a | yes | yes |
| ps2-ratchet-clank-pal | SN ProDG 3.01 (ee-gcc 2.95-based) for game code; SCE SDK 2.4 | ee-gcc | gcc-2.9x | medium | ee-gcc2.95.2-273a | **no** | **no** |

| supplementary game | truth | detected | ok |
| --- | --- | --- | --- |
| ps2-capcom-fighting-evolution | mwcc-ps2 (manifest: Metrowerks CodeWarrior DWARF 1 sections) | mwcc-ps2 | yes |
| ps2-dungeon-game | ee-gcc (DWARF producer `GNU C 3.2.2` in .debug_info) | ee-gcc | yes |

## Bootstrap gate

| game | tools | new-project s | split s | ninja s | all-asm sha1 | swapped function | matched |
| --- | --- | --- | --- | --- | --- | --- | --- |
| fatal-frame | pinned-manifest | 19.6 | 26.8 | 62.7 | `5ac4626e0d76218e977b01f4fae5948de9a1755e` | `CdvdInitIop` @ 0x0010cea8 | yes |
| persona-4 | toolchain-profile | 53.2 | 113.3 | 204.9 | `4eeec0360cf2715535d9f7e52eb69d786fb0158c` | `FUN_00102e70` @ 0x00102e70 | yes |
| persona-4 | local-manifest | 3.6 | 114.9 | 205.3 | `4eeec0360cf2715535d9f7e52eb69d786fb0158c` | `FUN_00102e70` @ 0x00102e70 | yes |
