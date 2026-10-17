# Compiler rules: leave-one-out

Generated 2026-10-12 23:21 UTC by `benchmarks/compiler_rules_loo.py`; tools `2bcde8b0d87bc254` (`romwright-cli`, `romwright-worker`, `ghidra_opt`), decompile sample 40 stratified functions + up to 60 the rule can reach per game. Rule coverage was refreshed against the final build, which differs from the build the import-level and C-lane measurements ran on only in the canonical rules's compiler keys (guarded-loops: mwcc-ps2; strict-greater-constant: mwcc-ps2-2.4) and the mwcc-ps2 version-class ids; the measurements themselves are unchanged.

Each cell compares the rule **on** against **off** on one build, per game the rule covers and that is not in its `derived_from`. Outputs are deterministic: any difference is real. `helps`: a judged metric improves, none worsens; `hurts`: the reverse; `mixed`: both; `neutral`: none moves (for an import-level rule with identical stored facts nothing is decompiled). Judged: recall, precision and decompile success (and, for `register-sled`, the helper calls left visible and the `unaff_` locals; for `literal-pool-extent`, the share of exact stored sizes and the number of too-long ones); gotos, labels, irregular functions, native warnings and the number of printed functions that differ are reported, not judged (counts over functions both arms decompiled).

## Rules

| rule | kind | status | origin | covered games | held out | helps | hurts | neutral | outcome | bar met |
|---|---|---|---|---|---|---|---|---|---|---|
| `nonreturn-libc-elf` | nonreturn-names | on | migrated | 11 | 11 | 0 | 0 | 11 | neutral | yes |
| `nonreturn-windows-crt` | nonreturn-names | on | migrated | 0 | 0 | 0 | 0 | 0 | no held-out game | yes |
| `canonical-char-negative-equality` | c-canonical | on | migrated | 61 | 60 | 0 | 0 | 7 | neutral | yes |
| `canonical-fuse-mask-statements` | c-canonical | on | migrated | 61 | 60 | 0 | 0 | 7 | neutral | yes |
| `canonical-narrow-locals` | c-canonical | on | migrated | 61 | 60 | 0 | 0 | 7 | neutral | yes |
| `canonical-narrow-uses` | c-canonical | on | migrated | 61 | 60 | 0 | 0 | 7 | neutral | yes |
| `canonical-guarded-loops` | c-canonical | on | migrated | 13 | 12 | 0 | 0 | 2 | neutral | yes |
| `canonical-strict-greater-constant` | c-canonical | on | migrated | 11 | 10 | 1 | 0 | 0 | helps | yes |
| `tailcall-promotion` | flag | candidate | learned | 48 | 48 | 2 | 34 | 12 | hurts | **NO** |
| `literal-pool-extent` | literal-pool-extent | on | learned | 10 | 7 | 7 | 0 | 0 | helps | yes |
| `nonreturn-itanium-eh` | nonreturn-names | on | migrated | 6 | 6 | 0 | 0 | 6 | neutral | yes |
| `thumb-pop-bx-is-return` | flag | on | migrated | 10 | 10 | 0 | 0 | 10 | neutral | yes |
| `thumb-frame-teardown-entry` | flag | on | migrated | 10 | 10 | 4 | 0 | 6 | helps | yes |
| `mwcc-register-sleds` | register-sled | on | migrated | 12 | 12 | 11 | 0 | 1 | helps | yes |

### `nonreturn-libc-elf`

C library and kernel entry points that never return, by the name an ELF symbol table gives them (leading underscores ignored). The names are the library's, not the compiler's, so every detected compiler is covered.

kind `nonreturn-names`, status `on`, origin `migrated`, compilers `*` (and unknown); derived from: ghidra-12.1.3 ElfFunctionsThatDoNotReturn. Bar: hurts no held-out game (migrated); outcome **neutral**.

| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | m22 exact on / off | m22 mean on / off | m22 better / worse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | mwcc-ps2 | yes | neutral | identical | 0.9987 / 0.9987 | 0.9963 / 0.9963 | - / - | 0.9991 / 0.9991 | - / - | - / - | - / - | - / - | - | 0 | 19.4 / 24.4 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-dark-chronicle-symtab | mwcc-ps2 | yes | neutral | identical | 1.0 / 1.0 | 0.9973 / 0.9973 | - / - | 0.9994 / 0.9994 | - / - | - / - | - / - | - / - | - | 0 | 14.9 / 18.3 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-dark-cloud | mwcc-ps2 | yes | neutral | identical | 0.9497 / 0.9497 | 0.9982 / 0.9982 | - / - | 0.9927 / 0.9927 | - / - | - / - | - / - | - / - | - | 0 | 9.2 / 11.9 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-dark-cloud-symtab | mwcc-ps2 | yes | neutral | identical | 1.0 / 1.0 | 0.9988 / 0.9988 | - / - | 0.9536 / 0.9536 | - / - | - / - | - / - | - / - | - | 0 | 7.8 / 9.8 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-digital-devil-saga | ee-gcc-2.9x | yes | neutral | identical | 0.9974 / 0.9974 | 0.9987 / 0.9987 | - / - | 0.9982 / 0.9982 | - / - | - / - | - / - | - / - | - | 0 | 14.8 / 25.5 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-fatal-frame | ee-gcc-2.9x | yes | neutral | identical | 0.9958 / 0.9958 | 0.9993 / 0.9993 | - / - | 0.9981 / 0.9981 | - / - | - / - | - / - | - / - | - | 0 | 7.8 / 10.2 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-fatal-frame-symtab | ee-gcc-2.9x | yes | neutral | identical | 1.0 / 1.0 | 0.9998 / 0.9998 | - / - | 0.9995 / 0.9995 | - / - | - / - | - / - | - / - | - | 0 | 5.5 / 7.9 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-god-hand | sn-prodg | yes | neutral | identical | 0.9976 / 0.9976 | 0.9943 / 0.9943 | - / - | 0.9951 / 0.9951 | - / - | - / - | - / - | - / - | - | 0 | 30.1 / 44.6 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-persona-4 | mwcc-ps2 | yes | neutral | identical | 0.9992 / 0.9992 | 0.9967 / 0.9967 | - / - | 0.942 / 0.942 | - / - | - / - | - / - | - / - | - | 0 | 29.1 / 88.6 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-ratchet-clank | ee-gcc-2.9x | yes | neutral | identical | 0.9281 / 0.9281 | 0.9965 / 0.9965 | - / - | 0.9645 / 0.9645 | - / - | - / - | - / - | - / - | - | 0 | 16.3 / 80.4 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-ratchet-clank-pal | ee-gcc-2.9x | yes | neutral | identical | 0.9276 / 0.9276 | 0.9947 / 0.9947 | - / - | 0.9509 / 0.9509 | - / - | - / - | - / - | - / - | - | 0 | 16.3 / 77.6 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |

### `nonreturn-windows-crt`

Windows CRT and kernel entry points that never return, by PE symbol name (leading underscores ignored).

kind `nonreturn-names`, status `on`, origin `migrated`, compilers `*` (and unknown); derived from: ghidra-12.1.3 PEFunctionsThatDoNotReturn. Bar: migrated: hurts no held-out game; outcome **no held-out game**.

No corpus game in the loaded set is covered by this rule.

### `canonical-char-negative-equality`

A negative constant compared with a char is false wherever char is unsigned; the same byte compared with its unsigned spelling is the same test on every target.

kind `c-canonical`, status `on`, origin `migrated`, compilers `*` (and unknown); derived from: ps2-persona-4. Bar: hurts no held-out game (migrated); outcome **neutral**.

Games covered with no C-output lane, so not measured (pending lanes): 53 (gba-fire-emblem-sacred-stones, gba-golden-sun, gba-kh-chain-of-memories, gba-klonoa-empire-of-dreams, gba-nascar-heat-2002, ...).

| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | m22 exact on / off | m22 mean on / off | m22 better / worse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 33 / 33 | 61.045 / 61.045 | 0 / 0 |
| ps2-dark-cloud | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 26 / 26 | 65.929 / 65.929 | 0 / 0 |
| ps2-digital-devil-saga | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 48 / 48 | 63.275 / 63.275 | 0 / 0 |
| ps2-fatal-frame | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 19 / 19 | 45.282 / 45.282 | 0 / 0 |
| ps2-god-hand | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 67 / 67 | 68.749 / 68.749 | 0 / 0 |
| ps2-persona-4 | - | no | derived | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | - / - | - / - | - / - |
|  | | | the rule was derived on this game | | | | | | | | | | | | | | | |
| ps2-ratchet-clank | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 24 / 24 | 63.118 / 63.118 | 0 / 0 |
| ps2-ratchet-clank-pal | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 25 / 25 | 55.902 / 55.902 | 0 / 0 |

### `canonical-fuse-mask-statements`

A narrow counter the decompiler masks on every assignment is fused back into one masked statement.

kind `c-canonical`, status `on`, origin `migrated`, compilers `*` (and unknown); derived from: ps2-persona-4. Bar: hurts no held-out game (migrated); outcome **neutral**.

Games covered with no C-output lane, so not measured (pending lanes): 53 (gba-fire-emblem-sacred-stones, gba-golden-sun, gba-kh-chain-of-memories, gba-klonoa-empire-of-dreams, gba-nascar-heat-2002, ...).

| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | m22 exact on / off | m22 mean on / off | m22 better / worse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 33 / 33 | 61.045 / 61.045 | 0 / 0 |
| ps2-dark-cloud | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 26 / 26 | 65.929 / 65.929 | 0 / 0 |
| ps2-digital-devil-saga | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 48 / 48 | 63.275 / 63.275 | 0 / 0 |
| ps2-fatal-frame | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 19 / 19 | 45.282 / 45.282 | 0 / 0 |
| ps2-god-hand | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 67 / 67 | 68.749 / 68.749 | 0 / 0 |
| ps2-persona-4 | - | no | derived | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | - / - | - / - | - / - |
|  | | | the rule was derived on this game | | | | | | | | | | | | | | | |
| ps2-ratchet-clank | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 24 / 24 | 63.118 / 63.118 | 0 / 0 |
| ps2-ratchet-clank-pal | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 25 / 25 | 55.902 / 55.902 | 0 / 0 |

### `canonical-narrow-locals`

A 32-bit local every assignment of which masks to 8 or 16 bits is that narrow type, and is declared so.

kind `c-canonical`, status `on`, origin `migrated`, compilers `*` (and unknown); derived from: ps2-persona-4. Bar: hurts no held-out game (migrated); outcome **neutral**.

Games covered with no C-output lane, so not measured (pending lanes): 53 (gba-fire-emblem-sacred-stones, gba-golden-sun, gba-kh-chain-of-memories, gba-klonoa-empire-of-dreams, gba-nascar-heat-2002, ...).

| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | m22 exact on / off | m22 mean on / off | m22 better / worse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 33 / 33 | 61.045 / 61.045 | 0 / 0 |
| ps2-dark-cloud | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 26 / 26 | 65.929 / 65.929 | 0 / 0 |
| ps2-digital-devil-saga | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 48 / 48 | 63.275 / 63.275 | 0 / 0 |
| ps2-fatal-frame | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 19 / 19 | 45.282 / 45.282 | 0 / 0 |
| ps2-god-hand | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 67 / 67 | 68.749 / 68.749 | 0 / 0 |
| ps2-persona-4 | - | no | derived | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | - / - | - / - | - / - |
|  | | | the rule was derived on this game | | | | | | | | | | | | | | | |
| ps2-ratchet-clank | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 24 / 24 | 63.118 / 63.118 | 0 / 0 |
| ps2-ratchet-clank-pal | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 25 / 25 | 55.902 / 55.902 | 0 / 0 |

### `canonical-narrow-uses`

Uses of a narrowed local lose the mask that the narrow type now performs.

kind `c-canonical`, status `on`, origin `migrated`, compilers `*` (and unknown); derived from: ps2-persona-4. Bar: hurts no held-out game (migrated); outcome **neutral**.

Games covered with no C-output lane, so not measured (pending lanes): 53 (gba-fire-emblem-sacred-stones, gba-golden-sun, gba-kh-chain-of-memories, gba-klonoa-empire-of-dreams, gba-nascar-heat-2002, ...).

| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | m22 exact on / off | m22 mean on / off | m22 better / worse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 33 / 33 | 61.045 / 61.045 | 0 / 0 |
| ps2-dark-cloud | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 26 / 26 | 65.929 / 65.929 | 0 / 0 |
| ps2-digital-devil-saga | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 48 / 48 | 63.275 / 63.275 | 0 / 0 |
| ps2-fatal-frame | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 19 / 19 | 45.282 / 45.282 | 0 / 0 |
| ps2-god-hand | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 67 / 67 | 68.749 / 68.749 | 0 / 0 |
| ps2-persona-4 | - | no | derived | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | - / - | - / - | - / - |
|  | | | the rule was derived on this game | | | | | | | | | | | | | | | |
| ps2-ratchet-clank | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 24 / 24 | 63.118 / 63.118 | 0 / 0 |
| ps2-ratchet-clank-pal | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 25 / 25 | 55.902 / 55.902 | 0 / 0 |

### `canonical-guarded-loops`

Loop inversion's folded guard is written as the loop test again, so it compiles back to a test of the counter. Derived on Persona 4 (MWCC). Leave-one-out over the seven PS2 C-output lanes (m22 objdiff match, rule off -> on): neutral on dds, ff, gh, dk and dc; it lowered the mean match of both held-out ee-gcc 2.9x lanes that it touched (Ratchet & Clank 63.150 -> 63.118, 2 functions worse; R&C PAL 55.912 -> 55.902, 1 worse) and improved none, so it is keyed to the compiler it was derived on and no longer covers ee-gcc. Programs of an unknown compiler keep it.

kind `c-canonical`, status `on`, origin `migrated`, compilers `mwcc-ps2` (and unknown); derived from: ps2-persona-4. Bar: hurts no held-out game (migrated); outcome **neutral**.

Measured, then excluded by narrowing the rule's compilers (no longer covered; their rows are in the JSON under `excluded`): ps2-digital-devil-saga (neutral), ps2-fatal-frame (neutral), ps2-god-hand (neutral), ps2-ratchet-clank (hurts), ps2-ratchet-clank-pal (hurts).

Games covered with no C-output lane, so not measured (pending lanes): 10 (ps2-dark-chronicle-symtab, ps2-dark-cloud-symtab, psx-digimon-world, psx-legend-of-mana, psx-nfs-high-stakes, ...).

| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | m22 exact on / off | m22 mean on / off | m22 better / worse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 33 / 33 | 61.045 / 61.045 | 0 / 0 |
| ps2-dark-cloud | - | yes | neutral | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 26 / 26 | 65.929 / 65.929 | 0 / 0 |
| ps2-persona-4 | - | no | derived | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | - / - | - / - | - / - |
|  | | | the rule was derived on this game | | | | | | | | | | | | | | | |

### `canonical-strict-greater-constant`

`K < x` is written `x >= K + 1`: MWCC compiles the strict form to a set-less-than into the assembler temporary and the non-strict form into the result register, the shape a source of the original produces. Derived on Persona 4 (MWCC 3.0.1; the pinned m22-002 lane 1 loses 2 exact functions with it off). Leave-one-out over the seven PS2 C-output lanes (m22 objdiff match, rule off -> on): neutral on dds, ff, gh, rc, rcpal; it helped Dark Chronicle (MWCC 3.0, linker stamp 2.4: exact 31 -> 33, mean 60.976 -> 61.045) and hurt Dark Cloud (MWCC 2.3.3, linker stamp 2.3: exact 27 -> 26, 10 functions better and 9 worse). The two are told apart by the Metrowerks linker stamp in the compiler id (`mwcc-ps2-2.4` against `mwcc-ps2-2.3`), so the rule is keyed to the era it was derived and measured on. A program of an unknown compiler keeps it.

kind `c-canonical`, status `on`, origin `migrated`, compilers `mwcc-ps2-2.4` (and unknown); derived from: ps2-persona-4. Bar: hurts no held-out game (migrated); outcome **helps**.

Measured, then excluded by narrowing the rule's compilers (no longer covered; their rows are in the JSON under `excluded`): ps2-dark-cloud (hurts), ps2-digital-devil-saga (neutral), ps2-fatal-frame (neutral), ps2-god-hand (neutral), ps2-ratchet-clank (neutral), ps2-ratchet-clank-pal (neutral).

Games covered with no C-output lane, so not measured (pending lanes): 9 (ps2-dark-chronicle-symtab, psx-digimon-world, psx-legend-of-mana, psx-nfs-high-stakes, psx-parasite-eve, ...).

| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | m22 exact on / off | m22 mean on / off | m22 better / worse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | - | yes | helps | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | 33 / 31 | 61.045 / 60.976 | 9 / 4 |
|  | | | m22 exact 31 -> 33; m22 mean 60.976 -> 61.045 | | | | | | | | | | | | | | | |
| ps2-persona-4 | - | no | derived | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | - / - | - / - | - / - |
|  | | | the rule was derived on this game | | | | | | | | | | | | | | | |

### `tailcall-promotion`

A direct branch out of a function whose target is code, sits in no body another entry proved, and whose own flow decodes to a terminator is a tail call to a function; its target is promoted to a function entry (discovery's `promote_tailcalls`). Stock Ghidra creates none of these. The global `ROMWRIGHT_PROMOTE_TAILCALLS` switch still turns it on for every program. Measured over the 48 wave games whose compiler is detected (leave-one-out, ENABLE against default): it trades a few recall points for precision almost everywhere (34 games hurt, 2 help, 12 neutral; no compiler family helps without hurting another game of the same family), so it stays a candidate and off.

kind `flag`, status `candidate`, origin `learned`, compilers `*`; derived from: -. Bar: helps >= 1 held-out game and hurts none; outcome **hurts**.

| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | m22 exact on / off | m22 mean on / off | m22 better / worse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-fire-emblem-sacred-stones | agbcc | yes | mixed | differ {"functions": [8220, 8214], "thunks": [7, 8], "flow_override | 0.9536 / 0.9536 | 0.988 / 0.9887 | 1.0 / 0.9773 | 0.9962 / 0.9962 | 2 / 2 | 1 / 1 | 11 / 11 | 118 / 120 | 1 | 4 | 38.7 / 8.1 | - / - | - / - | - / - |
|  | | | success 0.9773 -> 1.0; but; precision 0.9887 -> 0.988 | | | | | | | | | | | | | | | |
| gba-golden-sun | agbcc | yes | neutral | differ {"functions": [2495, 2484], "thunks": [3, 2], "flow_override | 0.8667 / 0.8667 | 0.9781 / 0.9781 | 1.0 / 1.0 | 0.9812 / 0.9812 | 5 / 5 | 3 / 3 | 16 / 16 | 155 / 158 | 1 | 1 | 58.3 / 18.6 | - / - | - / - | - / - |
| gba-kh-chain-of-memories | agbcc | yes | hurts | differ {"functions": [5228, 5226], "flow_overrides": [101, 95], "xr | 0.9582 / 0.9582 | 0.9635 / 0.9638 | 1.0 / 1.0 | 0.9918 / 0.9918 | 18 / 18 | 12 / 12 | 9 / 9 | 124 / 124 | 0 | 0 | 33.2 / 11.0 | - / - | - / - | - / - |
|  | | | precision 0.9638 -> 0.9635 | | | | | | | | | | | | | | | |
| gba-klonoa-empire-of-dreams | agbcc | yes | mixed | differ {"functions": [537, 524], "thunks": [3, 3], "flow_overrides" | 0.8612 / 0.8612 | 0.9013 / 0.9237 | 1.0 / 0.9773 | 0.9574 / 0.9574 | 22 / 22 | 9 / 9 | 156 / 157 | 565 / 577 | 2 | 4 | 6.9 / 2.0 | - / - | - / - | - / - |
|  | | | success 0.9773 -> 1.0; but; precision 0.9237 -> 0.9013 | | | | | | | | | | | | | | | |
| gba-nascar-heat-2002 | agbcc | yes | neutral | differ {"functions": [1083, 1083], "flow_overrides": [11, 8], "xref | 0.8009 / 0.8009 | 0.9732 / 0.9732 | 0.9756 / 0.9756 | 0.9704 / 0.9695 | 2 / 2 | 1 / 1 | 5 / 5 | 136 / 132 | 1 | 1 | 6.5 / 1.5 | - / - | - / - | - / - |
| gc-melee | mwcc-gc | yes | mixed | differ {"functions": [19849, 19836], "flow_overrides": [23, 10], "x | 0.9998 / 0.9997 | 0.9987 / 0.9993 | 1.0 / 1.0 | 0.9983 / 0.9985 | 0 / 0 | 0 / 0 | 0 / 0 | 117 / 116 | 1 | 2 | 57.5 / 23.9 | - / - | - / - | - / - |
|  | | | recall 0.9997 -> 0.9998; but; precision 0.9993 -> 0.9987 | | | | | | | | | | | | | | | |
| gc-pikmin | mwcc-gc | yes | mixed | differ {"functions": [8101, 8095], "flow_overrides": [98, 92], "xre | 0.9995 / 0.9993 | 0.9954 / 0.9959 | 1.0 / 0.9756 | 0.9962 / 0.9965 | 0 / 0 | 0 / 0 | 0 / 0 | 70 / 70 | 0 | 1 | 17.2 / 9.5 | - / - | - / - | - / - |
|  | | | recall 0.9993 -> 0.9995; success 0.9756 -> 1.0; but; precision 0.9959 -> 0.9954 | | | | | | | | | | | | | | | |
| gc-pikmin-2 | mwcc-gc | yes | hurts | differ {"functions": [24997, 24991], "flow_overrides": [1133, 1126] | 0.9998 / 0.9998 | 0.9982 / 0.9984 | 1.0 / 1.0 | 0.9984 / 0.9985 | 2 / 2 | 1 / 1 | 74 / 74 | 100 / 99 | 1 | 2 | 65.2 / 19.7 | - / - | - / - | - / - |
|  | | | precision 0.9984 -> 0.9982 | | | | | | | | | | | | | | | |
| gc-super-mario-strikers | mwcc-gc | yes | mixed | differ {"functions": [8640, 8634], "flow_overrides": [22, 15], "xre | 0.9994 / 0.9993 | 0.9953 / 0.9958 | 1.0 / 1.0 | 0.9977 / 0.998 | 0 / 0 | 0 / 0 | 124 / 124 | 138 / 137 | 1 | 2 | 63.7 / 10.9 | - / - | - / - | - / - |
|  | | | recall 0.9993 -> 0.9994; but; precision 0.9958 -> 0.9953 | | | | | | | | | | | | | | | |
| gc-tiger-woods-2004 | mwcc-gc | yes | mixed | differ {"functions": [7663, 7656], "flow_overrides": [18, 9], "xref | 0.9995 / 0.9993 | 0.9974 / 0.9982 | 1.0 / 1.0 | 0.9979 / 0.9983 | 2 / 2 | 1 / 1 | 0 / 0 | 105 / 104 | 2 | 3 | 19.5 / 6.9 | - / - | - / - | - / - |
|  | | | recall 0.9993 -> 0.9995; but; precision 0.9982 -> 0.9974 | | | | | | | | | | | | | | | |
| gc-twilight-princess | mwcc-gc | yes | hurts | differ {"functions": [48218, 48196], "flow_overrides": [1095, 1059] | 0.9999 / 0.9999 | 0.9976 / 0.998 | 1.0 / 1.0 | 0.9994 / 0.9994 | 5 / 5 | 3 / 3 | 185 / 188 | 176 / 181 | 3 | 5 | 313.4 / 127.5 | - / - | - / - | - / - |
|  | | | precision 0.998 -> 0.9976 | | | | | | | | | | | | | | | |
| gc-wind-waker | mwcc-gc | yes | hurts | differ {"functions": [39385, 39379], "flow_overrides": [1797, 1790] | 0.9999 / 0.9999 | 0.9981 / 0.9983 | 1.0 / 1.0 | 0.9996 / 0.9996 | 2 / 2 | 1 / 1 | 16 / 16 | 85 / 84 | 1 | 2 | 162.3 / 71.3 | - / - | - / - | - / - |
|  | | | precision 0.9983 -> 0.9981 | | | | | | | | | | | | | | | |
| n64-dr-mario-64 | n64-gcc | yes | neutral | identical | 0.9374 / 0.9374 | 0.9887 / 0.9887 | - / - | 0.9917 / 0.9917 | - / - | - / - | - / - | - / - | - | 0 | 10.2 / 2.3 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| n64-majoras-mask | ido | yes | neutral | identical | 0.9782 / 0.9782 | 0.998 / 0.998 | - / - | 0.9977 / 0.9977 | - / - | - / - | - / - | - / - | - | 0 | 99.5 / 29.2 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| n64-ocarina-of-time | ido | yes | neutral | identical | 0.9842 / 0.9842 | 0.9977 / 0.9977 | - / - | 0.997 / 0.997 | - / - | - / - | - / - | - / - | - | 0 | 153.5 / 31.9 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| n64-perfect-dark | ido | yes | neutral | identical | 0.9525 / 0.9525 | 0.9901 / 0.9901 | - / - | 0.9915 / 0.9915 | - / - | - / - | - / - | - / - | - | 0 | 52.2 / 11.8 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| n64-super-mario-64 | ido | yes | neutral | identical | 0.9974 / 0.9974 | 0.9053 / 0.9053 | - / - | 0.9085 / 0.9085 | - / - | - / - | - / - | - / - | - | 0 | 25.7 / 6.3 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| nds-dragon-quest-iv | mwcc-arm | yes | hurts | differ {"functions": [5050, 5036], "thunks": [2, 1], "flow_override | 0.9062 / 0.9062 | 0.995 / 0.9978 | 1.0 / 1.0 | 0.9916 / 0.9922 | 2 / 2 | 1 / 1 | 0 / 0 | 63 / 63 | 1 | 4 | 34.4 / 8.0 | - / - | - / - | - / - |
|  | | | precision 0.9978 -> 0.995 | | | | | | | | | | | | | | | |
| nds-kh-358-2-days | mwcc-arm | yes | hurts | differ {"functions": [1952, 1950], "flow_overrides": [3, 1], "xrefs | 0.8662 / 0.8662 | 0.9385 / 0.9395 | 1.0 / 1.0 | 0.9945 / 0.9945 | 2 / 2 | 1 / 1 | 4 / 4 | 73 / 73 | 0 | 0 | 63.5 / 23.2 | - / - | - / - | - / - |
|  | | | precision 0.9395 -> 0.9385 | | | | | | | | | | | | | | | |
| nds-kh-recoded | mwcc-arm | yes | hurts | differ {"functions": [2537, 2532], "flow_overrides": [4, 1], "xrefs | 0.8977 / 0.8977 | 0.9551 / 0.957 | 1.0 / 1.0 | 0.9971 / 0.9971 | 8 / 8 | 5 / 5 | 0 / 0 | 53 / 53 | 1 | 0 | 41.1 / 11.2 | - / - | - / - | - / - |
|  | | | precision 0.957 -> 0.9551 | | | | | | | | | | | | | | | |
| nds-pokemon-platinum | mwcc-arm | yes | hurts | differ {"functions": [10800, 10795], "flow_overrides": [6, 3], "xre | 0.9755 / 0.9755 | 0.9938 / 0.9943 | 1.0 / 1.0 | 0.9985 / 0.9985 | 0 / 0 | 0 / 0 | 0 / 0 | 84 / 84 | 0 | 0 | 83.5 / 25.0 | - / - | - / - | - / - |
|  | | | precision 0.9943 -> 0.9938 | | | | | | | | | | | | | | | |
| nds-world-ends-with-you | mwcc-arm | yes | hurts | differ {"functions": [2476, 2471], "flow_overrides": [6, 3], "xrefs | 0.9042 / 0.9042 | 0.9915 / 0.9935 | 1.0 / 1.0 | 0.9935 / 0.9935 | 2 / 2 | 1 / 1 | 24 / 24 | 73 / 73 | 0 | 0 | 28.0 / 11.7 | - / - | - / - | - / - |
|  | | | precision 0.9935 -> 0.9915 | | | | | | | | | | | | | | | |
| ps2-dark-chronicle | mwcc-ps2 | yes | hurts | differ {"functions": [7856, 7856], "thunks": [28, 43], "flow_overri | 0.9986 / 0.9987 | 0.9962 / 0.9963 | 1.0 / 1.0 | 0.9988 / 0.9991 | 2 / 2 | 1 / 1 | 2 / 2 | 92 / 91 | 3 | 28 | 35.7 / 19.4 | - / - | - / - | - / - |
|  | | | recall 0.9987 -> 0.9986; precision 0.9963 -> 0.9962 | | | | | | | | | | | | | | | |
| ps2-dark-chronicle-symtab | mwcc-ps2 | yes | neutral | identical | 1.0 / 1.0 | 0.9973 / 0.9973 | - / - | 0.9994 / 0.9994 | - / - | - / - | - / - | - / - | - | 0 | 17.1 / 14.9 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-dark-cloud | mwcc-ps2 | yes | neutral | identical | 0.9497 / 0.9497 | 0.9982 / 0.9982 | - / - | 0.9927 / 0.9927 | - / - | - / - | - / - | - / - | - | 0 | 12.0 / 9.2 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-dark-cloud-symtab | mwcc-ps2 | yes | neutral | identical | 1.0 / 1.0 | 0.9988 / 0.9988 | - / - | 0.9536 / 0.9536 | - / - | - / - | - / - | - / - | - | 0 | 9.9 / 7.8 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-digital-devil-saga | ee-gcc-2.9x | yes | mixed | differ {"functions": [10374, 10338], "thunks": [17, 16], "flow_over | 0.9973 / 0.9974 | 0.9952 / 0.9987 | 1.0 / 0.9783 | 0.998 / 0.9982 | 6 / 6 | 4 / 4 | 14 / 14 | 171 / 168 | 5 | 6 | 21.0 / 14.8 | - / - | - / - | - / - |
|  | | | success 0.9783 -> 1.0; but; recall 0.9974 -> 0.9973; precision 0.9987 -> 0.9952 | | | | | | | | | | | | | | | |
| ps2-fatal-frame | ee-gcc-2.9x | yes | neutral | identical | 0.9958 / 0.9958 | 0.9993 / 0.9993 | - / - | 0.9981 / 0.9981 | - / - | - / - | - / - | - / - | - | 0 | 10.7 / 7.8 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-fatal-frame-symtab | ee-gcc-2.9x | yes | neutral | identical | 1.0 / 1.0 | 0.9998 / 0.9998 | - / - | 0.9995 / 0.9995 | - / - | - / - | - / - | - / - | - | 0 | 8.4 / 5.5 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-god-hand | sn-prodg | yes | hurts | differ {"functions": [11273, 11270], "flow_overrides": [977, 974],  | 0.9976 / 0.9976 | 0.9941 / 0.9943 | 1.0 / 1.0 | 0.9951 / 0.9951 | 6 / 7 | 3 / 4 | 7 / 7 | 66 / 65 | 1 | 1 | 38.0 / 30.1 | - / - | - / - | - / - |
|  | | | precision 0.9943 -> 0.9941 | | | | | | | | | | | | | | | |
| ps2-persona-4 | mwcc-ps2 | yes | hurts | differ {"functions": [13141, 13134], "thunks": [82, 93], "flow_over | 0.9992 / 0.9992 | 0.9962 / 0.9967 | 1.0 / 1.0 | 0.9419 / 0.942 | 18 / 39 | 7 / 15 | 0 / 71 | 96 / 89 | 8 | 23 | 51.1 / 29.1 | - / - | - / - | - / - |
|  | | | precision 0.9967 -> 0.9962 | | | | | | | | | | | | | | | |
| ps2-ratchet-clank | ee-gcc-2.9x | yes | mixed | differ {"functions": [1700, 1698], "flow_overrides": [83, 82], "xre | 0.9287 / 0.9281 | 0.9959 / 0.9965 | 1.0 / 1.0 | 0.964 / 0.9645 | 25 / 25 | 15 / 15 | 66 / 66 | 107 / 106 | 1 | 1 | 22.7 / 16.3 | - / - | - / - | - / - |
|  | | | recall 0.9281 -> 0.9287; but; precision 0.9965 -> 0.9959 | | | | | | | | | | | | | | | |
| ps2-ratchet-clank-pal | ee-gcc-2.9x | yes | mixed | differ {"functions": [1701, 1699], "flow_overrides": [83, 82], "xre | 0.9281 / 0.9276 | 0.9941 / 0.9947 | 1.0 / 1.0 | 0.9503 / 0.9509 | 10 / 10 | 6 / 6 | 111 / 111 | 147 / 146 | 1 | 1 | 20.8 / 16.3 | - / - | - / - | - / - |
|  | | | recall 0.9276 -> 0.9281; but; precision 0.9947 -> 0.9941 | | | | | | | | | | | | | | | |
| psp-hot-pixel-symtab | allegrex-gcc | yes | hurts | differ {"functions": [10978, 10928], "thunks": [5, 4], "flow_overri | 1.0 / 1.0 | 0.9094 / 0.9135 | 0.98 / 0.98 | 0.9153 / 0.9153 | 43 / 41 | 26 / 25 | 23 / 23 | 112 / 108 | 3 | 10 | 24.1 / 16.6 | - / - | - / - | - / - |
|  | | | precision 0.9135 -> 0.9094 | | | | | | | | | | | | | | | |
| psp-melodie-symtab | allegrex-gcc | yes | hurts | differ {"functions": [3372, 3371]} | 1.0 / 1.0 | 0.9614 / 0.9617 | 1.0 / 1.0 | 0.9929 / 0.9929 | 9 / 9 | 4 / 4 | 0 / 0 | 72 / 72 | 0 | 0 | 4.6 / 2.8 | - / - | - / - | - / - |
|  | | | precision 0.9617 -> 0.9614 | | | | | | | | | | | | | | | |
| psp-pac-man-rally-symtab | allegrex-gcc | yes | hurts | differ {"functions": [6591, 6588]} | 1.0 / 1.0 | 0.9678 / 0.9683 | 1.0 / 1.0 | 0.9944 / 0.9944 | 0 / 0 | 0 / 0 | 0 / 0 | 59 / 59 | 0 | 0 | 21.1 / 14.6 | - / - | - / - | - / - |
|  | | | precision 0.9683 -> 0.9678 | | | | | | | | | | | | | | | |
| psp-psp-camera-01-symtab | mwcc-psp | yes | hurts | differ {"functions": [6735, 6733], "flow_overrides": [156, 152], "x | 1.0 / 1.0 | 0.9674 / 0.9677 | 1.0 / 1.0 | 0.9889 / 0.9891 | 37 / 37 | 19 / 19 | 0 / 0 | 94 / 94 | 1 | 1 | 23.2 / 5.4 | - / - | - / - | - / - |
|  | | | precision 0.9677 -> 0.9674 | | | | | | | | | | | | | | | |
| psp-tetris-symtab | mwcc-psp | yes | hurts | differ {"functions": [8705, 8703], "flow_overrides": [308, 304], "x | 1.0 / 1.0 | 0.977 / 0.9772 | 1.0 / 1.0 | 0.9934 / 0.9935 | 34 / 34 | 17 / 17 | 0 / 0 | 99 / 99 | 1 | 1 | 31.9 / 9.3 | - / - | - / - | - / - |
|  | | | precision 0.9772 -> 0.977 | | | | | | | | | | | | | | | |
| wii-mario-strikers-charged | mwcc-wii | yes | mixed | differ {"functions": [17724, 17695], "thunks": [155, 156], "flow_ov | 0.9974 / 0.9973 | 0.9954 / 0.9969 | 1.0 / 1.0 | 0.9833 / 0.9841 | 5 / 6 | 2 / 3 | 247 / 257 | 239 / 252 | 14 | 16 | 84.0 / 28.8 | - / - | - / - | - / - |
|  | | | recall 0.9973 -> 0.9974; but; precision 0.9969 -> 0.9954 | | | | | | | | | | | | | | | |
| wii-npc-pikmin-2 | mwcc-wii | yes | mixed | differ {"functions": [28178, 28170], "thunks": [280, 279], "flow_ov | 0.9979 / 0.9978 | 0.9956 / 0.9958 | 1.0 / 1.0 | 0.9767 / 0.9768 | 0 / 0 | 0 / 0 | 102 / 102 | 90 / 90 | 2 | 2 | 115.1 / 31.6 | - / - | - / - | - / - |
|  | | | recall 0.9978 -> 0.9979; but; precision 0.9958 -> 0.9956 | | | | | | | | | | | | | | | |
| wii-rock-band-3 | mwcc-wii | yes | mixed | differ {"functions": [58479, 58450], "thunks": [1075, 1080], "flow_ | 0.9875 / 0.9873 | 0.9981 / 0.9983 | 1.0 / 1.0 | 0.9754 / 0.9756 | 0 / 0 | 0 / 0 | 21 / 21 | 145 / 149 | 3 | 12 | 278.7 / 58.2 | - / - | - / - | - / - |
|  | | | recall 0.9873 -> 0.9875; but; precision 0.9983 -> 0.9981 | | | | | | | | | | | | | | | |
| wii-skyward-sword | mwcc-wii | yes | hurts | differ {"functions": [27352, 27348], "thunks": [439, 453], "flow_ov | 0.9894 / 0.9894 | 0.9959 / 0.996 | 1.0 / 1.0 | 0.9773 / 0.9773 | 6 / 6 | 1 / 1 | 100 / 100 | 143 / 142 | 2 | 23 | 84.0 / 29.3 | - / - | - / - | - / - |
|  | | | precision 0.996 -> 0.9959 | | | | | | | | | | | | | | | |
| wii-super-mario-galaxy | mwcc-wii | yes | mixed | differ {"functions": [41975, 41946], "thunks": [577, 581], "flow_ov | 0.9971 / 0.997 | 0.9975 / 0.9981 | 1.0 / 1.0 | 0.9888 / 0.9892 | 0 / 0 | 0 / 0 | 96 / 101 | 207 / 219 | 15 | 22 | 42.6 / 35.8 | - / - | - / - | - / - |
|  | | | recall 0.997 -> 0.9971; but; precision 0.9981 -> 0.9975 | | | | | | | | | | | | | | | |
| x360-amped-3 | msvc-14 | yes | hurts | differ {"functions": [36044, 35573], "thunks": [221, 219], "flow_ov | 0.9756 / 0.9756 | 0.9786 / 0.9915 | 1.0 / 1.0 | 0.7677 / 0.773 | 34 / 42 | 19 / 23 | 41 / 41 | 852 / 843 | 53 | 179 | 94.1 / 105.2 | - / - | - / - | - / - |
|  | | | precision 0.9915 -> 0.9786 | | | | | | | | | | | | | | | |
| x360-burnout-crash | msvc-16 | yes | mixed | differ {"functions": [10931, 10928], "thunks": [4, 5], "flow_overri | 0.996 / 0.9958 | 0.9986 / 0.9987 | 0.9762 / 0.9762 | 0.999 / 0.9991 | 0 / 0 | 0 / 0 | 48 / 48 | 131 / 132 | 1 | 2 | 47.1 / 30.7 | - / - | - / - | - / - |
|  | | | recall 0.9958 -> 0.996; but; precision 0.9987 -> 0.9986 | | | | | | | | | | | | | | | |
| x360-call-of-duty-advanced-warfare | msvc-16 | yes | helps | differ {"functions": [36532, 36515], "thunks": [516, 522], "flow_ov | 0.9045 / 0.9041 | 0.9972 / 0.9972 | 1.0 / 1.0 | 0.9743 / 0.9743 | 5 / 5 | 3 / 3 | 0 / 0 | 155 / 155 | 0 | 10 | 91.0 / 54.1 | - / - | - / - | - / - |
|  | | | recall 0.9041 -> 0.9045 | | | | | | | | | | | | | | | |
| x360-call-of-duty-modern-warfare-2 | msvc-15 | yes | helps | differ {"functions": [14980, 14978], "thunks": [161, 164], "flow_ov | 0.8012 / 0.8011 | 0.9936 / 0.9936 | 1.0 / 1.0 | 0.9795 / 0.9795 | 2 / 2 | 1 / 1 | 0 / 0 | 106 / 106 | 0 | 6 | 21.6 / 22.2 | - / - | - / - | - / - |
|  | | | recall 0.8011 -> 0.8012 | | | | | | | | | | | | | | | |
| x360-forza-horizon-2-prototype | msvc-16 | yes | hurts | differ {"functions": [77942, 77945], "thunks": [697, 699], "flow_ov | 0.951 / 0.9511 | 0.9988 / 0.9989 | 1.0 / 1.0 | 0.9404 / 0.9404 | 0 / 0 | 0 / 0 | 0 / 0 | 109 / 109 | 0 | 2 | 92.8 / 90.8 | - / - | - / - | - / - |
|  | | | recall 0.9511 -> 0.951; precision 0.9989 -> 0.9988 | | | | | | | | | | | | | | | |

### `literal-pool-extent`

These compilers put each function's literal pool right behind the function, and the symbol size they emit runs through it, so the flow walk's proven body (which ends at the last return) reads short: 0.43-0.83 of the GBA and NDS functions that truth sizes. The size of a function is extended through the pool its own PC-relative word loads name, never past the next entry, never over a decoded instruction, never over more words than its own loads can name, and never over a size the image's symbol table declared. Found on pokeemerald, Fire Emblem 8 and pokeheartgold; the two guards came from kh-chain-of-memories (a pool in the middle of a function) and nascar-heat-2002 (hand-written assembly sharing one pool), which are therefore derived, not held out. Held out (LOO, size_exact on -> off): golden-sun 0.318 -> 0.981, klonoa 0.168 -> 0.957, dragon-quest-iv 0.469 -> 0.992, kh-358-2-days 0.439 -> 0.995, kh-recoded 0.459 -> 0.997, pokemon-platinum 0.567 -> 0.999, world-ends-with-you 0.440 -> 0.994; recall, precision and decompile success unchanged.

kind `literal-pool-extent`, status `on`, origin `learned`, compilers `agbcc, mwcc-arm`; derived from: gba-pokeemerald, gba-fire-emblem-sacred-stones, nds-pokeheartgold, gba-kh-chain-of-memories, gba-nascar-heat-2002. Bar: helps >= 1 held-out game and hurts none; outcome **helps**.

| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | m22 exact on / off | m22 mean on / off | m22 better / worse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-fire-emblem-sacred-stones | - | no | derived | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | - / - | - / - | - / - |
|  | | | the rule was derived on this game | | | | | | | | | | | | | | | |
| gba-golden-sun | agbcc | yes | helps | differ {"functions": [2484, 2484]} | 0.8667 / 0.8667 | 0.9781 / 0.9781 | 0.9898 / 0.9898 | 0.9812 / 0.3184 | 11 / 11 | 6 / 6 | 18 / 18 | 383 / 383 | 0 | 1681 | 18.6 / 18.3 | - / - | - / - | - / - |
|  | | | size_exact 0.3184 -> 0.9812 | | | | | | | | | | | | | | | |
| gba-kh-chain-of-memories | - | no | derived | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | - / - | - / - | - / - |
|  | | | the rule was derived on this game | | | | | | | | | | | | | | | |
| gba-klonoa-empire-of-dreams | agbcc | yes | helps | differ {"functions": [524, 524]} | 0.8612 / 0.8612 | 0.9237 / 0.9237 | 0.9896 / 0.9896 | 0.9574 / 0.1682 | 43 / 43 | 28 / 28 | 58 / 58 | 1175 / 1175 | 0 | 375 | 2.0 / 2.2 | - / - | - / - | - / - |
|  | | | size_exact 0.1682 -> 0.9574 | | | | | | | | | | | | | | | |
| gba-nascar-heat-2002 | - | no | derived | differ {} | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - / - | - | - | - / - | - / - | - / - | - / - |
|  | | | the rule was derived on this game | | | | | | | | | | | | | | | |
| nds-dragon-quest-iv | mwcc-arm | yes | helps | differ {"functions": [5036, 5036]} | 0.9062 / 0.9062 | 0.9978 / 0.9978 | 1.0 / 1.0 | 0.9922 / 0.4693 | 0 / 0 | 0 / 0 | 28 / 28 | 191 / 191 | 0 | 2632 | 8.0 / 7.9 | - / - | - / - | - / - |
|  | | | size_exact 0.4693 -> 0.9922 | | | | | | | | | | | | | | | |
| nds-kh-358-2-days | mwcc-arm | yes | helps | differ {"functions": [1950, 1950]} | 0.8662 / 0.8662 | 0.9395 / 0.9395 | 1.0 / 1.0 | 0.9945 / 0.4389 | 7 / 7 | 3 / 3 | 9 / 9 | 206 / 206 | 0 | 1084 | 23.2 / 20.3 | - / - | - / - | - / - |
|  | | | size_exact 0.4389 -> 0.9945 | | | | | | | | | | | | | | | |
| nds-kh-recoded | mwcc-arm | yes | helps | differ {"functions": [2532, 2532]} | 0.8977 / 0.8977 | 0.957 / 0.957 | 1.0 / 1.0 | 0.9971 / 0.4589 | 6 / 6 | 4 / 4 | 7 / 7 | 158 / 158 | 0 | 1354 | 11.2 / 11.0 | - / - | - / - | - / - |
|  | | | size_exact 0.4589 -> 0.9971 | | | | | | | | | | | | | | | |
| nds-pokemon-platinum | mwcc-arm | yes | helps | differ {"functions": [10795, 10795]} | 0.9755 / 0.9755 | 0.9943 / 0.9943 | 1.0 / 1.0 | 0.9985 / 0.5667 | 0 / 0 | 0 / 0 | 0 / 0 | 210 / 210 | 0 | 4651 | 25.0 / 24.5 | - / - | - / - | - / - |
|  | | | size_exact 0.5667 -> 0.9985 | | | | | | | | | | | | | | | |
| nds-world-ends-with-you | mwcc-arm | yes | helps | differ {"functions": [2471, 2471]} | 0.9042 / 0.9042 | 0.9935 / 0.9935 | 1.0 / 1.0 | 0.9935 / 0.4399 | 0 / 0 | 0 / 0 | 24 / 24 | 165 / 165 | 0 | 1370 | 11.7 / 11.4 | - / - | - / - | - / - |
|  | | | size_exact 0.4399 -> 0.9935 | | | | | | | | | | | | | | | |

### `nonreturn-itanium-eh`

Itanium C++ ABI runtime entry points that never return (throw, terminate, unwind resume, the std::terminate mangled names). Emitted by GNU and LLVM runtimes; CodeWarrior and MSVC have their own.

kind `nonreturn-names`, status `on`, origin `migrated`, compilers `gcc, clang, ee-gcc, sn-prodg, allegrex-gcc, agbcc, n64-gcc, devkitarm-gcc, devkitppc-gcc, devkita64-gcc` (and unknown); derived from: ghidra-12.1.3 ElfFunctionsThatDoNotReturn. Bar: hurts no held-out game (migrated); outcome **neutral**.

| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | m22 exact on / off | m22 mean on / off | m22 better / worse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ps2-digital-devil-saga | ee-gcc-2.9x | yes | neutral | identical | 0.9974 / 0.9974 | 0.9987 / 0.9987 | - / - | 0.9982 / 0.9982 | - / - | - / - | - / - | - / - | - | 0 | 14.8 / 18.7 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-fatal-frame | ee-gcc-2.9x | yes | neutral | identical | 0.9958 / 0.9958 | 0.9993 / 0.9993 | - / - | 0.9981 / 0.9981 | - / - | - / - | - / - | - / - | - | 0 | 7.8 / 9.7 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-fatal-frame-symtab | ee-gcc-2.9x | yes | neutral | identical | 1.0 / 1.0 | 0.9998 / 0.9998 | - / - | 0.9995 / 0.9995 | - / - | - / - | - / - | - / - | - | 0 | 5.5 / 7.7 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-god-hand | sn-prodg | yes | neutral | identical | 0.9976 / 0.9976 | 0.9943 / 0.9943 | - / - | 0.9951 / 0.9951 | - / - | - / - | - / - | - / - | - | 0 | 30.1 / 38.8 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-ratchet-clank | ee-gcc-2.9x | yes | neutral | identical | 0.9281 / 0.9281 | 0.9965 / 0.9965 | - / - | 0.9645 / 0.9645 | - / - | - / - | - / - | - / - | - | 0 | 16.3 / 18.2 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| ps2-ratchet-clank-pal | ee-gcc-2.9x | yes | neutral | identical | 0.9276 / 0.9276 | 0.9947 / 0.9947 | - / - | 0.9509 / 0.9509 | - / - | - / - | - / - | - / - | - | 0 | 16.3 / 14.7 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |

### `thumb-pop-bx-is-return`

A Thumb `pop {..rX..}; bx rX` is a function return, not a computed jump. agbcc and older GCC return this way from nearly every function; as switch candidates they made recovery decompile 12,607 pokeemerald owners (budget-capped at 1,024, 1,400 s) to find no table. Read by discovery's indirect-jump list and by the VSA nested-dispatch scan.

kind `flag`, status `on`, origin `migrated`, compilers `agbcc, gcc, devkitarm-gcc, mwcc-arm` (and unknown); derived from: gba-pokeemerald. Bar: hurts no held-out game (migrated); outcome **neutral**.

| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | m22 exact on / off | m22 mean on / off | m22 better / worse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-fire-emblem-sacred-stones | agbcc | yes | neutral | differ {"functions": [8214, 8214], "xrefs": [57339, 57300]} | 0.9536 / 0.9536 | 0.9887 / 0.9887 | 1.0 / 1.0 | 0.9962 / 0.9959 | 7 / 7 | 3 / 3 | 0 / 0 | 98 / 98 | 1 | 2 | 8.1 / 13.1 | - / - | - / - | - / - |
| gba-golden-sun | agbcc | yes | neutral | identical | 0.8667 / 0.8667 | 0.9781 / 0.9781 | - / - | 0.9812 / 0.9812 | - / - | - / - | - / - | - / - | - | 0 | 18.6 / 56.5 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| gba-kh-chain-of-memories | agbcc | yes | neutral | differ {"functions": [5226, 5226], "xrefs": [62094, 62061]} | 0.9582 / 0.9582 | 0.9638 / 0.9638 | 1.0 / 1.0 | 0.9918 / 0.9918 | 16 / 16 | 11 / 11 | 0 / 0 | 202 / 202 | 0 | 1 | 11.0 / 26.5 | - / - | - / - | - / - |
| gba-klonoa-empire-of-dreams | agbcc | yes | neutral | identical | 0.8612 / 0.8612 | 0.9237 / 0.9237 | - / - | 0.9574 / 0.9574 | - / - | - / - | - / - | - / - | - | 0 | 2.0 / 9.8 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| gba-nascar-heat-2002 | agbcc | yes | neutral | differ {"functions": [1083, 1083], "xrefs": [10110, 10138]} | 0.8009 / 0.8009 | 0.9732 / 0.9732 | 0.9756 / 0.9756 | 0.9695 / 0.9704 | 3 / 3 | 2 / 2 | 38 / 38 | 112 / 112 | 0 | 1 | 1.5 / 8.8 | - / - | - / - | - / - |
| nds-dragon-quest-iv | mwcc-arm | yes | neutral | identical | 0.9062 / 0.9062 | 0.9978 / 0.9978 | - / - | 0.9922 / 0.9922 | - / - | - / - | - / - | - / - | - | 0 | 8.0 / 14.9 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| nds-kh-358-2-days | mwcc-arm | yes | neutral | identical | 0.8662 / 0.8662 | 0.9395 / 0.9395 | - / - | 0.9945 / 0.9945 | - / - | - / - | - / - | - / - | - | 0 | 23.2 / 43.8 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| nds-kh-recoded | mwcc-arm | yes | neutral | identical | 0.8977 / 0.8977 | 0.957 / 0.957 | - / - | 0.9971 / 0.9971 | - / - | - / - | - / - | - / - | - | 0 | 11.2 / 11.5 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| nds-pokemon-platinum | mwcc-arm | yes | neutral | identical | 0.9755 / 0.9755 | 0.9943 / 0.9943 | - / - | 0.9985 / 0.9985 | - / - | - / - | - / - | - / - | - | 0 | 25.0 / 21.9 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| nds-world-ends-with-you | mwcc-arm | yes | neutral | identical | 0.9042 / 0.9042 | 0.9935 / 0.9935 | - / - | 0.9935 / 0.9935 | - / - | - / - | - / - | - / - | - | 0 | 11.7 / 9.6 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |

### `thumb-frame-teardown-entry`

A Thumb entry whose first instruction gives back a frame it never built (`add sp,#imm` or a `pop`) is the tail of the function above, reached by a `bl` the compiler used as a long jump (agbcc does, past a conditional branch's range). Such an entry is refused as a function start. pokeemerald: 13 entries against none of the 15,856 FUNC symbols.

kind `flag`, status `on`, origin `migrated`, compilers `agbcc, gcc, devkitarm-gcc, mwcc-arm` (and unknown); derived from: gba-pokeemerald. Bar: hurts no held-out game (migrated); outcome **helps**.

| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | m22 exact on / off | m22 mean on / off | m22 better / worse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-fire-emblem-sacred-stones | agbcc | yes | helps | differ {"functions": [8214, 8215], "flow_overrides": [15, 16], "xre | 0.9536 / 0.9536 | 0.9887 / 0.9886 | 1.0 / 1.0 | 0.9962 / 0.9958 | 25 / 25 | 15 / 15 | 0 / 0 | 153 / 153 | 1 | 3 | 8.1 / 7.0 | - / - | - / - | - / - |
|  | | | precision 0.9886 -> 0.9887 | | | | | | | | | | | | | | | |
| gba-golden-sun | agbcc | yes | helps | differ {"functions": [2484, 2486], "thunks": [2, 3], "flow_override | 0.8667 / 0.8667 | 0.9781 / 0.9777 | 1.0 / 1.0 | 0.9812 / 0.9812 | 3 / 3 | 2 / 2 | 20 / 20 | 142 / 140 | 3 | 3 | 18.6 / 14.4 | - / - | - / - | - / - |
|  | | | precision 0.9777 -> 0.9781 | | | | | | | | | | | | | | | |
| gba-kh-chain-of-memories | agbcc | yes | neutral | differ {"functions": [5226, 5226], "xrefs": [62094, 62102]} | 0.9582 / 0.9582 | 0.9638 / 0.9638 | 1.0 / 1.0 | 0.9918 / 0.9916 | 18 / 18 | 12 / 12 | 0 / 0 | 126 / 126 | 0 | 1 | 11.0 / 12.0 | - / - | - / - | - / - |
| gba-klonoa-empire-of-dreams | agbcc | yes | helps | differ {"functions": [524, 527], "flow_overrides": [33, 34], "xrefs | 0.8612 / 0.8612 | 0.9237 / 0.9184 | 1.0 / 1.0 | 0.9574 / 0.9552 | 27 / 26 | 17 / 16 | 48 / 48 | 544 / 542 | 1 | 3 | 2.0 / 2.3 | - / - | - / - | - / - |
|  | | | precision 0.9184 -> 0.9237 | | | | | | | | | | | | | | | |
| gba-nascar-heat-2002 | agbcc | yes | neutral | differ {"functions": [1083, 1083]} | 0.8009 / 0.8009 | 0.9732 / 0.9732 | 0.9756 / 0.9756 | 0.9695 / 0.9685 | 26 / 26 | 16 / 16 | 21 / 21 | 167 / 167 | 0 | 1 | 1.5 / 1.6 | - / - | - / - | - / - |
| nds-dragon-quest-iv | mwcc-arm | yes | neutral | differ {"functions": [5036, 5036], "xrefs": [30648, 30652]} | 0.9062 / 0.9062 | 0.9978 / 0.9978 | 1.0 / 1.0 | 0.9922 / 0.9918 | 0 / 0 | 0 / 0 | 12 / 12 | 118 / 118 | 0 | 2 | 8.0 / 7.5 | - / - | - / - | - / - |
| nds-kh-358-2-days | mwcc-arm | yes | neutral | identical | 0.8662 / 0.8662 | 0.9395 / 0.9395 | - / - | 0.9945 / 0.9945 | - / - | - / - | - / - | - / - | - | 0 | 23.2 / 26.6 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| nds-kh-recoded | mwcc-arm | yes | neutral | identical | 0.8977 / 0.8977 | 0.957 / 0.957 | - / - | 0.9971 / 0.9971 | - / - | - / - | - / - | - / - | - | 0 | 11.2 / 10.1 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |
| nds-pokemon-platinum | mwcc-arm | yes | helps | differ {"functions": [10795, 10796], "xrefs": [54680, 54686]} | 0.9755 / 0.9755 | 0.9943 / 0.9942 | 1.0 / 1.0 | 0.9985 / 0.9984 | 0 / 0 | 0 / 0 | 6 / 6 | 135 / 135 | 0 | 2 | 25.0 / 24.0 | - / - | - / - | - / - |
|  | | | precision 0.9942 -> 0.9943 | | | | | | | | | | | | | | | |
| nds-world-ends-with-you | mwcc-arm | yes | neutral | identical | 0.9042 / 0.9042 | 0.9935 / 0.9935 | - / - | 0.9935 / 0.9935 | - / - | - / - | - / - | - / - | - | 0 | 11.7 / 10.9 | - / - | - / - | - / - |
|  | | | stored facts identical; nothing to decompile differently | | | | | | | | | | | | | | | |

### `mwcc-register-sleds`

CodeWarrior prologues that keep many callee-saved registers call _savegpr_N/_restgpr_N/_savefpr_N/_restfpr_N, runtime sleds that store (or load) rN..r31 (fN..f31) at negative offsets from r11. The importer names a sled entry when the bytes prove it (the words from that entry to the closing blr are exactly the helper's instructions); the worker gives each helper a call fixup so the decompiler sees the stores and loads instead of an opaque call. Layout read off Animal Crossing main.dol 0x8009ae00..0x8009af2c.

kind `register-sled`, status `on`, origin `migrated`, compilers `mwcc` (and unknown); derived from: gc-animal-crossing. Bar: hurts no held-out game (migrated); outcome **helps**.

| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | m22 exact on / off | m22 mean on / off | m22 better / worse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gc-melee | mwcc-gc | yes | neutral | identical | 0.9997 / 0.9997 | 0.9993 / 0.9993 | 1.0 / 1.0 | 0.9985 / 0.9985 | 2 / 2 | 1 / 1 | 3 / 3 | 84 / 84 | 0 | 0 | 23.9 / 22.1 | - / - | - / - | - / - |
| gc-pikmin | mwcc-gc | yes | helps | differ {"functions": [8095, 8095]} | 0.9993 / 0.9993 | 0.9959 / 0.9959 | 1.0 / 1.0 | 0.9965 / 0.9965 | 13 / 10 | 5 / 6 | 0 / 0 | 208 / 191 | 20 | 20 | 9.5 / 9.0 | - / - | - / - | - / - |
|  | | | sled_calls 39 -> 12 | | | | | | | | | | | | | | | |
| gc-pikmin-2 | mwcc-gc | yes | helps | differ {"functions": [24991, 24991]} | 0.9998 / 0.9998 | 0.9984 / 0.9984 | 1.0 / 1.0 | 0.9985 / 0.9985 | 9 / 9 | 8 / 8 | 162 / 162 | 185 / 171 | 17 | 17 | 19.7 / 26.7 | - / - | - / - | - / - |
|  | | | sled_calls 29 -> 12 | | | | | | | | | | | | | | | |
| gc-super-mario-strikers | mwcc-gc | yes | helps | differ {"functions": [8634, 8634]} | 0.9993 / 0.9993 | 0.9958 / 0.9958 | 1.0 / 1.0 | 0.998 / 0.998 | 72 / 74 | 42 / 44 | 844 / 846 | 614 / 568 | 61 | 101 | 10.9 / 10.3 | - / - | - / - | - / - |
|  | | | unaff 846 -> 844; sled_calls 131 -> 30 | | | | | | | | | | | | | | | |
| gc-tiger-woods-2004 | mwcc-gc | yes | helps | differ {"functions": [7656, 7656]} | 0.9993 / 0.9993 | 0.9982 / 0.9982 | 1.0 / 1.0 | 0.9983 / 0.9983 | 11 / 11 | 9 / 9 | 19 / 19 | 130 / 122 | 8 | 8 | 6.9 / 6.1 | - / - | - / - | - / - |
|  | | | sled_calls 14 -> 6 | | | | | | | | | | | | | | | |
| gc-twilight-princess | mwcc-gc | yes | helps | differ {"functions": [48196, 48196]} | 0.9999 / 0.9999 | 0.998 / 0.998 | 1.0 / 0.99 | 0.9994 / 0.9994 | 0 / 0 | 0 / 0 | 328 / 341 | 761 / 860 | 64 | 9102 | 127.5 / 119.9 | - / - | - / - | - / - |
|  | | | success 0.99 -> 1.0; unaff 341 -> 328; sled_calls 208 -> 1 | | | | | | | | | | | | | | | |
| gc-wind-waker | mwcc-gc | yes | helps | differ {"functions": [39379, 39379]} | 0.9999 / 0.9999 | 0.9983 / 0.9983 | 1.0 / 1.0 | 0.9996 / 0.9996 | 7 / 10 | 3 / 5 | 93 / 102 | 648 / 644 | 65 | 6059 | 71.3 / 79.9 | - / - | - / - | - / - |
|  | | | unaff 102 -> 93; sled_calls 218 -> 0 | | | | | | | | | | | | | | | |
| wii-mario-strikers-charged | mwcc-wii | yes | helps | differ {"functions": [17695, 17695]} | 0.9973 / 0.9973 | 0.9969 / 0.9969 | 1.0 / 1.0 | 0.9841 / 0.9841 | 62 / 65 | 28 / 29 | 954 / 973 | 813 / 945 | 62 | 1607 | 28.8 / 35.6 | - / - | - / - | - / - |
|  | | | unaff 973 -> 954; sled_calls 257 -> 1 | | | | | | | | | | | | | | | |
| wii-npc-pikmin-2 | mwcc-wii | yes | helps | differ {"functions": [28170, 28170]} | 0.9978 / 0.9978 | 0.9958 / 0.9958 | 1.0 / 1.0 | 0.9768 / 0.9768 | 4 / 6 | 2 / 3 | 1227 / 1237 | 697 / 861 | 60 | 1395 | 31.6 / 61.7 | - / - | - / - | - / - |
|  | | | unaff 1237 -> 1227; sled_calls 187 -> 2 | | | | | | | | | | | | | | | |
| wii-rock-band-3 | mwcc-wii | yes | helps | differ {"functions": [58450, 58450]} | 0.9873 / 0.9873 | 0.9983 / 0.9983 | 1.0 / 1.0 | 0.9756 / 0.9756 | 9 / 9 | 5 / 5 | 135 / 144 | 642 / 685 | 70 | 14766 | 58.2 / 107.7 | - / - | - / - | - / - |
|  | | | unaff 144 -> 135; sled_calls 224 -> 0 | | | | | | | | | | | | | | | |
| wii-skyward-sword | mwcc-wii | yes | helps | differ {"functions": [27348, 27348]} | 0.9894 / 0.9894 | 0.996 / 0.996 | 1.0 / 1.0 | 0.9773 / 0.9773 | 4 / 4 | 2 / 2 | 676 / 684 | 783 / 865 | 63 | 2205 | 29.3 / 59.5 | - / - | - / - | - / - |
|  | | | unaff 684 -> 676; sled_calls 209 -> 0 | | | | | | | | | | | | | | | |
| wii-super-mario-galaxy | mwcc-wii | yes | helps | differ {"functions": [41946, 41946]} | 0.997 / 0.997 | 0.9981 / 0.9981 | 1.0 / 1.0 | 0.9892 / 0.9892 | 2 / 5 | 1 / 2 | 418 / 426 | 759 / 773 | 65 | 5923 | 35.8 / 64.0 | - / - | - / - | - / - |
|  | | | unaff 426 -> 418; sled_calls 214 -> 0 | | | | | | | | | | | | | | | |

## Behaviour neutrality of the migration

Every game imported with a build of the tree before the rule layer (tools `5cbd9f2e5373b895`) and with this one with every shipped rule on except the learned ones (the migrated rules only): stored facts (functions, thunks, return behaviours, flow overrides, xrefs, symbols) identical on **60 of 61** games.

With the shipped learned rules on as well, the stored facts of 11 games differ from the baseline, as those rules intend: gba-fire-emblem-sacred-stones {"functions": [8214, 8214]}; gba-golden-sun {"functions": [2484, 2484]}; gba-kh-chain-of-memories {"functions": [5226, 5226]}; gba-klonoa-empire-of-dreams {"functions": [524, 524]}; gba-nascar-heat-2002 {"functions": [1083, 1083]}; nds-dragon-quest-iv {"functions": [5036, 5036]}; nds-kh-358-2-days {"functions": [1950, 1950]}; nds-kh-recoded {"functions": [2532, 2532]}; ...

* x360-forza-horizon-2-prototype: differs in {'functions': [77948, 77939], 'thunks': [699, 697], 'flow_overrides': [5888, 5884], 'xrefs': [432320, 432106]} (baseline, rules)

## Games and their compilers

| game | platform | compiler | language |
|---|---|---|---|
| gba-fire-emblem-sacred-stones | gba | agbcc | ARM:LE:32:v4t |
| gba-golden-sun | gba | agbcc | ARM:LE:32:v4t |
| gba-kh-chain-of-memories | gba | agbcc | ARM:LE:32:v4t |
| gba-klonoa-empire-of-dreams | gba | agbcc | ARM:LE:32:v4t |
| gba-nascar-heat-2002 | gba | agbcc | ARM:LE:32:v4t |
| gc-melee | gc | mwcc-gc | PowerPC:BE:32:Gekko_Broadway |
| gc-pikmin | gc | mwcc-gc | PowerPC:BE:32:Gekko_Broadway |
| gc-pikmin-2 | gc | mwcc-gc | PowerPC:BE:32:Gekko_Broadway |
| gc-super-mario-strikers | gc | mwcc-gc | PowerPC:BE:32:Gekko_Broadway |
| gc-tiger-woods-2004 | gc | mwcc-gc | PowerPC:BE:32:Gekko_Broadway |
| gc-twilight-princess | gc | mwcc-gc | PowerPC:BE:32:Gekko_Broadway |
| gc-wind-waker | gc | mwcc-gc | PowerPC:BE:32:Gekko_Broadway |
| n64-dr-mario-64 | n64 | n64-gcc | MIPS:BE:64:64-32addr |
| n64-majoras-mask | n64 | ido | MIPS:BE:64:64-32addr |
| n64-ocarina-of-time | n64 | ido | MIPS:BE:64:64-32addr |
| n64-perfect-dark | n64 | ido | MIPS:BE:64:64-32addr |
| n64-super-mario-64 | n64 | ido | MIPS:BE:64:64-32addr |
| nds-dragon-quest-iv | nds | mwcc-arm | ARM:LE:32:v5t |
| nds-kh-358-2-days | nds | mwcc-arm | ARM:LE:32:v5t |
| nds-kh-recoded | nds | mwcc-arm | ARM:LE:32:v5t |
| nds-pokemon-platinum | nds | mwcc-arm | ARM:LE:32:v5t |
| nds-world-ends-with-you | nds | mwcc-arm | ARM:LE:32:v5t |
| ps2-dark-chronicle | ps2 | mwcc-ps2-2.4 | r5900:LE:32:default |
| ps2-dark-chronicle-symtab | ps2 | mwcc-ps2-2.4 | r5900:LE:32:default |
| ps2-dark-cloud | ps2 | mwcc-ps2-2.3 | r5900:LE:32:default |
| ps2-dark-cloud-symtab | ps2 | mwcc-ps2-2.3 | r5900:LE:32:default |
| ps2-digital-devil-saga | ps2 | ee-gcc-2.9x | r5900:LE:32:default |
| ps2-fatal-frame | ps2 | ee-gcc-2.9x | r5900:LE:32:default |
| ps2-fatal-frame-symtab | ps2 | ee-gcc-2.9x | r5900:LE:32:default |
| ps2-god-hand | ps2 | sn-prodg | r5900:LE:32:default |
| ps2-persona-4 | ps2 | mwcc-ps2-2.4 | r5900:LE:32:default |
| ps2-ratchet-clank | ps2 | ee-gcc-2.9x | r5900:LE:32:default |
| ps2-ratchet-clank-pal | ps2 | ee-gcc-2.9x | r5900:LE:32:default |
| psp-hot-pixel | psp | allegrex-gcc | Allegrex:LE:32:default |
| psp-hot-pixel-symtab | psp | allegrex-gcc | Allegrex:LE:32:default |
| psp-melodie | psp | allegrex-gcc | Allegrex:LE:32:default |
| psp-melodie-symtab | psp | allegrex-gcc | Allegrex:LE:32:default |
| psp-pac-man-rally | psp | allegrex-gcc | Allegrex:LE:32:default |
| psp-pac-man-rally-symtab | psp | allegrex-gcc | Allegrex:LE:32:default |
| psp-psp-camera-01 | psp | mwcc-psp | MIPS:LE:32:default |
| psp-psp-camera-01-symtab | psp | mwcc-psp | MIPS:LE:32:default |
| psp-tetris | psp | mwcc-psp | MIPS:LE:32:default |
| psp-tetris-symtab | psp | mwcc-psp | MIPS:LE:32:default |
| psx-digimon-world | psx | unknown | PSX:LE:32:default |
| psx-legend-of-mana | psx | unknown | PSX:LE:32:default |
| psx-nfs-high-stakes | psx | unknown | PSX:LE:32:default |
| psx-parasite-eve | psx | unknown | PSX:LE:32:default |
| psx-parasite-eve-2 | psx | unknown | PSX:LE:32:default |
| psx-rage-racer | psx | unknown | PSX:LE:32:default |
| psx-silent-hill | psx | unknown | PSX:LE:32:default |
| psx-vagrant-story | psx | unknown | PSX:LE:32:default |
| wii-mario-strikers-charged | wii | mwcc-wii | PowerPC:BE:32:Gekko_Broadway |
| wii-npc-pikmin-2 | wii | mwcc-wii | PowerPC:BE:32:Gekko_Broadway |
| wii-rock-band-3 | wii | mwcc-wii | PowerPC:BE:32:Gekko_Broadway |
| wii-skyward-sword | wii | mwcc-wii | PowerPC:BE:32:Gekko_Broadway |
| wii-super-mario-galaxy | wii | mwcc-wii | PowerPC:BE:32:Gekko_Broadway |
| x360-amped-3 | x360 | msvc-14 | PowerPC:BE:64:Xenon-32addr |
| x360-burnout-crash | x360 | msvc-16 | PowerPC:BE:64:Xenon-32addr |
| x360-call-of-duty-advanced-warfare | x360 | msvc-16 | PowerPC:BE:64:Xenon-32addr |
| x360-call-of-duty-modern-warfare-2 | x360 | msvc-15 | PowerPC:BE:64:Xenon-32addr |
| x360-forza-horizon-2-prototype | x360 | msvc-16 | PowerPC:BE:64:Xenon-32addr |
