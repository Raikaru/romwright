# Locals, stack slots and return classes against DWARF (supplement)

Scored by `benchmarks/locals_truth.py`; definitions in its docstring. `common` rows score only the functions every listed tool produced C for, so ours and stock are compared on the same functions.

## ps2-capcom-fighting-evolution (truth: dwarf1-python, 5221 functions)

Functions in common: 146.

| tool | set | functions | DWARF locals | printed locals | count exact | over | under | MAE | class recall | class precision |
|---|---|---|---|---|---|---|---|---|---|---|
| ours:default | all_scored | 199 | 130 | 574 | 0.3065 | 0.6734 | 0.0201 | 2.2810 | 0.4692 | 0.1063 |
| ours:default | common | 146 | 117 | 495 | 0.2534 | 0.7329 | 0.0137 | 2.6160 | 0.4872 | 0.1152 |
| ours:infer-prototypes | all_scored | 199 | 130 | 496 | 0.4020 | 0.5779 | 0.0201 | 1.8890 | 0.5385 | 0.1411 |
| ours:infer-prototypes | common | 146 | 117 | 424 | 0.3767 | 0.6027 | 0.0205 | 2.1440 | 0.5641 | 0.1557 |
| stock | all_scored | 147 | 121 | 506 | 0.2517 | 0.7347 | 0.0136 | 2.6460 | 0.4959 | 0.1186 |
| stock | common | 146 | 117 | 498 | 0.2534 | 0.7329 | 0.0137 | 2.6370 | 0.5128 | 0.1205 |

| tool | set | stack: DWARF slots | printed slots | matched | recall | precision | pairs class-exact | return exact / partial / wrong | return exact rate |
|---|---|---|---|---|---|---|---|---|---|
| ours:default | all_scored | 11 | 125 | 11 | 1.0000 | 0.0880 | 1 / 7 | 178 / 0 / 21 | 0.8945 |
| ours:default | common | 11 | 125 | 11 | 1.0000 | 0.0880 | 1 / 7 | 129 / 0 / 17 | 0.8836 |
| ours:infer-prototypes | all_scored | 11 | 118 | 11 | 1.0000 | 0.0932 | 1 / 7 | 166 / 0 / 33 | 0.8342 |
| ours:infer-prototypes | common | 11 | 118 | 11 | 1.0000 | 0.0932 | 1 / 7 | 121 / 0 / 25 | 0.8288 |
| stock | all_scored | 11 | 125 | 11 | 1.0000 | 0.0880 | 5 / 11 | 90 / 7 / 50 | 0.6122 |
| stock | common | 11 | 125 | 11 | 1.0000 | 0.0880 | 5 / 11 | 89 / 7 / 50 | 0.6096 |

## ps2-dungeon-game (truth: readelf, 20 functions)

Functions in common: 20.

| tool | set | functions | DWARF locals | printed locals | count exact | over | under | MAE | class recall | class precision |
|---|---|---|---|---|---|---|---|---|---|---|
| ours:default | all_scored | 20 | 156 | 128 | 0.3000 | 0.5000 | 0.2000 | 4.4000 | 0.3269 | 0.3984 |
| ours:default | common | 20 | 156 | 128 | 0.3000 | 0.5000 | 0.2000 | 4.4000 | 0.3269 | 0.3984 |
| ours:infer-prototypes | all_scored | 20 | 156 | 129 | 0.2500 | 0.5500 | 0.2000 | 4.4500 | 0.3333 | 0.4031 |
| ours:infer-prototypes | common | 20 | 156 | 129 | 0.2500 | 0.5500 | 0.2000 | 4.4500 | 0.3333 | 0.4031 |
| stock | all_scored | 20 | 156 | 128 | 0.3000 | 0.5000 | 0.2000 | 4.4000 | 0.3526 | 0.4297 |
| stock | common | 20 | 156 | 128 | 0.3000 | 0.5000 | 0.2000 | 4.4000 | 0.3526 | 0.4297 |

| tool | set | stack: DWARF slots | printed slots | matched | recall | precision | pairs class-exact | return exact / partial / wrong | return exact rate |
|---|---|---|---|---|---|---|---|---|---|
| ours:default | all_scored | 28 | 44 | 28 | 1.0000 | 0.6364 | 0 / 13 | 8 / 0 / 12 | 0.4000 |
| ours:default | common | 28 | 44 | 28 | 1.0000 | 0.6364 | 0 / 13 | 8 / 0 / 12 | 0.4000 |
| ours:infer-prototypes | all_scored | 28 | 44 | 28 | 1.0000 | 0.6364 | 2 / 16 | 9 / 0 / 11 | 0.4500 |
| ours:infer-prototypes | common | 28 | 44 | 28 | 1.0000 | 0.6364 | 2 / 16 | 9 / 0 / 11 | 0.4500 |
| stock | all_scored | 28 | 44 | 28 | 1.0000 | 0.6364 | 14 / 28 | 5 / 1 / 14 | 0.2500 |
| stock | common | 28 | 44 | 28 | 1.0000 | 0.6364 | 14 / 28 | 5 / 1 / 14 | 0.2500 |

## psp-puzzle-bobble-pocket (truth: readelf, 145 functions)

Functions in common: 144.

| tool | set | functions | DWARF locals | printed locals | count exact | over | under | MAE | class recall | class precision |
|---|---|---|---|---|---|---|---|---|---|---|
| ours:default | all_scored | 144 | 647 | 875 | 0.3333 | 0.4444 | 0.2222 | 3.1940 | 0.5348 | 0.3954 |
| ours:default | common | 144 | 647 | 875 | 0.3333 | 0.4444 | 0.2222 | 3.1940 | 0.5348 | 0.3954 |
| ours:infer-prototypes | all_scored | 144 | 647 | 881 | 0.3264 | 0.4514 | 0.2222 | 3.3190 | 0.5301 | 0.3893 |
| ours:infer-prototypes | common | 144 | 647 | 881 | 0.3264 | 0.4514 | 0.2222 | 3.3190 | 0.5301 | 0.3893 |

| tool | set | stack: DWARF slots | printed slots | matched | recall | precision | pairs class-exact | return exact / partial / wrong | return exact rate |
|---|---|---|---|---|---|---|---|---|---|
| ours:default | all_scored | 138 | 782 | 133 | 0.9638 | 0.1701 | 3 / 4 | 56 / 0 / 88 | 0.3889 |
| ours:default | common | 138 | 782 | 133 | 0.9638 | 0.1701 | 3 / 4 | 56 / 0 / 88 | 0.3889 |
| ours:infer-prototypes | all_scored | 138 | 783 | 135 | 0.9783 | 0.1724 | 4 / 8 | 68 / 0 / 76 | 0.4722 |
| ours:infer-prototypes | common | 138 | 783 | 135 | 0.9783 | 0.1724 | 4 / 8 | 68 / 0 / 76 | 0.4722 |

## psp-puzzle-bobble-pocket-symtab (truth: readelf, 145 functions)

Functions in common: 130.

| tool | set | functions | DWARF locals | printed locals | count exact | over | under | MAE | class recall | class precision |
|---|---|---|---|---|---|---|---|---|---|---|
| ours:default | all_scored | 130 | 631 | 852 | 0.2923 | 0.4538 | 0.2538 | 3.5000 | 0.5325 | 0.3944 |
| ours:default | common | 130 | 631 | 852 | 0.2923 | 0.4538 | 0.2538 | 3.5000 | 0.5325 | 0.3944 |
| ours:infer-prototypes | all_scored | 130 | 631 | 949 | 0.2846 | 0.4923 | 0.2231 | 4.2460 | 0.5341 | 0.3551 |
| ours:infer-prototypes | common | 130 | 631 | 949 | 0.2846 | 0.4923 | 0.2231 | 4.2460 | 0.5341 | 0.3551 |

| tool | set | stack: DWARF slots | printed slots | matched | recall | precision | pairs class-exact | return exact / partial / wrong | return exact rate |
|---|---|---|---|---|---|---|---|---|---|
| ours:default | all_scored | 135 | 738 | 130 | 0.9630 | 0.1762 | 8 / 15 | 48 / 0 / 82 | 0.3692 |
| ours:default | common | 135 | 738 | 130 | 0.9630 | 0.1762 | 8 / 15 | 48 / 0 / 82 | 0.3692 |
| ours:infer-prototypes | all_scored | 135 | 739 | 132 | 0.9778 | 0.1786 | 9 / 19 | 59 / 0 / 71 | 0.4538 |
| ours:infer-prototypes | common | 135 | 739 | 132 | 0.9778 | 0.1786 | 9 / 19 | 59 / 0 / 71 | 0.4538 |

## gba-pokeemerald (truth: pyelftools-tolerant, 15678 functions)

Functions in common: 200.

| tool | set | functions | DWARF locals | printed locals | count exact | over | under | MAE | class recall | class precision |
|---|---|---|---|---|---|---|---|---|---|---|
| ours:default | all_scored | 200 | 184 | 455 | 0.3400 | 0.6250 | 0.0350 | 1.4750 | 0.4946 | 0.2000 |
| ours:default | common | 200 | 184 | 455 | 0.3400 | 0.6250 | 0.0350 | 1.4750 | 0.4946 | 0.2000 |

| tool | set | stack: DWARF slots | printed slots | matched | recall | precision | pairs class-exact | return exact / partial / wrong | return exact rate |
|---|---|---|---|---|---|---|---|---|---|
| ours:default | all_scored | 0 | 42 | 0 | - | 0.0000 | 0 / 0 | 167 / 0 / 33 | 0.8350 |
| ours:default | common | 0 | 42 | 0 | - | 0.0000 | 0 / 0 | 167 / 0 / 33 | 0.8350 |

## nds-pokeheartgold-arm9 (truth: readelf, 9530 functions)

Functions in common: 175.

| tool | set | functions | DWARF locals | printed locals | count exact | over | under | MAE | class recall | class precision |
|---|---|---|---|---|---|---|---|---|---|---|
| ours:default | all_scored | 200 | 253 | 443 | 0.4700 | 0.4950 | 0.0350 | 1.0600 | 0.4348 | 0.2483 |
| ours:default | common | 175 | 214 | 382 | 0.4800 | 0.4857 | 0.0343 | 1.0630 | 0.4346 | 0.2435 |
| stock | all_scored | 175 | 214 | 386 | 0.4914 | 0.4914 | 0.0171 | 1.0510 | 0.4579 | 0.2539 |
| stock | common | 175 | 214 | 386 | 0.4914 | 0.4914 | 0.0171 | 1.0510 | 0.4579 | 0.2539 |

| tool | set | stack: DWARF slots | printed slots | matched | recall | precision | pairs class-exact | return exact / partial / wrong | return exact rate |
|---|---|---|---|---|---|---|---|---|---|
| ours:default | all_scored | 0 | 56 | 0 | - | 0.0000 | 0 / 0 | 112 / 0 / 88 | 0.5600 |
| ours:default | common | 0 | 53 | 0 | - | 0.0000 | 0 / 0 | 106 / 0 / 69 | 0.6057 |
| stock | all_scored | 0 | 0 | 0 | - | - | 0 / 0 | 90 / 43 / 42 | 0.5143 |
| stock | common | 0 | 0 | 0 | - | - | 0 / 0 | 90 / 43 / 42 | 0.5143 |

