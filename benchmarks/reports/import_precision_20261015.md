# Import precision against stock Ghidra

Tools: release cli and worker of the tree after ImportPrecision (fingerprint 02fd4917ccfce59f), ghidra_opt 486ace43 (unchanged). Before: the tree at the start of the work, the five PSP images rescored on the audited truth. The GBA, NDS, GC, Wii and x360 rows were imported by an earlier build of the same sources (no rule or change of the final build reaches them).

Wins/losses/ties of ours against stock (a win or loss is a difference of 0.5 pp or more); games with a
stock DNF/crash and version-mismatch images (n64-star-fox-64, nds-dragon-quest-iv, psx-nfs-high-stakes) are in no test.

| platform | games | recall | precision | recall_verified | precision_verified |
|---|---|---|---|---|---|
| all | 53 | 51/0/2 (p=0) | 15/2/36 (p=0.00117) | 52/0/1 (p=0) | 6/2/44 (p=0.145) |
| gba | 3 | 3/0/0 (p=0.125) | 3/0/0 (p=0.125) | 3/0/0 (p=0.125) | 3/0/0 (p=0.125) |
| gc | 8 | 8/0/0 (p=0.00391) | 0/0/8 | 8/0/0 (p=0.00391) | 0/0/8 |
| n64 | 8 | 8/0/0 (p=0.00391) | 4/0/4 (p=0.0625) | 8/0/0 (p=0.00391) | 2/0/5 (p=0.25) |
| nds | 4 | 3/0/1 (p=0.125) | 2/0/2 (p=0.25) | 4/0/0 (p=0.0625) | 0/0/4 |
| ps2 | 8 | 8/0/0 (p=0.00391) | 1/0/7 (p=0.5) | 8/0/0 (p=0.00391) | 1/0/7 (p=0.5) |
| psp | 5 | 5/0/0 (p=0.0312) | 0/2/3 | 5/0/0 (p=0.0312) | 0/1/4 |
| psx | 7 | 7/0/0 (p=0.00781) | 5/0/2 (p=0.0312) | 7/0/0 (p=0.00781) | 0/1/6 |
| wii | 5 | 5/0/0 (p=0.0312) | 0/0/5 | 5/0/0 (p=0.0312) | 0/0/5 |
| x360 | 5 | 4/0/1 (p=0.0625) | 0/0/5 | 4/0/1 (p=0.0625) | 0/0/5 |

## Per image (ours / stock; `was` = the same metric before the change)

| image | recall | precision | precision was | recall_v | precision_v | precision_v was | invented ours / stock | import s | was |
|---|---|---|---|---|---|---|---|---|---|
| gba-fire-emblem-sacred-stones | 0.9536 / stock DNF (>4 h auto-analysis) | 0.9893 / stock DNF (>4 h auto-analysis) | 0.9893 | 0.958 / stock DNF (>4 h auto-analysis) | 0.9989 / stock DNF (>4 h auto-analysis) | 0.9989 | 88 / - | 47.2 | 49.9 |
| gba-golden-sun | 0.8667 / 0.6214 | 0.9781 / 0.6421 | 0.9781 | 0.9435 / 0.6684 | 0.9974 / 0.6932 | 0.9974 | 53 / 946 | 88.9 | 100.8 |
| gba-kh-chain-of-memories | 0.9582 / stock crashed (StackOverflowError in CreateFunctionCmd / CreateThunkFunctionCmd) | 0.964 / stock crashed (StackOverflowError in CreateFunctionCmd / CreateThunkFunctionCmd) | 0.964 | 0.9634 / stock crashed (StackOverflowError in CreateFunctionCmd / CreateThunkFunctionCmd) | 0.9924 / stock crashed (StackOverflowError in CreateFunctionCmd / CreateThunkFunctionCmd) | 0.9924 | 188 / - | 75.9 | 53.2 |
| gba-klonoa-empire-of-dreams | 0.8612 / 0.6708 | 0.9254 / 0.0153 | 0.9254 | 0.9418 / 0.6961 | 0.9583 / 0.4562 | 0.9583 | 39 / 24327 | 17.0 | 8.4 |
| gba-nascar-heat-2002 | 0.8151 / 0.7244 | 0.9818 / 0.0321 | 0.9818 | 0.8165 / 0.7034 | 1.0 / 0.9426 | 1.0 | 13 / 18793 | 9.9 | 6.3 |
| gc-mario-party-4 | 0.9988 / 0.9608 | 0.9897 / 0.989 | 0.9897 | 0.9988 / 0.9608 | 0.9908 / 0.989 | 0.9908 | 36 / 37 | 116.0 | 32.9 |
| gc-melee | 0.9997 / 0.8559 | 0.9993 / 0.9992 | 0.9993 | 0.9997 / 0.8559 | 0.9994 / 0.9992 | 0.9994 | 14 / 13 | 141.2 | 27.5 |
| gc-pikmin | 0.9993 / 0.8168 | 0.9959 / 0.9971 | 0.9959 | 0.9993 / 0.8168 | 0.9963 / 0.9971 | 0.9963 | 33 / 19 | 48.7 | 11.1 |
| gc-pikmin-2 | 0.9998 / 0.7383 | 0.9984 / 0.999 | 0.9984 | 0.9998 / 0.739 | 0.9985 / 0.999 | 0.9985 | 40 / 18 | 111.9 | 24.1 |
| gc-super-mario-strikers | 0.9993 / 0.8679 | 0.9958 / 0.9955 | 0.9958 | 0.9993 / 0.8679 | 0.9961 / 0.9955 | 0.9961 | 36 / 34 | 49.4 | 14.0 |
| gc-tiger-woods-2004 | 0.9993 / 0.9245 | 0.9982 / 0.998 | 0.9982 | 0.9993 / 0.9245 | 0.9983 / 0.998 | 0.9983 | 14 / 14 | 44.0 | 9.8 |
| gc-twilight-princess | 0.9998 / 0.835 | 0.9962 / 0.9962 | 0.9962 | 0.9997 / 0.8498 | 0.9959 / 0.9953 | 0.9959 | 63 / 52 | 807.9 | 267.9 |
| gc-wind-waker | 0.9997 / 0.856 | 0.9962 / 0.9957 | 0.9962 | 0.9999 / 0.8502 | 0.9996 / 0.9989 | 0.9996 | 53 / 51 | 159.2 | 185.2 |
| n64-banjo-kazooie | 0.9876 / 0.0096 | 1.0 / 1.0 | 0.9982 | 0.9876 / 0.0094 | 1.0 / 1.0 | 0.9984 | 0 / 0 | 24.5 | 18.0 |
| n64-dr-mario-64 | 0.9374 / 0.1615 | 0.9955 / 0.9784 | 0.9887 | 0.9367 / 0.1498 | 0.9992 / 1.0 | 0.9923 | 6 / 5 | 8.9 | 8.8 |
| n64-majoras-mask | 0.9782 / 0.0859 | 0.9992 / 0.9972 | 0.998 | 0.9782 / 0.0859 | 0.9992 / 0.9972 | 0.998 | 3 / 1 | 87.1 | 90.5 |
| n64-ocarina-of-time | 0.9842 / 0.0384 | 1.0 / 0.9917 | 0.9977 | 0.9842 / 0.0384 | 1.0 / 0.9917 | 0.9977 | 0 / 1 | 115.0 | 89.0 |
| n64-paper-mario | 0.9701 / 0.6584 | 0.9971 / 0.5786 | 0.9963 | 0.9783 / 0.6632 | 0.9988 / 0.579 | 0.9981 | 8 / 1349 | 55.3 | 36.1 |
| n64-perfect-dark | 0.9525 / 0.0002 | 0.991 / 0.5 | 0.9901 | 0.9534 / 0.0 | 0.9931 / None | 0.9921 | 49 / 1 | 33.7 | 17.1 |
| n64-star-fox-64 (version mismatch) | 0.9725 / 0.9309 | 0.9633 / 0.9707 | 0.9578 | 0.9725 / 0.9309 | 1.0 / 0.9993 | 0.9941 | 58 / 44 | 54.8 | 27.2 |
| n64-super-mario-64 | 0.9966 / 0.9547 | 0.9952 / 0.9997 | 0.9053 | 0.9974 / 0.9554 | 0.9952 / 0.9997 | 0.9052 | 17 / 1 | 17.9 | 8.0 |
| n64-super-smash-bros | 0.9551 / 0.8709 | 0.9989 / 1.0 | 0.9898 | 0.9732 / 0.8884 | 0.9989 / 1.0 | 0.9898 | 1 / 0 | 24.5 | 10.7 |
| nds-dragon-quest-iv (version mismatch) | 0.9071 / 0.8606 | 0.9986 / 0.9979 | 0.9978 | 0.9071 / 0.8606 | 0.9992 / 0.999 | 0.9992 | 7 / 10 | 65.6 | 10.1 |
| nds-kh-358-2-days | 0.9371 / 0.8388 | 0.9995 / 0.9497 | 0.9395 | 0.9371 / 0.8388 | 0.9995 / 0.9994 | 0.9995 | 1 / 94 | 138.5 | 50.9 |
| nds-kh-recoded | 0.9441 / 0.8685 | 0.9984 / 0.9682 | 0.957 | 0.9565 / 0.8879 | 1.0 / 1.0 | 1.0 | 4 / 77 | 35.5 | 24.5 |
| nds-pokemon-platinum | 0.9766 / 0.85 | 0.9952 / 0.9939 | 0.9943 | 0.9766 / 0.8499 | 0.9995 / 0.9996 | 0.9995 | 52 / 57 | 72.5 | 40.7 |
| nds-world-ends-with-you | 0.9087 / 0.9068 | 0.9972 / 0.9972 | 0.9935 | 0.9028 / 0.8961 | 1.0 / 1.0 | 1.0 | 7 / 7 | 27.1 | 19.3 |
| ps2-dark-chronicle | 0.9987 / 0.9288 | 0.9963 / 0.9982 | 0.9963 | 0.9987 / 0.9278 | 0.9996 / 0.9997 | 0.9996 | 29 / 13 | 55.2 | 136.4 |
| ps2-dark-cloud | 0.9992 / 0.9173 | 0.9907 / 0.985 | 0.9907 | 0.9992 / 0.9173 | 0.999 / 0.9856 | 0.999 | 37 / 55 | 28.8 | 39.0 |
| ps2-digital-devil-saga | 0.9973 / 0.863 | 0.9997 / 1.0 | 0.9987 | 0.9975 / 0.8585 | 0.9997 / 1.0 | 0.9993 | 3 / 0 | 44.9 | 55.4 |
| ps2-fatal-frame | 0.9958 / 0.8334 | 0.9995 / 1.0 | 0.9993 | 0.9959 / 0.8484 | 0.9997 / 1.0 | 0.9997 | 2 / 0 | 20.0 | 27.5 |
| ps2-god-hand | 0.9976 / 0.8552 | 0.9949 / 0.9988 | 0.9943 | 0.998 / 0.8919 | 1.0 / 1.0 | 1.0 | 57 / 12 | 60.1 | 92.6 |
| ps2-persona-4 | 0.9992 / 0.9028 | 0.997 / 0.9997 | 0.9967 | 0.9993 / 0.8991 | 0.999 / 0.9997 | 0.999 | 39 / 3 | 93.2 | 78.3 |
| ps2-ratchet-clank | 0.9281 / 0.7175 | 0.9965 / 1.0 | 0.9965 | 0.9245 / 0.7961 | 0.9993 / 1.0 | 0.9993 | 6 / 0 | 31.7 | 30.7 |
| ps2-ratchet-clank-pal | 0.9276 / 0.7184 | 0.9953 / 1.0 | 0.9947 | 0.9184 / 0.696 | 0.9986 / 1.0 | 0.9986 | 8 / 0 | 31.3 | 23.7 |
| psp-hot-pixel | 0.8924 / 0.5839 | 0.9965 / 0.9988 | 0.9295 | 0.8899 / 0.5763 | 0.999 / 1.0 | 0.9304 | 32 / 7 | 76.9 | 29.5 |
| psp-melodie | 0.962 / 0.5145 | 0.9917 / 0.9971 | 0.9778 | 0.9608 / 0.5126 | 0.9949 / 0.9982 | 0.9805 | 27 / 5 | 10.1 | 4.5 |
| psp-pac-man-rally | 0.9077 / 0.3127 | 0.9967 / 0.9976 | 0.9582 | 0.9067 / 0.3099 | 0.9971 / 0.998 | 0.9573 | 20 / 5 | 64.3 | 34.5 |
| psp-psp-camera-01 | 0.9606 / 0.6486 | 0.9935 / 0.9979 | 0.9902 | 0.9594 / 0.6421 | 0.9944 / 0.9978 | 0.9909 | 42 / 9 | 18.1 | 20.8 |
| psp-tetris | 0.9879 / 0.5183 | 0.9939 / 1.0 | 0.9896 | 0.9876 / 0.5079 | 0.9938 / 1.0 | 0.9894 | 51 / 0 | 34.3 | 26.6 |
| psx-digimon-world | 0.9686 / 0.9194 | 1.0 / 0.9371 | 1.0 | 0.9806 / 0.9393 | 1.0 / 1.0 | 1.0 | 0 / 108 | 12.7 | 2.1 |
| psx-legend-of-mana | 0.8498 / 0.7183 | 1.0 / 0.9686 | 1.0 | 0.812 / 0.7232 | 1.0 / 1.0 | 1.0 | 0 / 20 | 4.5 | 0.9 |
| psx-nfs-high-stakes (version mismatch) | 0.9824 / 0.9502 | 0.9896 / 0.9892 | 0.9896 | 0.9813 / 0.9489 | 1.0 / 1.0 | 1.0 | 17 / 17 | 8.9 | 3.4 |
| psx-parasite-eve | 0.9275 / 0.812 | 0.9959 / 0.9912 | 0.9954 | 0.9275 / 0.812 | 1.0 / 0.9984 | 0.9995 | 9 / 17 | 5.6 | 2.6 |
| psx-parasite-eve-2 | 0.9293 / 0.8166 | 0.9545 / 0.9139 | 0.9545 | 0.9481 / 0.8324 | 0.9542 / 0.9622 | 0.9542 | 57 / 99 | 3.2 | 1.7 |
| psx-rage-racer | 0.9523 / 0.8844 | 0.9956 / 0.9944 | 0.9948 | 0.9523 / 0.8844 | 0.9956 / 0.9944 | 0.9948 | 5 / 6 | 5.3 | 1.7 |
| psx-silent-hill | 0.9953 / 0.872 | 0.8898 / 0.8558 | 0.8898 | 0.9952 / 0.8702 | 0.9 / 0.9005 | 0.9 | 26 / 31 | 1.4 | 0.4 |
| psx-vagrant-story | 0.8614 / 0.752 | 0.9988 / 0.9842 | 0.9988 | 0.8404 / 0.7215 | 0.9981 / 1.0 | 0.9981 | 1 / 12 | 2.0 | 2.8 |
| wii-mario-strikers-charged | 0.9973 / 0.8653 | 0.9969 / 0.9977 | 0.9969 | 0.9973 / 0.8646 | 0.997 / 0.9977 | 0.997 | 55 / 35 | 89.9 | 77.5 |
| wii-npc-pikmin-2 | 0.9978 / 0.6913 | 0.9958 / 0.9983 | 0.9958 | 0.9978 / 0.7319 | 0.9968 / 1.0 | 0.9968 | 117 / 34 | 79.5 | 83.3 |
| wii-rock-band-3 | 0.9873 / 0.8612 | 0.9983 / 0.9961 | 0.9983 | 1.0 / 0.9794 | 1.0 / 1.0 | 1.0 | 100 / 197 | 128.0 | 190.4 |
| wii-skyward-sword | 0.9894 / 0.6205 | 0.996 / 0.9982 | 0.996 | 0.9897 / 0.566 | 0.997 / 1.0 | 0.997 | 109 / 30 | 73.7 | 112.5 |
| wii-super-mario-galaxy | 0.997 / 0.849 | 0.9981 / 0.9987 | 0.9981 | 0.9965 / 0.8531 | 0.9977 / 0.9979 | 0.9977 | 80 / 47 | 86.4 | 151.2 |
| x360-amped-3 | 0.9756 / 0.8194 | 0.9915 / 0.9956 | 0.9915 | 0.9756 / 0.8194 | 0.9931 / 0.9972 | 0.9931 | 304 / 131 | 318.3 | 461.9 |
| x360-burnout-crash | 0.9958 / 0.9952 | 0.9987 / 0.9987 | 0.9987 | 0.9958 / 0.9952 | 1.0 / 1.0 | 1.0 | 14 / 14 | 77.7 | 148.2 |
| x360-call-of-duty-advanced-warfare | 0.9041 / 0.7201 | 0.9972 / 0.9974 | 0.9972 | 0.9041 / 0.7201 | 0.9972 / 0.9975 | 0.9972 | 103 / 75 | 110.9 | 200.5 |
| x360-call-of-duty-modern-warfare-2 | 0.8011 / 0.6631 | 0.9936 / 0.9935 | 0.9936 | 0.8011 / 0.6631 | 0.9936 / 0.9935 | 0.9936 | 96 / 80 | 51.4 | 83.9 |
| x360-forza-horizon-2-prototype | 0.951 / 0.6817 | 0.9989 / 0.9987 | 0.9989 | 0.951 / 0.6817 | 0.9989 / 0.9987 | 0.9989 | 89 / 71 | 582.4 | 586.2 |

## Invented entries by class (`shared` = the other tool found the same entry; a shared entry in no truth row is a truth-gap candidate)

| image | ours | in a verified function | in an unverified row | between rows | shared with stock | by producer | stock | stock in verified | stock between rows | stock shared |
|---|---|---|---|---|---|---|---|---|---|---|
| gba-fire-emblem-sacred-stones | 88 | 9 | 11 | 68 | 0 | pattern 50, flow 20, call 12, thunk 6 | - | - | - | - |
| gba-golden-sun | 53 | 5 | 3 | 45 | 36 | call 26, pattern 19, flow 8 | 946 | 613 | 297 | 36 |
| gba-kh-chain-of-memories | 188 | 38 | 15 | 135 | 0 | pattern 122, call 39, flow 19, thunk 8 | - | - | - | - |
| gba-klonoa-empire-of-dreams | 39 | 19 | 0 | 20 | 18 | call 18, pattern 17, flow 2, thunk 2 | 24327 | 385 | 23942 | 18 |
| gba-nascar-heat-2002 | 13 | 0 | 5 | 8 | 2 | pattern 9, call 2, thunk 1, flow 1 | 18793 | 28 | 18739 | 2 |
| gc-mario-party-4 | 36 | 32 | 0 | 4 | 28 | call 28, flow 8 | 37 | 37 | 0 | 28 |
| gc-melee | 14 | 12 | 0 | 2 | 0 | flow 13, call 1 | 13 | 13 | 0 | 0 |
| gc-pikmin | 33 | 30 | 0 | 3 | 10 | flow 23, call 10 | 19 | 19 | 0 | 10 |
| gc-pikmin-2 | 40 | 38 | 0 | 2 | 8 | flow 31, call 9 | 18 | 18 | 0 | 8 |
| gc-super-mario-strikers | 36 | 34 | 0 | 2 | 26 | call 26, flow 10 | 34 | 34 | 0 | 26 |
| gc-tiger-woods-2004 | 14 | 13 | 0 | 1 | 4 | flow 10, call 4 | 14 | 14 | 0 | 4 |
| gc-twilight-princess | 63 | 53 | 2 | 8 | 41 | call 41, flow 17, const 5 | 52 | 51 | 0 | 41 |
| gc-wind-waker | 53 | 4 | 0 | 49 | 41 | call 41, flow 12 | 51 | 10 | 41 | 41 |
| n64-banjo-kazooie | 0 | 0 | 0 | 0 | 0 |  | 0 | 0 | 0 | 0 |
| n64-dr-mario-64 | 6 | 1 | 5 | 0 | 4 | call 4, flow 2 | 5 | 0 | 0 | 4 |
| n64-majoras-mask | 3 | 3 | 0 | 0 | 0 | flow 3 | 1 | 1 | 0 | 0 |
| n64-ocarina-of-time | 0 | 0 | 0 | 0 | 0 |  | 1 | 1 | 0 | 0 |
| n64-paper-mario | 8 | 3 | 5 | 0 | 5 | call 5, flow 3 | 1349 | 1266 | 73 | 5 |
| n64-perfect-dark | 49 | 37 | 12 | 0 | 0 | flow 37, call 12 | 1 | 0 | 1 | 0 |
| n64-star-fox-64 | 58 | 0 | 0 | 58 | 42 | call 27, flow 16, pattern 15 | 44 | 1 | 43 | 42 |
| n64-super-mario-64 | 17 | 17 | 0 | 0 | 0 | flow 17 | 1 | 1 | 0 | 0 |
| n64-super-smash-bros | 1 | 1 | 0 | 0 | 0 | flow 1 | 0 | 0 | 0 | 0 |
| nds-dragon-quest-iv | 7 | 4 | 0 | 3 | 4 | call 4, pattern 2, flow 1 | 10 | 5 | 5 | 4 |
| nds-kh-358-2-days | 1 | 1 | 0 | 0 | 1 | call 1 | 94 | 1 | 93 | 1 |
| nds-kh-recoded | 4 | 0 | 3 | 1 | 3 | call 3, pattern 1 | 77 | 0 | 74 | 3 |
| nds-pokemon-platinum | 52 | 5 | 0 | 47 | 46 | call 39, flow 8, pattern 5 | 57 | 4 | 53 | 46 |
| nds-world-ends-with-you | 7 | 0 | 6 | 1 | 1 | pattern 6, call 1 | 7 | 0 | 5 | 1 |
| ps2-dark-chronicle | 29 | 3 | 0 | 26 | 11 | flow 26, call 2, const 1 | 13 | 2 | 11 | 11 |
| ps2-dark-cloud | 37 | 4 | 0 | 33 | 2 | call 32, const 3, flow 2 | 55 | 53 | 2 | 2 |
| ps2-digital-devil-saga | 3 | 3 | 0 | 0 | 0 | flow 3 | 0 | 0 | 0 | 0 |
| ps2-fatal-frame | 2 | 1 | 1 | 0 | 0 | flow 2 | 0 | 0 | 0 | 0 |
| ps2-god-hand | 57 | 0 | 13 | 44 | 12 | flow 41, pattern 9, const 4, call 3 | 12 | 0 | 9 | 12 |
| ps2-persona-4 | 39 | 10 | 25 | 4 | 0 | flow 33, const 4, call 2 | 3 | 3 | 0 | 0 |
| ps2-ratchet-clank | 6 | 1 | 5 | 0 | 0 | flow 6 | 0 | 0 | 0 | 0 |
| ps2-ratchet-clank-pal | 8 | 2 | 6 | 0 | 0 | flow 8 | 0 | 0 | 0 | 0 |
| psp-hot-pixel | 32 | 9 | 0 | 23 | 7 | flow 21, call 9, const 2 | 7 | 0 | 7 | 7 |
| psp-melodie | 27 | 16 | 0 | 11 | 2 | flow 17, call 7, pointer 1, const 1 | 5 | 3 | 2 | 2 |
| psp-pac-man-rally | 20 | 17 | 0 | 3 | 1 | flow 18, call 1, const 1 | 5 | 4 | 1 | 1 |
| psp-psp-camera-01 | 42 | 35 | 0 | 7 | 4 | flow 31, call 9, pattern 2 | 9 | 9 | 0 | 4 |
| psp-tetris | 51 | 50 | 0 | 1 | 0 | flow 42, call 6, thunk 3 | 0 | 0 | 0 | 0 |
| psx-digimon-world | 0 | 0 | 0 | 0 | 0 |  | 108 | 0 | 108 | 0 |
| psx-legend-of-mana | 0 | 0 | 0 | 0 | 0 |  | 20 | 0 | 20 | 0 |
| psx-nfs-high-stakes | 17 | 0 | 0 | 17 | 17 | call 17 | 17 | 0 | 17 | 17 |
| psx-parasite-eve | 9 | 0 | 0 | 9 | 6 | call 5, flow 3, pattern 1 | 17 | 3 | 14 | 6 |
| psx-parasite-eve-2 | 57 | 57 | 0 | 0 | 40 | pattern 37, flow 10, const 9, call 1 | 99 | 41 | 58 | 40 |
| psx-rage-racer | 5 | 5 | 0 | 0 | 2 | flow 4, pattern 1 | 6 | 6 | 0 | 2 |
| psx-silent-hill | 26 | 23 | 0 | 3 | 23 | pattern 20, flow 5, call 1 | 31 | 20 | 11 | 23 |
| psx-vagrant-story | 1 | 1 | 0 | 0 | 0 | flow 1 | 12 | 0 | 12 | 0 |
| wii-mario-strikers-charged | 55 | 53 | 0 | 2 | 32 | call 33, flow 22 | 35 | 35 | 0 | 32 |
| wii-npc-pikmin-2 | 117 | 12 | 102 | 3 | 34 | flow 73, call 42, thunk 2 | 34 | 0 | 0 | 34 |
| wii-rock-band-3 | 100 | 0 | 98 | 2 | 53 | call 53, flow 45, pattern 1, thunk 1 | 197 | 0 | 0 | 53 |
| wii-skyward-sword | 109 | 32 | 74 | 3 | 30 | flow 72, call 35, const 1, thunk 1 | 30 | 0 | 0 | 30 |
| wii-super-mario-galaxy | 80 | 57 | 18 | 5 | 43 | call 44, flow 36 | 47 | 44 | 0 | 43 |
| x360-amped-3 | 304 | 245 | 0 | 59 | 131 | flow 191, call 113 | 131 | 84 | 47 | 131 |
| x360-burnout-crash | 14 | 0 | 0 | 14 | 14 | flow 9, call 5 | 14 | 0 | 14 | 14 |
| x360-call-of-duty-advanced-warfare | 103 | 101 | 0 | 2 | 74 | flow 55, call 48 | 75 | 74 | 1 | 74 |
| x360-call-of-duty-modern-warfare-2 | 96 | 96 | 0 | 0 | 79 | call 74, flow 22 | 80 | 80 | 0 | 79 |
| x360-forza-horizon-2-prototype | 89 | 89 | 0 | 0 | 69 | flow 48, call 41 | 71 | 71 | 0 | 69 |
