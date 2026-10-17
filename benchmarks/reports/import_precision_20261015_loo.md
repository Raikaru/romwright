# Rules on against all six import-precision rules off, same tree (leave-one-out aggregate)

Per image: truth entries and invented entries gained or lost when the rules are on (`compare`, read off the two projects; PSP on the audited truth). Off arm: ROMWRIGHT_COMPILER_RULES_DISABLE=landing-pad-not-entry,wide-switch-case-blocks,case-run-in-one-function,branch-table-after-dispatch,epilogue-not-entry,ido-leaf-return-pair. On arm: the final build.

```
n64-banjo-kazooie: hits 6779->6779 (lost 0 gained 0); invented 12->0 (-12 +0); precision 0.9982->1.0 pv 0.9984->1.0; seconds 26.8->24.5
n64-dr-mario-64: hits 1318->1318 (lost 0 gained 0); invented 15->6 (-9 +0); precision 0.9887->0.9955 pv 0.9923->0.9992; seconds 8.2->8.9
n64-majoras-mask: hits 3996->3996 (lost 0 gained 0); invented 8->3 (-5 +0); precision 0.998->0.9992 pv 0.998->0.9992; seconds 116.6->87.1
n64-ocarina-of-time: hits 3046->3046 (lost 0 gained 0); invented 7->0 (-7 +0); precision 0.9977->1.0 pv 0.9977->1.0; seconds 138.7->115.0
n64-paper-mario: hits 2729->2729 (lost 0 gained 0); invented 10->8 (-2 +0); precision 0.9963->0.9971 pv 0.9981->0.9988; seconds 92.0->55.3
n64-perfect-dark: hits 5389->5389 (lost 0 gained 0); invented 54->49 (-5 +0); precision 0.9901->0.991 pv 0.9921->0.9931; seconds 53.0->33.7
n64-super-mario-64: hits 3520->3517 (lost 3 gained 0); invented 368->17 (-351 +0); precision 0.9053->0.9952 pv 0.9052->0.9952; seconds 21.5->17.9 RECALL LOSS
   lost: 0x80325ad0 0x80325ad8 0x80325bcc
n64-super-smash-bros: hits 873->873 (lost 0 gained 0); invented 9->1 (-8 +0); precision 0.9898->0.9989 pv 0.9898->0.9989; seconds 28.7->24.5
ps2-dark-chronicle: hits 7827->7827 (lost 0 gained 0); invented 29->29 (-0 +0); precision 0.9963->0.9963 pv 0.9996->0.9996; seconds 65.0->55.2
ps2-dark-cloud: hits 3939->3939 (lost 0 gained 0); invented 37->37 (-0 +0); precision 0.9907->0.9907 pv 0.999->0.999; seconds 33.8->28.8
ps2-digital-devil-saga: hits 10325->10324 (lost 1 gained 0); invented 13->3 (-10 +0); precision 0.9987->0.9997 pv 0.9993->0.9997; seconds 42.9->44.9 RECALL LOSS
   lost: 0x30c838
ps2-fatal-frame: hits 4232->4232 (lost 0 gained 0); invented 3->2 (-1 +0); precision 0.9993->0.9995 pv 0.9997->0.9997; seconds 24.7->20.0
ps2-god-hand: hits 11206->11206 (lost 0 gained 0); invented 64->57 (-7 +0); precision 0.9943->0.9949 pv 1.0->1.0; seconds 58.2->60.1
ps2-persona-4: hits 13091->13091 (lost 0 gained 0); invented 43->39 (-4 +0); precision 0.9967->0.997 pv 0.999->0.999; seconds 51.7->93.2
ps2-ratchet-clank: hits 1692->1692 (lost 0 gained 0); invented 6->6 (-0 +0); precision 0.9965->0.9965 pv 0.9993->0.9993; seconds 27.6->31.7
ps2-ratchet-clank-pal: hits 1690->1690 (lost 0 gained 0); invented 8->8 (-0 +0); precision 0.9953->0.9953 pv 0.9986->0.9986; seconds 25.1->31.3
psp-hot-pixel: hits 9091->9117 (lost 1 gained 27); invented 638->32 (-607 +1); precision 0.9344->0.9965 pv 0.9355->0.999; seconds 27.5->76.9 RECALL LOSS
   lost: 0x2532b0
psp-melodie: hits 3214->3214 (lost 0 gained 0); invented 40->27 (-13 +0); precision 0.9877->0.9917 pv 0.9908->0.9949; seconds 5.0->10.1
psp-pac-man-rally: hits 5976->5972 (lost 4 gained 0); invented 208->20 (-188 +0); precision 0.9664->0.9967 pv 0.9658->0.9971; seconds 33.4->64.3 RECALL LOSS
   lost: 0xf2df0 0xf3434 0x10a29c 0x10a2bc
psp-psp-camera-01: hits 6445->6443 (lost 2 gained 0); invented 64->42 (-22 +0); precision 0.9902->0.9935 pv 0.9909->0.9944; seconds 13.9->18.1 RECALL LOSS
   lost: 0x887acd8 0x887acec
psp-tetris: hits 8247->8247 (lost 0 gained 0); invented 87->51 (-37 +1); precision 0.9896->0.9939 pv 0.9894->0.9938; seconds 24.7->34.3
psx-digimon-world: hits 1694->1694 (lost 0 gained 0); invented 0->0 (-0 +0); precision 1.0->1.0 pv 1.0->1.0; seconds 6.1->12.7
psx-legend-of-mana: hits 730->730 (lost 0 gained 0); invented 0->0 (-0 +0); precision 1.0->1.0 pv 1.0->1.0; seconds 2.7->4.5
psx-nfs-high-stakes: hits 1616->1616 (lost 0 gained 0); invented 17->17 (-0 +0); precision 0.9896->0.9896 pv 1.0->1.0; seconds 8.9->8.9
psx-parasite-eve: hits 2186->2186 (lost 0 gained 0); invented 10->9 (-1 +0); precision 0.9954->0.9959 pv 0.9995->1.0; seconds 7.6->5.6
psx-parasite-eve-2: hits 1196->1196 (lost 0 gained 0); invented 57->57 (-0 +0); precision 0.9545->0.9545 pv 0.9542->0.9542; seconds 3.9->3.2
psx-rage-racer: hits 1137->1137 (lost 0 gained 0); invented 6->5 (-1 +0); precision 0.9948->0.9956 pv 0.9948->0.9956; seconds 5.5->5.3
psx-silent-hill: hits 210->210 (lost 0 gained 0); invented 26->26 (-0 +0); precision 0.8898->0.8898 pv 0.9->0.9; seconds 1.5->1.4
psx-vagrant-story: hits 858->858 (lost 0 gained 0); invented 1->1 (-0 +0); precision 0.9988->0.9988 pv 0.9981->0.9981; seconds 3.3->2.0
total {'lost': 11, 'gained': 27, 'removed': 1290, 'added': 2}
```
