// m5-004 gate fixture: a freestanding MIPS III image shaped like the game
// code of a Nintendo 64 cartridge. No IPL3 and no SDK: the boot loader's
// code is Nintendo's, so the fixture's ROM carries only the documented
// header fields and this image.
//
// Built by tests/m5-004_n64.py into an ELF with DWARF (the scoring twin) and
// a ROM whose header states where this image runs.

#define VI_ORIGIN (*(volatile unsigned int *)0xA4400004)
#define RDRAM     ((volatile unsigned int *)0x80200000)

__attribute__((noinline)) int scale_up(int value) { return value * 9 + 7; }

__attribute__((noinline)) int pick(int a, int b) { return a > b ? a : b; }

__attribute__((noinline)) void present(unsigned int address) { VI_ORIGIN = address; }

__attribute__((noinline)) int render(int frame) {
    int chosen = pick(scale_up(frame), frame << 3);
    present((unsigned int)chosen);
    return chosen;
}

__attribute__((noinline)) void n64_main(void) {
    int total = 0;
    for (int frame = 0; frame < 30; ++frame) {
        total += render(frame);
    }
    RDRAM[0] = (unsigned int)total;
    for (;;) {
    }
}
