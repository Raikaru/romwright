// m5-003 gate fixture: a freestanding MIPS R3000A image shaped like a
// PlayStation executable. No BIOS calls and no SDK: the header fields the
// loader reads are the documented ones (psx-spx "Executables"), and the code
// only touches main RAM and the GPU register window.
//
// Built by tests/m5-003_psx.py into an ELF with DWARF (the scoring twin) and
// a raw image wrapped in a 2 KiB PS-EXE header.

#define GP0        (*(volatile unsigned int *)0x1F801810)
#define WORK_RAM   ((volatile unsigned int *)0x80100000)

__attribute__((noinline)) int step(int value) { return value * 5 - 3; }

__attribute__((noinline)) int fold(int a, int b) {
    int mixed = a ^ b;
    return mixed < 0 ? -mixed : mixed;
}

__attribute__((noinline)) void submit(unsigned int command) { GP0 = command; }

__attribute__((noinline)) int frame(int tick) {
    int value = fold(step(tick), tick << 2);
    submit((unsigned int)value);
    return value;
}

__attribute__((noinline)) void psx_main(void) {
    int total = 0;
    for (int tick = 0; tick < 60; ++tick) {
        total += frame(tick);
    }
    WORK_RAM[0] = (unsigned int)total;
    for (;;) {
    }
}
