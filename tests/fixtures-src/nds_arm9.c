// m5-002 gate fixture: the ARM9 image of a Nintendo DS cartridge. Loaded at
// main RAM 0x02000000 (gbatek "DS Memory Map"), ARMv5TE, no SDK.
//
// Built by tests/m5-002_nds.py into an ELF with DWARF (the scoring twin) and
// a raw image the container carries.

#define REG_DISPCNT (*(volatile unsigned int *)0x04000000)
#define VRAM_A      ((volatile unsigned short *)0x06800000)

__attribute__((noinline)) int blend(int a, int b) { return (a + b) >> 1; }

__attribute__((noinline)) int saturate(int value) {
    if (value < 0) {
        return 0;
    }
    return value > 255 ? 255 : value;
}

__attribute__((noinline)) void write_pixel(int index, unsigned short colour) {
    VRAM_A[index] = colour;
}

__attribute__((noinline)) int shade(int row, int column) {
    int mixed = blend(row * 3, column * 5);
    write_pixel(row * 256 + column, (unsigned short)saturate(mixed));
    return mixed;
}

__attribute__((noinline)) void arm9_main(void) {
    REG_DISPCNT = 0x10000;
    int total = 0;
    for (int row = 0; row < 24; ++row) {
        total += shade(row, row + 1);
    }
    *(volatile int *)0x02100000 = total;
    for (;;) {
    }
}
