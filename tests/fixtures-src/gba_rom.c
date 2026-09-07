// m5-001 gate fixture: a freestanding ARMv4T image shaped like a Game Boy
// Advance cartridge. No SDK, no BIOS calls: the ROM header fields the loader
// reads are the documented ones (gbatek "Cartridge Header"), and every
// function is ARM-mode so the first slice does not depend on Thumb context.
//
// Built by tests/m5-001_gba.py into an ELF with DWARF (the scoring twin) and
// a raw ROM image (the loader's input). Addresses come from gba_rom.ld.

#define REG_IE   (*(volatile unsigned short *)0x04000200)
#define VRAM     ((volatile unsigned short *)0x06000000)
#define EWRAM    ((volatile unsigned int *)0x02000000)

__attribute__((noinline)) int scale(int value) { return value * 3 + 1; }

__attribute__((noinline)) int clamp(int value, int limit) {
    return value > limit ? limit : value;
}

__attribute__((noinline)) unsigned int checksum(const unsigned char *bytes, unsigned int len) {
    unsigned int sum = 0;
    for (unsigned int i = 0; i < len; ++i) {
        sum = (sum << 1) ^ bytes[i];
    }
    return sum;
}

__attribute__((noinline)) void plot(int x, int y, unsigned short colour) {
    VRAM[y * 240 + x] = colour;
}

__attribute__((noinline)) int frame(int seed) {
    int value = scale(clamp(seed, 200));
    plot(value & 0xff, (value >> 8) & 0x7f, (unsigned short)value);
    return value;
}

// The cartridge entry point: the linker script places this at ROM start, so
// the loader must resolve the branch there rather than assume offset zero is
// the first instruction of a function.
__attribute__((noinline)) void game_main(void) {
    REG_IE = 0;
    unsigned int accumulated = 0;
    for (int tick = 0; tick < 64; ++tick) {
        accumulated += (unsigned int)frame(tick);
    }
    EWRAM[0] = accumulated;
    EWRAM[1] = checksum((const unsigned char *)EWRAM, 4);
    for (;;) {
    }
}
