// m5-002 gate fixture: the ARM7 image of a Nintendo DS cartridge. Loaded at
// ARM7 WRAM 0x037f8000 (gbatek "DS Memory Map"), ARMv4T, no SDK. A separate
// CPU with a separate language is the reason a container yields two programs
// rather than one.

#define REG_SOUNDCNT (*(volatile unsigned short *)0x04000500)
#define IPC_FIFO     (*(volatile unsigned int *)0x04000188)

__attribute__((noinline)) int mix(int left, int right) { return left - right; }

__attribute__((noinline)) unsigned int rotate(unsigned int value, int by) {
    return (value >> by) | (value << (32 - by));
}

__attribute__((noinline)) int sample(int tick) {
    return mix(tick * 7, (int)rotate((unsigned int)tick, 3));
}

__attribute__((noinline)) void arm7_main(void) {
    REG_SOUNDCNT = 0x807f;
    int accumulated = 0;
    for (int tick = 1; tick < 32; ++tick) {
        accumulated += sample(tick);
    }
    IPC_FIFO = (unsigned int)accumulated;
    for (;;) {
    }
}
