// Dump RSP disassembly of a bin file, one "mnemonic operands" per line.
use std::env;
fn main() {
    let path = env::args().nth(1).unwrap();
    let data = std::fs::read(path).unwrap();
    for ins in romwright_core::rsp::disassemble(&data, 0x80000000, data.len()/4) {
        println!("{} {}", ins.mnemonic, ins.operands);
    }
}
