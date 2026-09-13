use std::env;
fn main() {
    let path = env::args().nth(1).unwrap();
    let data = std::fs::read(path).unwrap();
    for ins in romwright_core::vu::disassemble(&data, 0, data.len()/4) {
        println!("{} {}", ins.mnemonic, ins.operands);
    }
}
