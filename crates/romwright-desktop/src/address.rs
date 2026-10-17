//! Address text at the UI edge: what the analyst types and what panels show.
//!
//! The Qt frontend passed hex strings between docks; here every panel holds a
//! typed [`Address`] and only these two functions touch text.

use romwright_model::{Address, AddressSpace};

/// Display form shared by every panel: `0x401000` for RAM, `ext::0x10` for the
/// external space, `<space>::0x..` for any other space (Qt `addressText`).
pub fn format(address: &Address) -> String {
    match &address.space {
        AddressSpace::Ram => format!("0x{:x}", address.offset),
        AddressSpace::External => format!("ext::0x{:x}", address.offset),
        AddressSpace::Other(space) => format!("{space}::0x{:x}", address.offset),
    }
}

/// Parses what an analyst types into the address field: `401000`, `0x401000`,
/// `ram:00401000`, `ext::0x10` or `<space>::0x..`. Empty or non-hex text is
/// `None`; register names are never read as addresses.
pub fn parse(text: &str) -> Option<Address> {
    let text = text.trim();
    let (space, offset) = match text.split_once("::") {
        Some(("ext", offset)) => (AddressSpace::External, offset),
        Some(("ram", offset)) => (AddressSpace::Ram, offset),
        Some((space, offset)) if !space.is_empty() => (AddressSpace::Other(space.to_string()), offset),
        Some(_) => return None,
        None => (AddressSpace::Ram, text.strip_prefix("ram:").unwrap_or(text)),
    };
    let digits = offset
        .strip_prefix("0x")
        .or_else(|| offset.strip_prefix("0X"))
        .unwrap_or(offset);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, 16)
        .ok()
        .map(|offset| Address { space, offset })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typed_forms_and_round_trips_display() {
        assert_eq!(parse("401000"), Some(Address::ram(0x401000)));
        assert_eq!(parse(" 0x401000 "), Some(Address::ram(0x401000)));
        assert_eq!(parse("ram:00401000"), Some(Address::ram(0x401000)));
        let external = parse("ext::0x10").unwrap();
        assert_eq!(external.space, AddressSpace::External);
        assert_eq!(format(&external), "ext::0x10");
        assert_eq!(format(&Address::ram(0x401000)), "0x401000");
        for bad in ["", "rax", "0x", "::10", "12g"] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }
}
