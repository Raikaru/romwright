//! Single owner of navigation state: current program, current address, and
//! the back/forward history (Qt `NavigationController`). Panels never talk
//! to each other; the shell turns every change here into a broadcast.

use romwright_model::Address;

#[derive(Debug, Default)]
pub struct Navigation {
    address: Option<Address>,
    history: Vec<Address>,
    index: Option<usize>,
}

impl Navigation {
    /// A program switch clears the cursor and the whole history: addresses
    /// from another image are not places in this one.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Jumps to an address. With `record` false (traversal, wheel scrolling)
    /// the history is untouched; recording truncates the forward branch and
    /// appends, collapsing consecutive duplicates.
    pub fn go_to(&mut self, address: Address, record: bool) {
        if record {
            let keep = self.index.map_or(0, |index| index + 1);
            self.history.truncate(keep);
            if self.history.last() != Some(&address) {
                self.history.push(address.clone());
            }
            self.index = self.history.len().checked_sub(1);
        }
        self.address = Some(address);
    }

    pub fn address(&self) -> Option<&Address> {
        self.address.as_ref()
    }

    pub fn can_back(&self) -> bool {
        self.index.is_some_and(|index| index > 0)
    }

    pub fn can_forward(&self) -> bool {
        self.index
            .is_some_and(|index| index + 1 < self.history.len())
    }

    /// Steps back; returns the new address when there was somewhere to go.
    pub fn back(&mut self) -> Option<Address> {
        let index = self.index.filter(|index| *index > 0)? - 1;
        self.index = Some(index);
        self.address = Some(self.history[index].clone());
        self.address.clone()
    }

    pub fn forward(&mut self) -> Option<Address> {
        let index = self.index? + 1;
        let address = self.history.get(index)?.clone();
        self.index = Some(index);
        self.address = Some(address);
        self.address.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_truncates_forward_branch_and_collapses_duplicates() {
        let mut nav = Navigation::default();
        assert!(!nav.can_back() && !nav.can_forward());
        nav.go_to(Address::ram(1), true);
        nav.go_to(Address::ram(1), true);
        nav.go_to(Address::ram(2), true);
        nav.go_to(Address::ram(3), true);
        assert_eq!(nav.back(), Some(Address::ram(2)));
        assert_eq!(nav.back(), Some(Address::ram(1)));
        assert_eq!(nav.back(), None);
        assert!(nav.can_forward());
        nav.go_to(Address::ram(9), false);
        assert!(nav.can_forward(), "unrecorded jumps keep history");
        assert_eq!(nav.forward(), Some(Address::ram(2)));
        nav.go_to(Address::ram(7), true);
        assert!(!nav.can_forward());
        assert_eq!(nav.back(), Some(Address::ram(2)));
        nav.reset();
        assert_eq!(nav.address(), None);
    }
}
