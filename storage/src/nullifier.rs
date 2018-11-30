use hash::H256;

/// Nullifier epoch (tag).
///
/// Sprout and Sapling nullifiers are considered disjoint,
/// even if they have the same bit pattern.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tag {
    Sprout,
    Sapling,
}

/// Nullifier.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Nullifier {
    tag: Tag,
    hash: H256,
}

pub trait NullifierTracker {
    fn contains(&self, nullifier: Nullifier) -> bool;
}

impl Nullifier {
    pub fn new(tag: Tag, hash: H256) -> Self {
        Nullifier {
            tag: tag,
            hash: hash,
        }
    }
}

impl From<(Tag, H256)> for Nullifier {
    fn from(tuple: (Tag, H256)) -> Self {
        Nullifier {
            tag: tuple.0,
            hash: tuple.1,
        }
    }
}