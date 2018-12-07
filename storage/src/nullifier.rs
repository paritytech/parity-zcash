use hash::H256;

/// Nullifier epoch (tag).
///
/// Sprout and Sapling nullifiers are considered disjoint,
/// even if they have the same bit pattern.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tag {
    /// Sprout nullifier.
    Sprout,
    /// Sapling nullifier.
    Sapling,
}

/// Nullifier.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Nullifier {
    tag: Tag,
    hash: H256,
}

/// Trait to query existing nullifier.
pub trait NullifierTracker : Sync {
    fn contains_nullifier(&self, nullifier: Nullifier) -> bool;
}

impl Nullifier {
    /// New nullifer.
    pub fn new(tag: Tag, hash: H256) -> Self {
        Nullifier {
            tag: tag,
            hash: hash,
        }
    }

    /// Nullifer tag
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// Nullifer hash
    pub fn hash(&self) -> &H256 {
        &self.hash
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