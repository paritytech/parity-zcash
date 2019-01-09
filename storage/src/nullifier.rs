use hash::H256;
use EpochTag;

/// Nullifier.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Nullifier {
	tag: EpochTag,
	hash: H256,
}

/// Trait to query existing nullifier.
pub trait NullifierTracker : Sync {
	fn contains_nullifier(&self, nullifier: Nullifier) -> bool;
}

impl Nullifier {
	/// New nullifer.
	pub fn new(tag: EpochTag, hash: H256) -> Self {
		Nullifier {
			tag: tag,
			hash: hash,
		}
	}

	/// Nullifer tag
	pub fn tag(&self) -> EpochTag {
		self.tag
	}

	/// Nullifer hash
	pub fn hash(&self) -> &H256 {
		&self.hash
	}
}

impl From<(EpochTag, H256)> for Nullifier {
	fn from(tuple: (EpochTag, H256)) -> Self {
		Nullifier {
			tag: tuple.0,
			hash: tuple.1,
		}
	}
}