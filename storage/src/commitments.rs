use EpochTag;
use hash::H256;

/// Trait to query sequence of blockchain commitments;
pub trait CommitmentProvider : Sync {
	/// Total amount of stored commitments
	fn commitments_count(&self, tag: EpochTag) -> u64;
	/// Commitment at given position
	fn commitment_at(&self, tag: EpochTag, index: u64) -> H256;
	/// Root of all stored commitments
	fn commitments_merkle_root(&self, tag: EpochTag) -> H256;
}
