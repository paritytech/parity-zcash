use EpochRef;

/// Trait to query existing nullifier.
pub trait NullifierTracker : Sync {
	fn contains_nullifier(&self, nullifier: EpochRef) -> bool;
}
