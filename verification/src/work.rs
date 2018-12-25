use primitives::compact::Compact;
use primitives::hash::H256;
use primitives::bigint::U256;
use chain::IndexedBlockHeader;
use network::ConsensusParams;
use storage::BlockHeaderProvider;
use work_zcash::work_required_zcash;

/// Returns true if hash is lower or equal than target represented by compact bits
pub fn is_valid_proof_of_work_hash(bits: Compact, hash: &H256) -> bool {
	let target = match bits.to_u256() {
		Ok(target) => target,
		_err => return false,
	};

	let value = U256::from(&*hash.reversed() as &[u8]);
	value <= target
}

/// Returns true if hash is lower or equal than target and target is lower or equal
/// than current network maximum
pub fn is_valid_proof_of_work(max_work_bits: Compact, bits: Compact, hash: &H256) -> bool {
	let maximum = match max_work_bits.to_u256() {
		Ok(max) => max,
		_err => return false,
	};

	let target = match bits.to_u256() {
		Ok(target) => target,
		_err => return false,
	};

	let value = U256::from(&*hash.reversed() as &[u8]);
	target <= maximum && value <= target
}

/// Returns work required for given header
pub fn work_required(parent_hash: H256, height: u32, store: &BlockHeaderProvider, consensus: &ConsensusParams) -> Compact {
	let max_bits = consensus.network.max_bits().into();
	if height == 0 {
		return max_bits;
	}

	let parent_header = store.block_header(parent_hash.clone().into()).expect("self.height != 0; qed");

	work_required_zcash(IndexedBlockHeader {
		hash: parent_hash,
		raw: parent_header
	}, store, consensus, max_bits)
}
