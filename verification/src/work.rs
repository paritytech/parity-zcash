use std::cmp;
use primitives::compact::Compact;
use primitives::hash::H256;
use primitives::bigint::U256;
use chain::{IndexedBlockHeader, BlockHeader};
use network::{Network, ConsensusParams};
use storage::{BlockHeaderProvider, BlockRef};
use work_zcash::work_required_zcash;

use constants::{
	DOUBLE_SPACING_SECONDS, TARGET_TIMESPAN_SECONDS,
	MIN_TIMESPAN, MAX_TIMESPAN, RETARGETING_INTERVAL
};

pub fn is_retarget_height(height: u32) -> bool {
	height % RETARGETING_INTERVAL == 0
}

fn range_constrain(value: i64, min: i64, max: i64) -> i64 {
	cmp::min(cmp::max(value, min), max)
}

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

/// Returns constrained number of seconds since last retarget
pub fn retarget_timespan(retarget_timestamp: u32, last_timestamp: u32) -> u32 {
	// subtract unsigned 32 bit numbers in signed 64 bit space in
	// order to prevent underflow before applying the range constraint.
	let timespan = last_timestamp as i64 - retarget_timestamp as i64;
	range_constrain(timespan, MIN_TIMESPAN as i64, MAX_TIMESPAN as i64) as u32
}

/// Returns work required for given header
pub fn work_required(parent_hash: H256, time: u32, height: u32, store: &BlockHeaderProvider, consensus: &ConsensusParams) -> Compact {
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

pub fn block_reward_satoshi(block_height: u32) -> u64 {
	let mut res = 50 * 100 * 1000 * 1000;
	for _ in 0..block_height / 210000 { res /= 2 }
	res
}

#[cfg(test)]
mod tests {
	use primitives::hash::H256;
	use primitives::compact::Compact;
	use network::{Network};
	use super::{is_valid_proof_of_work_hash, is_valid_proof_of_work, block_reward_satoshi};

	fn is_valid_pow(max: Compact, bits: u32, hash: &'static str) -> bool {
		is_valid_proof_of_work_hash(bits.into(), &H256::from_reversed_str(hash)) &&
		is_valid_proof_of_work(max.into(), bits.into(), &H256::from_reversed_str(hash))
	}

	#[test]
	fn reward() {
		assert_eq!(block_reward_satoshi(0), 5000000000);
		assert_eq!(block_reward_satoshi(209999), 5000000000);
		assert_eq!(block_reward_satoshi(210000), 2500000000);
		assert_eq!(block_reward_satoshi(420000), 1250000000);
		assert_eq!(block_reward_satoshi(420001), 1250000000);
		assert_eq!(block_reward_satoshi(629999), 1250000000);
		assert_eq!(block_reward_satoshi(630000), 625000000);
		assert_eq!(block_reward_satoshi(630001), 625000000);
	}
}
