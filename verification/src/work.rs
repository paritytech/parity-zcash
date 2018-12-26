use primitives::compact::Compact;
use primitives::hash::H256;
use primitives::bigint::{Uint, U256};
use network::ConsensusParams;
use storage::{BlockHeaderProvider, BlockAncestors};
use timestamp::median_timestamp_inclusive;

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
pub fn work_required(parent_hash: H256, time: u32, height: u32, store: &BlockHeaderProvider, consensus: &ConsensusParams) -> Compact {
	let max_bits = consensus.network.max_bits().into();

	// chain starts with has minimal difficulty
	if height == 0 {
		return max_bits;
	}

	let parent_header = store.block_header(parent_hash.clone().into()).expect("self.height != 0; qed");

	// Special difficulty rule for testnet:
	// If the new block's timestamp is more than 6 * 2.5 minutes
	// then allow mining of a min-difficulty block.
	if let Some(allow_min_difficulty_after_height) = consensus.pow_allow_min_difficulty_after_height {
		if height >= allow_min_difficulty_after_height {
			if time > parent_header.time + consensus.pow_target_spacing * 6 {
				return max_bits;
			}
		}
	}

	// Find the first block in the averaging interval + calculate total difficulty for blocks in the interval
	let (count, oldest_hash, bits_total) = BlockAncestors::new(parent_header.previous_header_hash.into(), store)
		.take(consensus.pow_averaging_window as usize - 1)
		.fold((1, Default::default(), U256::from(parent_header.bits)), |(count, _, bits_total), header|
			(count + 1, header.previous_header_hash, bits_total.overflowing_add(header.bits.into()).0));
	if count != consensus.pow_averaging_window {
		return max_bits;
	}

	let bits_avg = bits_total / consensus.pow_averaging_window.into();
	let parent_mtp = median_timestamp_inclusive(parent_header.hash(), store);
	let oldest_mtp = median_timestamp_inclusive(oldest_hash, store);

	calculate_work_required(bits_avg, parent_mtp, oldest_mtp, consensus, max_bits)
}

fn calculate_work_required(bits_avg: U256, parent_mtp: u32, oldest_mtp: u32, consensus: &ConsensusParams, max_bits: Compact) -> Compact {
	// Limit adjustment step
	// Use medians to prevent time-warp attacks
	let actual_timespan = parent_mtp - oldest_mtp;

	let mut actual_timespan = consensus.averaging_window_timespan() as i64 +
		(actual_timespan as i64 - consensus.averaging_window_timespan() as i64) / 4;

	if actual_timespan < consensus.min_actual_timespan() as i64 {
		actual_timespan = consensus.min_actual_timespan() as i64;
	}
	if actual_timespan > consensus.max_actual_timespan() as i64 {
		actual_timespan = consensus.max_actual_timespan() as i64;
	}

	// Retarget
	let actual_timespan = actual_timespan as u32;
	let mut bits_new = bits_avg / consensus.averaging_window_timespan().into();
	bits_new = bits_new * actual_timespan.into();

	if bits_new > max_bits.into() {
		return max_bits;
	}

	bits_new.into()
}

#[cfg(test)]
mod tests {
	extern crate test_data;

	use std::collections::HashMap;
	use primitives::bytes::Bytes;
	use primitives::compact::Compact;
	use primitives::bigint::U256;
	use primitives::hash::H256;
	use network::{Network, ConsensusParams};
	use chain::BlockHeader;
	use storage::{BlockHeaderProvider, BlockRef};
	use timestamp::median_timestamp_inclusive;
	use super::{work_required, calculate_work_required};

	#[derive(Default)]
	pub struct MemoryBlockHeaderProvider {
		pub by_height: Vec<BlockHeader>,
		pub by_hash: HashMap<H256, usize>,
	}

	impl MemoryBlockHeaderProvider {
		pub fn last(&self) -> &BlockHeader {
			self.by_height.last().unwrap()
		}

		pub fn insert(&mut self, header: BlockHeader) {
			self.by_hash.insert(header.hash(), self.by_height.len());
			self.by_height.push(header);
		}

		pub fn replace_last(&mut self, header: BlockHeader) {
			let idx = self.by_height.len() - 1;
			self.by_hash.remove(&self.by_height[idx].hash());
			self.by_hash.insert(header.hash(), idx);
			self.by_height[idx] = header;
		}

		pub fn next_height(&self) -> u32 {
			self.by_height.len() as u32
		}

		pub fn next_time(&self) -> u32 {
			self.last().time + (self.last().time - self.by_height[self.by_height.len() - 2].time)
		}
	}

	impl BlockHeaderProvider for MemoryBlockHeaderProvider {
		fn block_header_bytes(&self, _block_ref: BlockRef) -> Option<Bytes> {
			unimplemented!()
		}

		fn block_header(&self, block_ref: BlockRef) -> Option<BlockHeader> {
			match block_ref {
				BlockRef::Hash(ref hash) => self.by_hash.get(hash).map(|h| &self.by_height[*h]).cloned(),
				BlockRef::Number(height) => self.by_height.get(height as usize).cloned(),
			}
		}
	}

	#[test]
	fn main_chain_required_work_works() {
		let consensus = ConsensusParams::new(Network::Mainnet);

		// insert genesis block
		let mut header_provider = MemoryBlockHeaderProvider::default();
		let genesis = test_data::genesis().block_header;
		header_provider.insert(genesis.clone());

		// assert block#1 work
		let h1 = test_data::block_h1();
		let expected = h1.block_header.bits;
		let actual = work_required(genesis.hash(), h1.block_header.time, 1, &header_provider, &consensus);
		assert_eq!(expected, actual);
	}

	// original test link:
	// https://github.com/Bitcoin-ABC/bitcoin-abc/blob/d8eac91f8d16716eed0ad11ccac420122280bb13/src/test/pow_tests.cpp#L193
	#[test]
	fn work_required_works() {
		let consensus = ConsensusParams::new(Network::Mainnet);
		let max_bits = Network::Mainnet.max_bits();

		let last_block = 2 * consensus.pow_averaging_window;
		let first_block = last_block - consensus.pow_averaging_window;

		// insert genesis block
		let mut header_provider = MemoryBlockHeaderProvider::default();
		header_provider.insert(BlockHeader {
			time: 1269211443,
			bits: Compact::new(0x1e7fffff),
			version: 0,
			previous_header_hash: 0.into(),
			merkle_root_hash: 0.into(),
			nonce: 0.into(),
			reserved_hash: Default::default(),
			solution: Default::default(),
		});

		// Start with blocks evenly-spaced and equal difficulty
		for i in 1..last_block+1 {
			let header = BlockHeader {
				time: header_provider.last().time + consensus.pow_target_spacing,
				bits: Compact::new(0x1e7fffff),
				version: 0,
				previous_header_hash: header_provider.by_height[i as usize - 1].hash(),
				merkle_root_hash: 0.into(),
				nonce: 0.into(),
				reserved_hash: Default::default(),
				solution: Default::default(),
			};
			header_provider.insert(header);
		}

		// Result should be the same as if last difficulty was used
		let bits_avg: U256 = header_provider.by_height[last_block as usize].bits.into();
		let expected = calculate_work_required(bits_avg,
			median_timestamp_inclusive(header_provider.by_height[last_block as usize].hash(), &header_provider),
			median_timestamp_inclusive(header_provider.by_height[first_block as usize].hash(), &header_provider),
			&consensus, max_bits.into());
		let actual = work_required(header_provider.last().hash(), header_provider.next_time(), header_provider.next_height(),
			&header_provider, &consensus);
		assert_eq!(actual, expected);

		// Result should be unchanged, modulo integer division precision loss
		let mut bits_expected: U256 = Compact::new(0x1e7fffff).into();
		bits_expected = bits_expected / consensus.averaging_window_timespan().into();
		bits_expected = bits_expected * consensus.averaging_window_timespan().into(); 
		assert_eq!(work_required(header_provider.last().hash(), header_provider.next_time(), header_provider.next_height(),
			&header_provider, &consensus),
			bits_expected.into());

		// Randomise the final block time (plus 1 to ensure it is always different)
		use rand::{thread_rng, Rng};
		let mut last_header = header_provider.by_height[last_block as usize].clone();
		last_header.time += thread_rng().gen_range(1, consensus.pow_target_spacing / 2);
		header_provider.replace_last(last_header);

		// Result should be the same as if last difficulty was used
		let bits_avg: U256 = header_provider.by_height[last_block as usize].bits.into();
		let expected = calculate_work_required(bits_avg,
			median_timestamp_inclusive(header_provider.by_height[last_block as usize].hash(), &header_provider),
			median_timestamp_inclusive(header_provider.by_height[first_block as usize].hash(), &header_provider),
			&consensus, max_bits.into());
		let actual = work_required(header_provider.last().hash(), header_provider.next_time(), header_provider.next_height(),
			&header_provider, &consensus);
		assert_eq!(actual, expected);

		// Result should not be unchanged
		let bits_expected = Compact::new(0x1e7fffff);
		assert!(work_required(header_provider.last().hash(), header_provider.next_time(), header_provider.next_height(),
			&header_provider, &consensus) != bits_expected);

		// Change the final block difficulty
		let mut last_header = header_provider.by_height[last_block as usize].clone();
		last_header.bits = Compact::new(0x1e0fffff);
		header_provider.replace_last(last_header);

		// Result should not be the same as if last difficulty was used
		let bits_avg = header_provider.by_height[last_block as usize].bits;
		let expected = calculate_work_required(bits_avg.into(),
			median_timestamp_inclusive(header_provider.by_height[last_block as usize].hash(), &header_provider),
			median_timestamp_inclusive(header_provider.by_height[first_block as usize].hash(), &header_provider),
			&consensus, max_bits.into());
		let actual = work_required(header_provider.last().hash(), header_provider.next_time(), header_provider.next_height(),
			&header_provider, &consensus);
		assert!(actual != expected);

		// Result should be the same as if the average difficulty was used
		let bits_avg = "0000796968696969696969696969696969696969696969696969696969696969".parse().unwrap();
		let expected = calculate_work_required(bits_avg,
			median_timestamp_inclusive(header_provider.by_height[last_block as usize].hash(), &header_provider),
			median_timestamp_inclusive(header_provider.by_height[first_block as usize].hash(), &header_provider),
			&consensus, max_bits.into());
		let actual = work_required(header_provider.last().hash(), header_provider.next_time(), header_provider.next_height(),
			&header_provider, &consensus);
		assert_eq!(actual, expected);
	}
}
