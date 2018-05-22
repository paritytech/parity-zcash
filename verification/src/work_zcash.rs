use primitives::compact::Compact;
use primitives::hash::H256;
use primitives::bigint::{Uint, U256};
use chain::{IndexedBlockHeader, BlockHeader};
use network::{Network, ConsensusParams, ZCashConsensusParams};
use storage::BlockHeaderProvider;
use timestamp::median_timestamp_inclusive;
use work::{is_retarget_height, work_required_testnet, work_required_retarget};

/// Returns work required for given header for the ZCash block
pub fn work_required_zcash(parent_header: IndexedBlockHeader, time: u32, height: u32, store: &BlockHeaderProvider, fork: &ZCashConsensusParams, max_bits: Compact) -> Compact {
	// Find the first block in the averaging interval
	let mut oldest_hash = parent_header.hash.clone();
	let mut bits_total: U256 = parent_header.raw.bits.into();
	for i in 1..fork.pow_averaging_window {
		let block_number = match height.checked_sub(i + 1) {
			Some(block_number) => block_number,
			None => {
println!("=== XXX");
				return max_bits
			},
		};

		let previous_header = store.block_header(block_number.into()).expect("block_number > 0 && block_number < height; qed");
		bits_total = bits_total + previous_header.bits.into();
		oldest_hash = previous_header.hash();
	}
println!("=== bits_total = {:?}", Compact::from_u256(bits_total));
	let bits_avg = bits_total / fork.pow_averaging_window.into();
	let parent_mtp = median_timestamp_inclusive(parent_header.hash.clone(), store);
	let oldest_mtp = median_timestamp_inclusive(oldest_hash, store);
	calculate_work_required(bits_avg, parent_mtp, oldest_mtp, fork, max_bits)
}

fn calculate_work_required(bits_avg: U256, parent_mtp: u32, oldest_mtp: u32, fork: &ZCashConsensusParams, max_bits: Compact) -> Compact {
	// Limit adjustment step
	// Use medians to prevent time-warp attacks
	let actual_timespan = parent_mtp - oldest_mtp;
println!("=== parent_mtp: {}", parent_mtp);
println!("=== oldest_mtp: {}", oldest_mtp);
println!("=== actual_timespan_0: {}", actual_timespan);
	let mut actual_timespan = fork.averaging_window_timespan() as i64 +
		(actual_timespan as i64 - fork.averaging_window_timespan() as i64) / 4;
println!("=== actual_timespan_1: {}", actual_timespan);
	if actual_timespan < fork.min_actual_timespan() as i64 {
		actual_timespan = fork.min_actual_timespan() as i64;
	}
	if actual_timespan > fork.max_actual_timespan() as i64 {
		actual_timespan = fork.max_actual_timespan() as i64;
	}
println!("=== actual_timespan_2: {}", actual_timespan);
	// Retarget
	let actual_timespan = actual_timespan as u32;
	let mut bits_new = bits_avg / fork.averaging_window_timespan().into();
	bits_new = bits_new * actual_timespan.into();

	if bits_new > max_bits.into() {
		return max_bits;
	}

	bits_new.into()
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;
	use primitives::bytes::Bytes;
	use primitives::compact::Compact;
	use primitives::hash::H256;
	use primitives::bigint::U256;
	use network::{Network, ZCashConsensusParams, ConsensusFork};
	use storage::{BlockHeaderProvider, BlockRef};
	use chain::BlockHeader;
	use timestamp::median_timestamp_inclusive;
	use work::work_required;
	use work_bch::tests::MemoryBlockHeaderProvider;
	use super::{work_required_zcash, calculate_work_required};

	// original test link:
	// https://github.com/Bitcoin-ABC/bitcoin-abc/blob/d8eac91f8d16716eed0ad11ccac420122280bb13/src/test/pow_tests.cpp#L193
	#[test]
	fn zcash_work_required_works() {
		let fork = ZCashConsensusParams::new(Network::Mainnet);
		let max_bits = Network::Mainnet.max_bits(&ConsensusFork::ZCash(fork.clone()));

		let last_block = 2 * fork.pow_averaging_window;
		let first_block = last_block - fork.pow_averaging_window;

		// insert genesis block
		let mut header_provider = MemoryBlockHeaderProvider::default();
		header_provider.insert(BlockHeader {
			time: 1269211443,
			bits: Compact::new(0x1e7fffff),
			version: 0,
			previous_header_hash: 0.into(),
			merkle_root_hash: 0.into(),
			nonce: 0.into(),
			hash_final_sapling_root: None,
			equihash_solution: None,
		});

		// Start with blocks evenly-spaced and equal difficulty
		for i in 1..last_block+1 {
			let header = BlockHeader {
				time: header_provider.last().time + fork.pow_target_spacing,
				bits: Compact::new(0x1e7fffff),
				version: 0,
				previous_header_hash: 0.into(),
				merkle_root_hash: 0.into(),
				nonce: 0.into(),
				hash_final_sapling_root: None,
				equihash_solution: None,
			};
			header_provider.insert(header);
		}

		// Result should be unchanged, modulo integer division precision loss
		let mut expected: U256 = Compact::new(0x1e7fffff).into();
		expected = expected / fork.averaging_window_timespan().into();
		expected = expected * fork.averaging_window_timespan().into();
		let actual = work_required_zcash(header_provider.last().clone().into(),
			0, header_provider.by_height.len() as u32, &header_provider, &fork, max_bits.into());
		assert_eq!(actual, expected.into());

		// Result should be the same as if last difficulty was used
		let bits_avg: U256 = header_provider.by_height[last_block as usize].bits.into();
		let expected = calculate_work_required(bits_avg,
			median_timestamp_inclusive(header_provider.by_height[last_block as usize].hash(), &header_provider),
			median_timestamp_inclusive(header_provider.by_height[first_block as usize].hash(), &header_provider),
			&fork, max_bits.into());
		let actual = work_required_zcash(header_provider.last().clone().into(),
			0, header_provider.by_height.len() as u32, &header_provider, &fork, max_bits.into());
		assert_eq!(actual, expected);

/*
		// Result should be unchanged, modulo integer division precision loss
		let mut bits_expected: U256 = Compact::new(0x1e7fffff).into();
		bits_expected = bits_expected / fork.averaging_window_timespan().into();
		bits_expected = bits_expected * fork.averaging_window_timespan().into(); 
		assert_eq!(calculate_work_required(bits_expected,
			median_timestamp_inclusive(header_provider.by_height[last_block as usize].hash(), &header_provider),
			median_timestamp_inclusive(header_provider.by_height[first_block as usize].hash(), &header_provider),
			&fork, max_bits.into()), bits_expected.into());

		// Randomise the final block time (plus 1 to ensure it is always different)
		use std::rand::{task_rng, Rng};
		header_provider.by_height[last_block].time += task_rng().gen_range(1, fork.pow_target_spacing / 2);

		// Result should be the same as if last difficulty was used
		bits_expected = header_provider.by_height[last_block].bits;
		assert_eq!(calculate_work_required(bits_expected,
			median_timestamp_inclusive(header_provider.by_height[last_block as usize].hash(), &header_provider),
			median_timestamp_inclusive(header_provider.by_height[first_block as usize].hash(), &header_provider),
			&fork, max_bits.into()), bits_expected.into());

    // Result should be the same as if last difficulty was used
    bnAvg.SetCompact(blocks[lastBlk].nBits);
    EXPECT_EQ(CalculateNextWorkRequired(bnAvg,
                                        blocks[lastBlk].GetMedianTimePast(),
                                        blocks[firstBlk].GetMedianTimePast(),
                                        params),
              GetNextWorkRequired(&blocks[lastBlk], nullptr, params));
    // Result should not be unchanged
    EXPECT_NE(0x1e7fffff, GetNextWorkRequired(&blocks[lastBlk], nullptr, params));*/
	}
}