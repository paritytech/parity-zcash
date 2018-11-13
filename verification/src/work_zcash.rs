use primitives::compact::Compact;
use primitives::bigint::U256;
use chain::IndexedBlockHeader;
use network::ZCashConsensusParams;
use storage::BlockHeaderProvider;
use timestamp::median_timestamp_inclusive;

/// Returns work required for given header for the ZCash block
pub fn work_required_zcash(parent_header: IndexedBlockHeader, store: &BlockHeaderProvider, fork: &ZCashConsensusParams, max_bits: Compact) -> Compact {
	// Find the first block in the averaging interval
	let parent_hash = parent_header.hash.clone();
	let mut oldest_hash = parent_header.raw.previous_header_hash;
	let mut bits_total: U256 = parent_header.raw.bits.into();
	for _ in 1..fork.pow_averaging_window {
		let previous_header = match store.block_header(oldest_hash.into()) {
			Some(previous_header) => previous_header,
			None => return max_bits,
		};

		bits_total = bits_total + previous_header.bits.into();
		oldest_hash = previous_header.previous_header_hash;
	}

	let bits_avg = bits_total / fork.pow_averaging_window.into();
	let parent_mtp = median_timestamp_inclusive(parent_hash, store);
	let oldest_mtp = median_timestamp_inclusive(oldest_hash, store);

	calculate_work_required(bits_avg, parent_mtp, oldest_mtp, fork, max_bits)
}

fn calculate_work_required(bits_avg: U256, parent_mtp: u32, oldest_mtp: u32, fork: &ZCashConsensusParams, max_bits: Compact) -> Compact {
	// Limit adjustment step
	// Use medians to prevent time-warp attacks
	let actual_timespan = parent_mtp - oldest_mtp;

	let mut actual_timespan = fork.averaging_window_timespan() as i64 +
		(actual_timespan as i64 - fork.averaging_window_timespan() as i64) / 4;

	if actual_timespan < fork.min_actual_timespan() as i64 {
		actual_timespan = fork.min_actual_timespan() as i64;
	}
	if actual_timespan > fork.max_actual_timespan() as i64 {
		actual_timespan = fork.max_actual_timespan() as i64;
	}

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
	use primitives::compact::Compact;
	use primitives::bigint::U256;
	use network::{Network, ZCashConsensusParams, ConsensusFork};
	use chain::BlockHeader;
	use timestamp::median_timestamp_inclusive;
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
			reserved_hash: Default::default(),
			solution: Default::default(),
		});

		// Start with blocks evenly-spaced and equal difficulty
		for i in 1..last_block+1 {
			let header = BlockHeader {
				time: header_provider.last().time + fork.pow_target_spacing,
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
			&fork, max_bits.into());
		let actual = work_required_zcash(header_provider.last().clone().into(),
			&header_provider, &fork, max_bits.into());
		assert_eq!(actual, expected);

		// Result should be unchanged, modulo integer division precision loss
		let mut bits_expected: U256 = Compact::new(0x1e7fffff).into();
		bits_expected = bits_expected / fork.averaging_window_timespan().into();
		bits_expected = bits_expected * fork.averaging_window_timespan().into(); 
		assert_eq!(work_required_zcash(header_provider.last().clone().into(),
			&header_provider, &fork, max_bits.into()),
			bits_expected.into());

		// Randomise the final block time (plus 1 to ensure it is always different)
		use rand::{thread_rng, Rng};
		let mut last_header = header_provider.by_height[last_block as usize].clone();
		last_header.time += thread_rng().gen_range(1, fork.pow_target_spacing / 2);
		header_provider.replace_last(last_header);

		// Result should be the same as if last difficulty was used
		let bits_avg: U256 = header_provider.by_height[last_block as usize].bits.into();
		let expected = calculate_work_required(bits_avg,
			median_timestamp_inclusive(header_provider.by_height[last_block as usize].hash(), &header_provider),
			median_timestamp_inclusive(header_provider.by_height[first_block as usize].hash(), &header_provider),
			&fork, max_bits.into());
		let actual = work_required_zcash(header_provider.last().clone().into(),
			&header_provider, &fork, max_bits.into());
		assert_eq!(actual, expected);

		// Result should not be unchanged
		let bits_expected = Compact::new(0x1e7fffff);
		assert!(work_required_zcash(header_provider.last().clone().into(),
			&header_provider, &fork, max_bits.into()) != bits_expected);

		// Change the final block difficulty
		let mut last_header = header_provider.by_height[last_block as usize].clone();
		last_header.bits = Compact::new(0x1e0fffff);
		header_provider.replace_last(last_header);

		// Result should not be the same as if last difficulty was used
		let bits_avg = header_provider.by_height[last_block as usize].bits;
		let expected = calculate_work_required(bits_avg.into(),
			median_timestamp_inclusive(header_provider.by_height[last_block as usize].hash(), &header_provider),
			median_timestamp_inclusive(header_provider.by_height[first_block as usize].hash(), &header_provider),
			&fork, max_bits.into());
		let actual = work_required_zcash(header_provider.last().clone().into(),
			&header_provider, &fork, max_bits.into());
		assert!(actual != expected);

		// Result should be the same as if the average difficulty was used
		let bits_avg = "0000796968696969696969696969696969696969696969696969696969696969".parse().unwrap();
		let expected = calculate_work_required(bits_avg,
			median_timestamp_inclusive(header_provider.by_height[last_block as usize].hash(), &header_provider),
			median_timestamp_inclusive(header_provider.by_height[first_block as usize].hash(), &header_provider),
			&fork, max_bits.into());
		let actual = work_required_zcash(header_provider.last().clone().into(),
			&header_provider, &fork, max_bits.into());
		assert_eq!(actual, expected);
	}
}