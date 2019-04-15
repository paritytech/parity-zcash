use chain::Transaction;
use storage::TransactionOutputProvider;
use FeeError;

/// Compute miner fee for given transaction.
///
/// Returns None if overflow/underflow happens during computation. Missed prevout
/// is treated as 0-value.
pub fn checked_transaction_fee(store: &TransactionOutputProvider, tx_idx: usize, tx: &Transaction) -> Result<u64, FeeError> {
	// (1) Total sum of all transparent + shielded inputs
	let mut incoming: u64 = 0;
	for (input_idx, input) in tx.inputs.iter().enumerate() {
		let prevout = match store.transaction_output(&input.previous_output, tx_idx) {
			Some(prevout) => prevout,
			None => return Err(FeeError::MissingInput(input_idx)),
		};
		incoming = match incoming.checked_add(prevout.value) {
			Some(incoming) => incoming,
			None => return Err(FeeError::InputsOverflow),
		};
	}

	if let Some(ref join_split) = tx.join_split {
		for js_desc in &join_split.descriptions {
			incoming = match incoming.checked_add(js_desc.value_pub_new) {
				Some(incoming) => incoming,
				None => return Err(FeeError::InputsOverflow),
			};
		}
	}

	if let Some(ref sapling) = tx.sapling {
		if sapling.balancing_value > 0 {
			let balancing_value = sapling.balancing_value as u64;

			incoming = match incoming.checked_add(balancing_value) {
				Some(incoming) => incoming,
				None => return Err(FeeError::InputsOverflow),
			};
		}
	}

	// (2) Total sum of all outputs
	let mut spends = tx.total_spends();

	if let Some(ref join_split) = tx.join_split {
		for js_desc in &join_split.descriptions {
			spends = match spends.checked_add(js_desc.value_pub_old) {
				Some(spends) => spends,
				None => return Err(FeeError::OutputsOverflow),
			};
		}
	}

	if let Some(ref sapling) = tx.sapling {
		if sapling.balancing_value < 0 {
			let balancing_value = match sapling.balancing_value.checked_neg() {
				Some(balancing_value) => balancing_value as u64,
				None => return Err(FeeError::OutputsOverflow),
			};
			
			spends = match spends.checked_add(balancing_value) {
				Some(spends) => spends,
				None => return Err(FeeError::OutputsOverflow),
			};
		}
	}

	// (3) Fee is the difference between (1) and (2)
	match incoming.checked_sub(spends) {
		Some(fee) => Ok(fee),
		None => Err(FeeError::NegativeFee),
	}
}

#[cfg(test)]
mod tests {
	extern crate test_data;

	use std::sync::Arc;
	use storage::AsSubstore;
	use db::BlockChainDatabase;
	use super::*;

	#[test]
	fn test_transaction_fee() {
		let b0 = test_data::block_builder().header().nonce(1.into()).build()
			.transaction()
				.output().value(1_000_000).build()
				.output().value(2_000_000).build()
				.build()
			.build();
		let tx0 = b0.transactions[0].clone();
		let tx0_hash = tx0.hash();
		let b1 = test_data::block_builder().header().parent(b0.hash().clone()).nonce(2.into()).build()
			.transaction()
				.input().hash(tx0_hash.clone()).index(0).build()
				.input().hash(tx0_hash).index(1).build()
				.output().value(2_500_000).build()
				.build()
			.build();
		let tx2 = b1.transactions[0].clone();

		let db = Arc::new(BlockChainDatabase::init_test_chain(vec![b0.into(), b1.into()]));
		let store = db.as_transaction_output_provider();

		assert_eq!(checked_transaction_fee(store, ::std::usize::MAX, &tx0), Err(FeeError::NegativeFee));
		assert_eq!(checked_transaction_fee(store, ::std::usize::MAX, &tx2), Ok(500_000));
	}
}
