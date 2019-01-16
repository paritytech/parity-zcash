use chain::Transaction;
use ser::Serializable;
use storage::{TransactionOutputProvider, DuplexTransactionOutputProvider};
use MemoryPool;

/// Transaction fee calculator for memory pool
pub trait MemoryPoolFeeCalculator {
	/// Compute transaction fee
	fn calculate(&self, memory_pool: &MemoryPool, tx: &Transaction) -> u64;
}

/// Fee calculator that computes sum of real transparent fee + real shielded fee.
pub struct FeeCalculator<'a>(pub &'a TransactionOutputProvider);

impl<'a> MemoryPoolFeeCalculator for FeeCalculator<'a> {
	fn calculate(&self, memory_pool: &MemoryPool, tx: &Transaction) -> u64 {
		let tx_out_provider = DuplexTransactionOutputProvider::new(self.0, memory_pool);
		transaction_fee(&tx_out_provider, tx)
	}
}

/// Used in tests in this && external crates
#[cfg(any(test, feature = "test-helpers"))]
pub struct NonZeroFeeCalculator;

#[cfg(any(test, feature = "test-helpers"))]
impl MemoryPoolFeeCalculator for NonZeroFeeCalculator {
	fn calculate(&self, _: &MemoryPool, tx: &Transaction) -> u64 {
		// add 100_000_000 to make sure tx won't be rejected by txpoool because of fee
		// + but keep ordering by outputs sum
		100_000_000 + tx.outputs.iter().fold(0, |acc, output| acc + output.value)
	}
}

/// Compute miner fee for given transaction.
///
/// It could return a wrong value (that should have overflow/underflow) if either outputs sum,
/// inputs sum or their difference overflows/underflows. But since it is used for prioritizing
/// verified transactions && verification checks that values are correct, the call is safe.
pub fn transaction_fee(store: &TransactionOutputProvider, transaction: &Transaction) -> u64 {
	let mut inputs_sum = transaction.inputs.iter().map(|input|
		store.transaction_output(&input.previous_output, ::std::usize::MAX)
			.expect("transaction must be verified by caller")
			.value)
		.fold(0u64, |acc, value| acc.saturating_add(value));
	if let Some(ref join_split) = transaction.join_split {
		let js_value_pub_new = join_split.descriptions.iter()
			.fold(0u64, |acc, jsd| acc.saturating_add(jsd.value_pub_new));
		inputs_sum = inputs_sum.saturating_add(js_value_pub_new);
	}
	if let Some(ref sapling) = transaction.sapling {
		if sapling.balancing_value > 0 {
			inputs_sum = inputs_sum.saturating_add(sapling.balancing_value as u64);
		}
	}

	let mut outputs_sum = transaction.outputs.iter().map(|output| output.value)
		.fold(0u64, |acc, value| acc.saturating_add(value));
	if let Some(ref join_split) = transaction.join_split {
		let js_value_pub_old = join_split.descriptions.iter()
			.fold(0u64, |acc, jsd| acc.saturating_add(jsd.value_pub_old));
		outputs_sum = outputs_sum.saturating_add(js_value_pub_old);
	}
	if let Some(ref sapling) = transaction.sapling {
		if sapling.balancing_value < 0 {
			inputs_sum = inputs_sum.saturating_add(sapling.balancing_value
				.checked_neg().unwrap_or(::std::i64::MAX) as u64);
		}
	}

	inputs_sum.saturating_sub(outputs_sum)
}

pub fn transaction_fee_rate(store: &TransactionOutputProvider, tx: &Transaction) -> u64 {
	transaction_fee(store, tx) / tx.serialized_size() as u64
}

#[cfg(test)]
mod tests {
	extern crate test_data;

	use std::sync::Arc;
	use storage::{AsSubstore};
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

		assert_eq!(transaction_fee(db.as_transaction_output_provider(), &tx0), 0);
		assert_eq!(transaction_fee(db.as_transaction_output_provider(), &tx2), 500_000);

		assert_eq!(transaction_fee_rate(db.as_transaction_output_provider(), &tx0), 0);
		assert_eq!(transaction_fee_rate(db.as_transaction_output_provider(), &tx2), 4_901);
	}
}
