use std::ops;
use ser::Serializable;
use chain::IndexedTransaction;
use network::{ConsensusParams};
use duplex_store::NoopStore;
use sigops::transaction_sigops;
use error::TransactionError;
use constants::{MIN_COINBASE_SIZE, MAX_COINBASE_SIZE};

pub struct TransactionVerifier<'a> {
	pub version: TransactionVersion<'a>,
	pub empty: TransactionEmpty<'a>,
	pub null_non_coinbase: TransactionNullNonCoinbase<'a>,
	pub oversized_coinbase: TransactionOversizedCoinbase<'a>,
	pub joint_split_in_coinbase: TransactionJointSplitInCoinbase<'a>,
	pub size: TransactionAbsoluteSize<'a>,
	pub value_overflow: TransactionValueOverflow<'a>,
}

impl<'a> TransactionVerifier<'a> {
	pub fn new(transaction: &'a IndexedTransaction, consensus: &'a ConsensusParams) -> Self {
		trace!(target: "verification", "Tx pre-verification {}", transaction.hash.to_reversed_str());
		TransactionVerifier {
			version: TransactionVersion::new(transaction),
			empty: TransactionEmpty::new(transaction),
			null_non_coinbase: TransactionNullNonCoinbase::new(transaction),
			oversized_coinbase: TransactionOversizedCoinbase::new(transaction, MIN_COINBASE_SIZE..MAX_COINBASE_SIZE),
			joint_split_in_coinbase: TransactionJointSplitInCoinbase::new(transaction),
			size: TransactionAbsoluteSize::new(transaction, consensus),
			value_overflow: TransactionValueOverflow::new(transaction, consensus),
		}
	}

	pub fn check(&self) -> Result<(), TransactionError> {
		self.version.check()?;
		self.empty.check()?;
		self.null_non_coinbase.check()?;
		self.oversized_coinbase.check()?;
		self.joint_split_in_coinbase.check()?;
		self.size.check()?;
		self.value_overflow.check()?;
		Ok(())
	}
}

pub struct MemoryPoolTransactionVerifier<'a> {
	pub empty: TransactionEmpty<'a>,
	pub null_non_coinbase: TransactionNullNonCoinbase<'a>,
	pub is_coinbase: TransactionMemoryPoolCoinbase<'a>,
	pub size: TransactionAbsoluteSize<'a>,
	pub sigops: TransactionSigops<'a>,
	pub value_overflow: TransactionValueOverflow<'a>,
}

impl<'a> MemoryPoolTransactionVerifier<'a> {
	pub fn new(transaction: &'a IndexedTransaction, consensus: &'a ConsensusParams) -> Self {
		trace!(target: "verification", "Mempool-Tx pre-verification {}", transaction.hash.to_reversed_str());
		MemoryPoolTransactionVerifier {
			empty: TransactionEmpty::new(transaction),
			null_non_coinbase: TransactionNullNonCoinbase::new(transaction),
			is_coinbase: TransactionMemoryPoolCoinbase::new(transaction),
			size: TransactionAbsoluteSize::new(transaction, consensus),
			sigops: TransactionSigops::new(transaction, consensus.max_block_sigops()),
			value_overflow: TransactionValueOverflow::new(transaction, consensus),
		}
	}

	pub fn check(&self) -> Result<(), TransactionError> {
		self.empty.check()?;
		self.null_non_coinbase.check()?;
		self.is_coinbase.check()?;
		self.size.check()?;
		self.sigops.check()?;
		self.value_overflow.check()?;
		Ok(())
	}
}

/// If version == 1 or nJointSplit == 0, then tx_in_count MUST NOT be 0.
/// Transactions containing empty `vin` must have either non-empty `vjoinsplit` or non-empty `vShieldedSpend`.
/// Transactions containing empty `vout` must have either non-empty `vjoinsplit` or non-empty `vShieldedOutput`.
pub struct TransactionEmpty<'a> {
	transaction: &'a IndexedTransaction,
}

impl<'a> TransactionEmpty<'a> {
	fn new(transaction: &'a IndexedTransaction) -> Self {
		TransactionEmpty {
			transaction: transaction,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		// If version == 1 or nJointSplit == 0, then tx_in_count MUST NOT be 0.
		if self.transaction.raw.version == 1 || self.transaction.raw.joint_split.is_none() {
			if self.transaction.raw.inputs.is_empty() {
				return Err(TransactionError::Empty);
			}
		}

		// Transactions containing empty `vin` must have either non-empty `vjoinsplit`.
		// Transactions containing empty `vout` must have either non-empty `vjoinsplit`.
		// TODO [Sapling]: ... or non-empty `vShieldedOutput`
		if self.transaction.raw.is_empty() {
			if self.transaction.raw.joint_split.is_none() {
				return Err(TransactionError::Empty);
			}
		}

		Ok(())
	}
}

pub struct TransactionNullNonCoinbase<'a> {
	transaction: &'a IndexedTransaction,
}

impl<'a> TransactionNullNonCoinbase<'a> {
	fn new(transaction: &'a IndexedTransaction) -> Self {
		TransactionNullNonCoinbase {
			transaction: transaction,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		if !self.transaction.raw.is_coinbase() && self.transaction.raw.is_null() {
			Err(TransactionError::NullNonCoinbase)
		} else {
			Ok(())
		}
	}
}

pub struct TransactionOversizedCoinbase<'a> {
	transaction: &'a IndexedTransaction,
	size_range: ops::Range<usize>,
}

impl<'a> TransactionOversizedCoinbase<'a> {
	fn new(transaction: &'a IndexedTransaction, size_range: ops::Range<usize>) -> Self {
		TransactionOversizedCoinbase {
			transaction: transaction,
			size_range: size_range,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		if self.transaction.raw.is_coinbase() {
			let script_len = self.transaction.raw.inputs[0].script_sig.len();
			if script_len < self.size_range.start || script_len > self.size_range.end {
				return Err(TransactionError::CoinbaseSignatureLength(script_len));
			}
		}

		Ok(())
	}
}

pub struct TransactionMemoryPoolCoinbase<'a> {
	transaction: &'a IndexedTransaction,
}
impl<'a> TransactionMemoryPoolCoinbase<'a> {
	fn new(transaction: &'a IndexedTransaction) -> Self {
		TransactionMemoryPoolCoinbase {
			transaction: transaction,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		if self.transaction.raw.is_coinbase() {
			Err(TransactionError::MemoryPoolCoinbase)
		} else {
			Ok(())
		}
	}
}

/// The encoded size of the transaction MUST be less than or equal to EVER possible max limit.
pub struct TransactionAbsoluteSize<'a> {
	transaction: &'a IndexedTransaction,
	absoute_max_size: usize,
}

impl<'a> TransactionAbsoluteSize<'a> {
	fn new(transaction: &'a IndexedTransaction, consensus: &'a ConsensusParams) -> Self {
		TransactionAbsoluteSize {
			transaction: transaction,
			absoute_max_size: consensus.absolute_max_transaction_size(),
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		let size = self.transaction.raw.serialized_size();
		if size > self.absoute_max_size {
			Err(TransactionError::MaxSize)
		} else {
			Ok(())
		}
	}
}

pub struct TransactionSigops<'a> {
	transaction: &'a IndexedTransaction,
	max_sigops: usize,
}

impl<'a> TransactionSigops<'a> {
	fn new(transaction: &'a IndexedTransaction, max_sigops: usize) -> Self {
		TransactionSigops {
			transaction: transaction,
			max_sigops: max_sigops,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		let sigops = transaction_sigops(&self.transaction.raw, &NoopStore, false, false);
		if sigops > self.max_sigops {
			Err(TransactionError::MaxSigops)
		} else {
			Ok(())
		}
	}
}

/// The transaction version number MUST be greater than or equal to 1.
pub struct TransactionVersion<'a> {
	transaction: &'a IndexedTransaction,
}

impl<'a> TransactionVersion<'a> {
	fn new(transaction: &'a IndexedTransaction) -> Self {
		TransactionVersion {
			transaction,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		if self.transaction.raw.version < 1 {
			return Err(TransactionError::InvalidVersion);
		}

		Ok(())
	}
}

/// A coinbase transaction MUST NOT have any JoinSplit descriptions.
pub struct TransactionJointSplitInCoinbase<'a> {
	transaction: &'a IndexedTransaction,
}

impl<'a> TransactionJointSplitInCoinbase<'a> {
	fn new(transaction: &'a IndexedTransaction) -> Self {
		TransactionJointSplitInCoinbase {
			transaction,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		if self.transaction.raw.is_coinbase() && self.transaction.raw.joint_split.is_some() {
			return Err(TransactionError::CoinbaseWithJointSplit);
		}

		Ok(())
	}
}

/// Check for overflow of output values.
pub struct TransactionValueOverflow<'a> {
	transaction: &'a IndexedTransaction,
	max_value: u64,
}

impl<'a> TransactionValueOverflow<'a> {
	fn new(transaction: &'a IndexedTransaction, consensus: &'a ConsensusParams) -> Self {
		TransactionValueOverflow {
			transaction,
			max_value: consensus.max_transaction_value(),
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		let mut total_output = 0u64;
		for output in &self.transaction.raw.outputs {
			if output.value > self.max_value {
				return Err(TransactionError::ValueOverflow)
			}

			total_output = match total_output.checked_add(output.value) {
				Some(total_output) if total_output <= self.max_value => total_output,
				_ => return Err(TransactionError::ValueOverflow),
			};
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	extern crate test_data;

	use network::{Network, ConsensusParams};
	use error::TransactionError;
	use super::{TransactionEmpty, TransactionVersion, TransactionJointSplitInCoinbase, TransactionValueOverflow};

	#[test]
	fn transaction_empty_works() {
		assert_eq!(TransactionEmpty::new(&test_data::TransactionBuilder::with_version(1)
			.add_output(0)
			.add_default_joint_split()
			.into()).check(), Err(TransactionError::Empty));

		assert_eq!(TransactionEmpty::new(&test_data::TransactionBuilder::with_version(2)
			.add_output(0)
			.into()).check(), Err(TransactionError::Empty));

		assert_eq!(TransactionEmpty::new(&test_data::TransactionBuilder::with_version(2)
			.add_output(0)
			.add_default_joint_split()
			.into()).check(), Ok(()));

		assert_eq!(TransactionEmpty::new(&test_data::TransactionBuilder::with_version(2)
			.into()).check(), Err(TransactionError::Empty));
	}

	#[test]
	fn transaction_version_works() {
		assert_eq!(TransactionVersion::new(&test_data::TransactionBuilder::with_version(0)
			.into()).check(), Err(TransactionError::InvalidVersion));

		assert_eq!(TransactionVersion::new(&test_data::TransactionBuilder::with_version(1)
			.into()).check(), Ok(()));
	}

	#[test]
	fn transaction_joint_split_in_coinbase_works() {
		assert_eq!(TransactionJointSplitInCoinbase::new(&test_data::TransactionBuilder::coinbase()
			.add_default_joint_split().into()).check(), Err(TransactionError::CoinbaseWithJointSplit));

		assert_eq!(TransactionJointSplitInCoinbase::new(&test_data::TransactionBuilder::coinbase()
			.into()).check(), Ok(()));

		assert_eq!(TransactionJointSplitInCoinbase::new(&test_data::TransactionBuilder::default()
			.add_default_joint_split().into()).check(), Ok(()));

		assert_eq!(TransactionJointSplitInCoinbase::new(&test_data::TransactionBuilder::default()
			.into()).check(), Ok(()));
	}

	#[test]
	fn transaction_value_overflow_works() {
		let consensus = ConsensusParams::new(Network::Mainnet);

		assert_eq!(TransactionValueOverflow::new(&test_data::TransactionBuilder::with_output(consensus.max_transaction_value() + 1)
			.into(), &consensus).check(), Err(TransactionError::ValueOverflow));

		assert_eq!(TransactionValueOverflow::new(&test_data::TransactionBuilder::with_output(consensus.max_transaction_value() / 2)
			.add_output(consensus.max_transaction_value() / 2 + 1)
			.into(), &consensus).check(), Err(TransactionError::ValueOverflow));

		assert_eq!(TransactionValueOverflow::new(&test_data::TransactionBuilder::with_output(consensus.max_transaction_value())
			.into(), &consensus).check(), Ok(()));
	}
}
