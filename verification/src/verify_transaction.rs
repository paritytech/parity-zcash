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
}

impl<'a> TransactionVerifier<'a> {
	pub fn new(transaction: &'a IndexedTransaction) -> Self {
		trace!(target: "verification", "Tx pre-verification {}", transaction.hash.to_reversed_str());
		TransactionVerifier {
			version: TransactionVersion::new(transaction),
			empty: TransactionEmpty::new(transaction),
			null_non_coinbase: TransactionNullNonCoinbase::new(transaction),
			oversized_coinbase: TransactionOversizedCoinbase::new(transaction, MIN_COINBASE_SIZE..MAX_COINBASE_SIZE),
			joint_split_in_coinbase: TransactionJointSplitInCoinbase::new(transaction),
		}
	}

	pub fn check(&self) -> Result<(), TransactionError> {
		self.version.check()?;
		self.empty.check()?;
		self.null_non_coinbase.check()?;
		self.oversized_coinbase.check()?;
		self.joint_split_in_coinbase.check()?;
		Ok(())
	}
}

pub struct MemoryPoolTransactionVerifier<'a> {
	pub empty: TransactionEmpty<'a>,
	pub null_non_coinbase: TransactionNullNonCoinbase<'a>,
	pub is_coinbase: TransactionMemoryPoolCoinbase<'a>,
	pub size: TransactionSize<'a>,
	pub sigops: TransactionSigops<'a>,
}

impl<'a> MemoryPoolTransactionVerifier<'a> {
	pub fn new(transaction: &'a IndexedTransaction, consensus: &'a ConsensusParams) -> Self {
		trace!(target: "verification", "Mempool-Tx pre-verification {}", transaction.hash.to_reversed_str());
		MemoryPoolTransactionVerifier {
			empty: TransactionEmpty::new(transaction),
			null_non_coinbase: TransactionNullNonCoinbase::new(transaction),
			is_coinbase: TransactionMemoryPoolCoinbase::new(transaction),
			size: TransactionSize::new(transaction, consensus),
			sigops: TransactionSigops::new(transaction, consensus.max_block_sigops()),
		}
	}

	pub fn check(&self) -> Result<(), TransactionError> {
		try!(self.empty.check());
		try!(self.null_non_coinbase.check());
		try!(self.is_coinbase.check());
		try!(self.size.check());
		try!(self.sigops.check());
		Ok(())
	}
}

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
		if self.transaction.raw.is_empty() {
			Err(TransactionError::Empty)
		} else {
			Ok(())
		}
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

pub struct TransactionSize<'a> {
	transaction: &'a IndexedTransaction,
	consensus: &'a ConsensusParams,
}

impl<'a> TransactionSize<'a> {
	fn new(transaction: &'a IndexedTransaction, consensus: &'a ConsensusParams) -> Self {
		TransactionSize {
			transaction: transaction,
			consensus: consensus,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		let size = self.transaction.raw.serialized_size();
		if size > self.consensus.max_transaction_size() {
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

#[cfg(test)]
mod tests {
	use chain::{Transaction, OutPoint, TransactionInput, IndexedTransaction};
	use error::TransactionError;
	use super::{TransactionVersion, TransactionJointSplitInCoinbase};

	#[test]
	fn transaction_version_works() {
		let tx0: IndexedTransaction = Transaction::default().into();
		assert_eq!(TransactionVersion::new(&tx0).check(), Err(TransactionError::InvalidVersion));

		let tx1: IndexedTransaction = Transaction {
			version: 1,
			..Default::default()
		}.into();
		assert_eq!(TransactionVersion::new(&tx1).check(), Ok(()));
	}

	#[test]
	fn transaction_joint_split_in_coinbase_works() {
		let coinbase_with_joint_split: IndexedTransaction = Transaction {
			inputs: vec![TransactionInput {
				previous_output: OutPoint::null(),
				..Default::default()
			}],
			joint_split: Some(Default::default()),
			..Default::default()
		}.into();
		assert_eq!(
			TransactionJointSplitInCoinbase::new(&coinbase_with_joint_split).check(),
			Err(TransactionError::CoinbaseWithJointSplit)
		);

		let coinbase_without_joint_split: IndexedTransaction = Transaction {
			inputs: vec![Default::default()],
			..Default::default()
		}.into();
		assert_eq!(
			TransactionJointSplitInCoinbase::new(&coinbase_without_joint_split).check(),
			Ok(())
		);

		let non_coinbase_with_joint_split: IndexedTransaction = Transaction {
			joint_split: Some(Default::default()),
			..Default::default()
		}.into();
		assert_eq!(
			TransactionJointSplitInCoinbase::new(&non_coinbase_with_joint_split).check(),
			Ok(())
		);

		let non_coinbase_without_joint_split: IndexedTransaction = Transaction {
			..Default::default()
		}.into();
		assert_eq!(
			TransactionJointSplitInCoinbase::new(&non_coinbase_without_joint_split).check(),
			Ok(())
		);
	}
}