use std::{collections::HashMap, ops};
use ser::Serializable;
use chain::{IndexedTransaction, BTC_TX_VERSION, OVERWINTER_TX_VERSION,
	OVERWINTER_TX_VERSION_GROUP_ID, SAPLING_TX_VERSION_GROUP_ID};
use network::{ConsensusParams};
use storage::NoopStore;
use sigops::transaction_sigops;
use error::TransactionError;
use constants::{MIN_COINBASE_SIZE, MAX_COINBASE_SIZE};

pub struct TransactionVerifier<'a> {
	pub version: TransactionVersion<'a>,
	pub expiry: TransactionExpiry<'a>,
	pub empty: TransactionEmpty<'a>,
	pub null_non_coinbase: TransactionNullNonCoinbase<'a>,
	pub oversized_coinbase: TransactionOversizedCoinbase<'a>,
	pub non_transparent_coinbase: TransactionNonTransparentCoinbase<'a>,
	pub size: TransactionAbsoluteSize<'a>,
	pub sapling: TransactionSapling<'a>,
	pub join_split: TransactionJoinSplit<'a>,
	pub output_value_overflow: TransactionOutputValueOverflow<'a>,
	pub input_value_overflow: TransactionInputValueOverflow<'a>,
	pub duplicate_inputs: TransactionDuplicateInputs<'a>,
	pub duplicate_join_split_nullifiers: TransactionDuplicateJoinSplitNullifiers<'a>,
	pub duplicate_sapling_nullifiers: TransactionDuplicateSaplingNullifiers<'a>,
}

impl<'a> TransactionVerifier<'a> {
	pub fn new(transaction: &'a IndexedTransaction, consensus: &'a ConsensusParams) -> Self {
		trace!(target: "verification", "Tx pre-verification {}", transaction.hash.to_reversed_str());
		TransactionVerifier {
			version: TransactionVersion::new(transaction),
			expiry: TransactionExpiry::new(transaction, consensus),
			empty: TransactionEmpty::new(transaction),
			null_non_coinbase: TransactionNullNonCoinbase::new(transaction),
			oversized_coinbase: TransactionOversizedCoinbase::new(transaction, MIN_COINBASE_SIZE..MAX_COINBASE_SIZE),
			non_transparent_coinbase: TransactionNonTransparentCoinbase::new(transaction),
			size: TransactionAbsoluteSize::new(transaction, consensus),
			sapling: TransactionSapling::new(transaction),
			join_split: TransactionJoinSplit::new(transaction),
			output_value_overflow: TransactionOutputValueOverflow::new(transaction, consensus),
			input_value_overflow: TransactionInputValueOverflow::new(transaction, consensus),
			duplicate_inputs: TransactionDuplicateInputs::new(transaction),
			duplicate_join_split_nullifiers: TransactionDuplicateJoinSplitNullifiers::new(transaction),
			duplicate_sapling_nullifiers: TransactionDuplicateSaplingNullifiers::new(transaction),
		}
	}

	pub fn check(&self) -> Result<(), TransactionError> {
		self.version.check()?;
		self.expiry.check()?;
		self.empty.check()?;
		self.null_non_coinbase.check()?;
		self.oversized_coinbase.check()?;
		self.non_transparent_coinbase.check()?;
		self.size.check()?;
		self.sapling.check()?;
		self.join_split.check()?;
		self.output_value_overflow.check()?;
		self.input_value_overflow.check()?;
		self.duplicate_inputs.check()?;
		self.duplicate_join_split_nullifiers.check()?;
		self.duplicate_sapling_nullifiers.check()?;
		Ok(())
	}
}

pub struct MemoryPoolTransactionVerifier<'a> {
	pub version: TransactionVersion<'a>,
	pub expiry: TransactionExpiry<'a>,
	pub empty: TransactionEmpty<'a>,
	pub null_non_coinbase: TransactionNullNonCoinbase<'a>,
	pub is_coinbase: TransactionMemoryPoolCoinbase<'a>,
	pub size: TransactionAbsoluteSize<'a>,
	pub sigops: TransactionSigops<'a>,
	pub sapling: TransactionSapling<'a>,
	pub join_split: TransactionJoinSplit<'a>,
	pub output_value_overflow: TransactionOutputValueOverflow<'a>,
	pub input_value_overflow: TransactionInputValueOverflow<'a>,
	pub duplicate_inputs: TransactionDuplicateInputs<'a>,
	pub duplicate_join_split_nullifiers: TransactionDuplicateJoinSplitNullifiers<'a>,
	pub duplicate_sapling_nullifiers: TransactionDuplicateSaplingNullifiers<'a>,
}

impl<'a> MemoryPoolTransactionVerifier<'a> {
	pub fn new(transaction: &'a IndexedTransaction, consensus: &'a ConsensusParams) -> Self {
		trace!(target: "verification", "Mempool-Tx pre-verification {}", transaction.hash.to_reversed_str());
		MemoryPoolTransactionVerifier {
			version: TransactionVersion::new(transaction),
			expiry: TransactionExpiry::new(transaction, consensus),
			empty: TransactionEmpty::new(transaction),
			null_non_coinbase: TransactionNullNonCoinbase::new(transaction),
			is_coinbase: TransactionMemoryPoolCoinbase::new(transaction),
			size: TransactionAbsoluteSize::new(transaction, consensus),
			sigops: TransactionSigops::new(transaction, consensus.max_block_sigops()),
			sapling: TransactionSapling::new(transaction),
			join_split: TransactionJoinSplit::new(transaction),
			output_value_overflow: TransactionOutputValueOverflow::new(transaction, consensus),
			input_value_overflow: TransactionInputValueOverflow::new(transaction, consensus),
			duplicate_inputs: TransactionDuplicateInputs::new(transaction),
			duplicate_join_split_nullifiers: TransactionDuplicateJoinSplitNullifiers::new(transaction),
			duplicate_sapling_nullifiers: TransactionDuplicateSaplingNullifiers::new(transaction),
		}
	}

	pub fn check(&self) -> Result<(), TransactionError> {
		self.version.check()?;
		self.expiry.check()?;
		self.empty.check()?;
		self.null_non_coinbase.check()?;
		self.is_coinbase.check()?;
		self.size.check()?;
		self.sigops.check()?;
		self.sapling.check()?;
		self.join_split.check()?;
		self.output_value_overflow.check()?;
		self.input_value_overflow.check()?;
		self.duplicate_inputs.check()?;
		self.duplicate_join_split_nullifiers.check()?;
		self.duplicate_sapling_nullifiers.check()?;
		Ok(())
	}
}

/// If version == 1 or nJoinSplit == 0, then tx_in_count MUST NOT be 0.
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
		// Transactions containing empty `vin` must have either non-empty `vjoinsplit` or non-empty `vShieldedSpend`.
		if self.transaction.raw.inputs.is_empty() {
			let is_empty_join_split = self.transaction.raw.join_split.is_none();
			let is_empty_shielded_spends = self.transaction.raw.sapling.as_ref().map(|s| s.spends.is_empty()).unwrap_or(true);
			if is_empty_join_split && is_empty_shielded_spends {
				return Err(TransactionError::Empty);
			}
		}

		// Transactions containing empty `vout` must have either non-empty `vjoinsplit` or non-empty `vShieldedOutput`.
		if self.transaction.raw.outputs.is_empty() {
			let is_empty_join_split = self.transaction.raw.join_split.is_none();
			let is_empty_shielded_outputs = self.transaction.raw.sapling.as_ref().map(|s| s.outputs.is_empty()).unwrap_or(true);
			if is_empty_join_split && is_empty_shielded_outputs {
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
		match self.transaction.raw.overwintered {
			true => self.check_overwintered(),
			false => self.check_non_overwintered(),
		}
	}

	fn check_overwintered(&self) -> Result<(), TransactionError> {
		if self.transaction.raw.version < OVERWINTER_TX_VERSION {
			return Err(TransactionError::InvalidVersion);
		}

		let is_overwinter_group = self.transaction.raw.version_group_id == OVERWINTER_TX_VERSION_GROUP_ID;
		let is_sapling_group = self.transaction.raw.version_group_id == SAPLING_TX_VERSION_GROUP_ID;
		if !is_overwinter_group && !is_sapling_group {
			return Err(TransactionError::InvalidVersionGroup);
		}

		Ok(())
	}

	fn check_non_overwintered(&self) -> Result<(), TransactionError> {
		if self.transaction.raw.version < BTC_TX_VERSION {
			return Err(TransactionError::InvalidVersion);
		}

		Ok(())
	}
}

/// A coinbase transaction MUST NOT have any JoinSplit descriptions.
/// A coinbase transaction cannot have spend descriptions or output descriptions.
pub struct TransactionNonTransparentCoinbase<'a> {
	transaction: &'a IndexedTransaction,
}

impl<'a> TransactionNonTransparentCoinbase<'a> {
	fn new(transaction: &'a IndexedTransaction) -> Self {
		TransactionNonTransparentCoinbase {
			transaction,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		if self.transaction.raw.is_coinbase() {
			if self.transaction.raw.join_split.is_some() {
				return Err(TransactionError::NonTransparentCoinbase);
			}
			if let Some(ref sapling) = self.transaction.raw.sapling {
				if !sapling.spends.is_empty() || !sapling.outputs.is_empty() {
					return Err(TransactionError::NonTransparentCoinbase);
				}
			}
		}

		Ok(())
	}
}

/// Check that transaction sapling is well-formed.
pub struct TransactionSapling<'a> {
	transaction: &'a IndexedTransaction,
}

impl<'a> TransactionSapling<'a> {
	fn new(transaction: &'a IndexedTransaction) -> Self {
		TransactionSapling {
			transaction,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		if let Some(ref sapling) = self.transaction.raw.sapling {
			// sapling balance should be zero if spends and outputs are empty
			if sapling.balancing_value != 0 && sapling.spends.is_empty() && sapling.outputs.is_empty() {
				return Err(TransactionError::EmptySaplingHasBalance);
			}
		}

		Ok(())
	}
}


/// Check that transaction join split is well-formed.
pub struct TransactionJoinSplit<'a> {
	transaction: &'a IndexedTransaction,
}

impl<'a> TransactionJoinSplit<'a> {
	fn new(transaction: &'a IndexedTransaction) -> Self {
		TransactionJoinSplit {
			transaction,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		if let Some(ref join_split) = self.transaction.raw.join_split {
			if self.transaction.raw.version == 1 {
				return Err(TransactionError::JoinSplitVersionInvalid);
			}

			for desc in &join_split.descriptions {
				if desc.value_pub_old != 0 && desc.value_pub_new != 0 {
					return Err(TransactionError::JoinSplitBothPubsNonZero)
				}
			}
		}

		Ok(())
	}
}

/// Check for overflow of output values.
pub struct TransactionOutputValueOverflow<'a> {
	transaction: &'a IndexedTransaction,
	max_value: i64,
}

impl<'a> TransactionOutputValueOverflow<'a> {
	fn new(transaction: &'a IndexedTransaction, consensus: &'a ConsensusParams) -> Self {
		TransactionOutputValueOverflow {
			transaction,
			max_value: consensus.max_transaction_value(),
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		let mut total_output = 0i64;

		// each output should be less than max_value
		// the sum of all outputs should be less than max value
		for output in &self.transaction.raw.outputs {
			if output.value > self.max_value as u64 {
				return Err(TransactionError::OutputValueOverflow)
			}

			total_output = match total_output.checked_add(output.value as i64) {
				Some(total_output) if total_output <= self.max_value => total_output,
				_ => return Err(TransactionError::OutputValueOverflow),
			};
		}

		if let Some(ref sapling) = self.transaction.raw.sapling {
			// check that sapling amount is within limits
			if sapling.balancing_value < -self.max_value || sapling.balancing_value > self.max_value {
				return Err(TransactionError::OutputValueOverflow);
			}

			// negative sapling amount takes value from transparent pool
			if sapling.balancing_value < 0 {
				total_output = match total_output.checked_add(-sapling.balancing_value) {
					Some(total_output) if total_output <= self.max_value => total_output,
					_ => return Err(TransactionError::OutputValueOverflow),
				};
			}
		}

		if let Some(ref join_split) = self.transaction.raw.join_split {
			for desc in &join_split.descriptions {
				if desc.value_pub_old > self.max_value as u64 {
					return Err(TransactionError::OutputValueOverflow);
				}

				if desc.value_pub_new > self.max_value as u64 {
					return Err(TransactionError::OutputValueOverflow);
				}

				total_output = match total_output.checked_add(desc.value_pub_old as i64) {
					Some(total_output) if total_output <= self.max_value => total_output,
					_ => return Err(TransactionError::OutputValueOverflow),
				};
			}
		}

		Ok(())
	}
}

/// Check for overflow of (known) input values.
pub struct TransactionInputValueOverflow<'a> {
	transaction: &'a IndexedTransaction,
	max_value: u64,
}

impl<'a> TransactionInputValueOverflow<'a> {
	fn new(transaction: &'a IndexedTransaction, consensus: &'a ConsensusParams) -> Self {
		TransactionInputValueOverflow {
			transaction,
			max_value: consensus.max_transaction_value() as u64,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		let mut total_input = 0u64;

		// inputs values are unknown at verification stage

		// every value_pub_new should be within money range
		// their sum should be within money range
		if let Some(ref join_split) = self.transaction.raw.join_split {
			for desc in &join_split.descriptions {
				if desc.value_pub_new > self.max_value {
					return Err(TransactionError::InputValueOverflow);
				}

				total_input = match total_input.checked_add(desc.value_pub_new) {
					Some(total_input) if total_input <= self.max_value => total_input,
					_ => return Err(TransactionError::InputValueOverflow),
				};
			}
		}

		if let Some(ref sapling) = self.transaction.raw.sapling {
			// positive sapling amount adds value to the transparent pool
			if sapling.balancing_value > 0 {
				match total_input.checked_add(sapling.balancing_value as u64) {
					Some(total_input) if total_input <= self.max_value => (),
					_ => return Err(TransactionError::InputValueOverflow),
				};
			}
		}

		Ok(())
	}
}

/// Check that transaction expiry height is too high.
pub struct TransactionExpiry<'a> {
	transaction: &'a IndexedTransaction,
	height_threshold: u32,
}

impl<'a> TransactionExpiry<'a> {
	fn new(transaction: &'a IndexedTransaction, consensus: &'a ConsensusParams) -> Self {
		TransactionExpiry {
			transaction,
			height_threshold: consensus.transaction_expiry_height_threshold(),
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		if self.transaction.raw.overwintered && self.transaction.raw.expiry_height >= self.height_threshold {
			return Err(TransactionError::ExpiryHeightTooHigh);
		}

		Ok(())
	}
}

/// Check that transaction doesn't have duplicate inputs.
pub struct TransactionDuplicateInputs<'a> {
	transaction: &'a IndexedTransaction,
}

impl<'a> TransactionDuplicateInputs<'a> {
	fn new(transaction: &'a IndexedTransaction) -> Self {
		TransactionDuplicateInputs {
			transaction,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		let mut inputs = HashMap::new();
		for (idx, input) in self.transaction.raw.inputs.iter().enumerate() {
			if let Some(old_idx) = inputs.insert(&input.previous_output, idx) {
				return Err(TransactionError::DuplicateInput(old_idx, idx));
			}
		}

		Ok(())
	}
}

/// Check that transaction doesn't have duplicate JoinSplit nullifiers.
pub struct TransactionDuplicateJoinSplitNullifiers<'a> {
	transaction: &'a IndexedTransaction,
}

impl<'a> TransactionDuplicateJoinSplitNullifiers<'a> {
	fn new(transaction: &'a IndexedTransaction) -> Self {
		TransactionDuplicateJoinSplitNullifiers {
			transaction,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		if let Some(join_split) = self.transaction.raw.join_split.as_ref() {
			let mut nullifiers = HashMap::new();
			for (idx, description) in join_split.descriptions.iter().enumerate() {
				if let Some(old_idx) = nullifiers.insert(&description.nullifiers[0], idx) {
					return Err(TransactionError::DuplicateJoinSplitNullifier(old_idx, idx));
				}
				if let Some(old_idx) = nullifiers.insert(&description.nullifiers[1], idx) {
					return Err(TransactionError::DuplicateJoinSplitNullifier(old_idx, idx));
				}
			}
		}

		Ok(())
	}
}

/// Check that transaction doesn't have duplicate Sapling nullifiers.
pub struct TransactionDuplicateSaplingNullifiers<'a> {
	transaction: &'a IndexedTransaction,
}

impl<'a> TransactionDuplicateSaplingNullifiers<'a> {
	fn new(transaction: &'a IndexedTransaction) -> Self {
		TransactionDuplicateSaplingNullifiers {
			transaction,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		if let Some(sapling) = self.transaction.raw.sapling.as_ref() {
			let mut nullifiers = HashMap::new();
			for (idx, spend) in sapling.spends.iter().enumerate() {
				if let Some(old_idx) = nullifiers.insert(&spend.nullifier, idx) {
					return Err(TransactionError::DuplicateSaplingSpendNullifier(old_idx, idx));
				}
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	extern crate test_data;

	use chain::{BTC_TX_VERSION, OVERWINTER_TX_VERSION, OVERWINTER_TX_VERSION_GROUP_ID,
		SAPLING_TX_VERSION_GROUP_ID, Sapling, JoinSplit, JoinSplitDescription};
	use network::{Network, ConsensusParams};
	use error::TransactionError;
	use super::{TransactionEmpty, TransactionVersion, TransactionNonTransparentCoinbase,
		TransactionOutputValueOverflow, TransactionExpiry, TransactionSapling, TransactionJoinSplit,
		TransactionInputValueOverflow, TransactionDuplicateInputs, TransactionDuplicateJoinSplitNullifiers,
		TransactionDuplicateSaplingNullifiers};

	#[test]
	fn transaction_empty_works() {
		// empty inputs

		assert_eq!(TransactionEmpty::new(&test_data::TransactionBuilder::with_version(2)
			.add_output(0)
			.into()).check(), Err(TransactionError::Empty));

		assert_eq!(TransactionEmpty::new(&test_data::TransactionBuilder::with_version(2)
			.add_output(0)
			.add_default_join_split()
			.into()).check(), Ok(()));

		assert_eq!(TransactionEmpty::new(&test_data::TransactionBuilder::with_version(2)
			.add_output(0)
			.set_sapling(Sapling { spends: vec![Default::default()], ..Default::default() })
			.into()).check(), Ok(()));

		// empty outputs

		assert_eq!(TransactionEmpty::new(&test_data::TransactionBuilder::with_version(2)
			.add_default_input(0)
			.into()).check(), Err(TransactionError::Empty));

		assert_eq!(TransactionEmpty::new(&test_data::TransactionBuilder::with_version(2)
			.add_default_input(0)
			.add_default_join_split()
			.into()).check(), Ok(()));

		assert_eq!(TransactionEmpty::new(&test_data::TransactionBuilder::with_version(2)
			.add_default_input(0)
			.set_sapling(Sapling { outputs: vec![Default::default()], ..Default::default() })
			.into()).check(), Ok(()));
	}

	#[test]
	fn transaction_version_works() {
		assert_eq!(TransactionVersion::new(&test_data::TransactionBuilder::with_version(0)
			.into()).check(), Err(TransactionError::InvalidVersion));

		assert_eq!(TransactionVersion::new(&test_data::TransactionBuilder::with_version(BTC_TX_VERSION)
			.into()).check(), Ok(()));

		assert_eq!(TransactionVersion::new(&test_data::TransactionBuilder::overwintered()
			.set_version(BTC_TX_VERSION).into()).check(), Err(TransactionError::InvalidVersion));

		assert_eq!(TransactionVersion::new(&test_data::TransactionBuilder::overwintered()
			.set_version(OVERWINTER_TX_VERSION).into()).check(), Err(TransactionError::InvalidVersionGroup));

		assert_eq!(TransactionVersion::new(&test_data::TransactionBuilder::overwintered()
			.set_version(OVERWINTER_TX_VERSION).set_version_group_id(OVERWINTER_TX_VERSION_GROUP_ID).into()).check(),
			Ok(()));

		assert_eq!(TransactionVersion::new(&test_data::TransactionBuilder::overwintered()
			.set_version(OVERWINTER_TX_VERSION).set_version_group_id(SAPLING_TX_VERSION_GROUP_ID).into()).check(),
			Ok(()));
	}

	#[test]
	fn transaction_non_transparent_coinbase_works() {
		assert_eq!(TransactionNonTransparentCoinbase::new(&test_data::TransactionBuilder::coinbase()
			.add_default_join_split().into()).check(), Err(TransactionError::NonTransparentCoinbase));

		assert_eq!(TransactionNonTransparentCoinbase::new(&test_data::TransactionBuilder::coinbase()
			.set_sapling(Sapling { spends: vec![Default::default()], ..Default::default() }).into()).check(),
			Err(TransactionError::NonTransparentCoinbase));

		assert_eq!(TransactionNonTransparentCoinbase::new(&test_data::TransactionBuilder::coinbase()
			.set_sapling(Sapling { outputs: vec![Default::default()], ..Default::default() }).into()).check(),
			Err(TransactionError::NonTransparentCoinbase));

		assert_eq!(TransactionNonTransparentCoinbase::new(&test_data::TransactionBuilder::coinbase()
			.set_sapling(Default::default()).into()).check(),
			Ok(()));

		assert_eq!(TransactionNonTransparentCoinbase::new(&test_data::TransactionBuilder::coinbase()
			.into()).check(), Ok(()));

		assert_eq!(TransactionNonTransparentCoinbase::new(&test_data::TransactionBuilder::default()
			.add_default_join_split().into()).check(), Ok(()));

		assert_eq!(TransactionNonTransparentCoinbase::new(&test_data::TransactionBuilder::default()
			.into()).check(), Ok(()));
	}

	#[test]
	fn transaction_output_value_overflow_works() {
		let consensus = ConsensusParams::new(Network::Mainnet);
		let max_value = consensus.max_transaction_value();

		assert_eq!(TransactionOutputValueOverflow::new(&test_data::TransactionBuilder::with_output(max_value as u64 + 1)
			.into(), &consensus).check(), Err(TransactionError::OutputValueOverflow));

		assert_eq!(TransactionOutputValueOverflow::new(&test_data::TransactionBuilder::with_output(max_value as u64 / 2)
			.add_output(max_value as u64 / 2 + 1)
			.into(), &consensus).check(), Err(TransactionError::OutputValueOverflow));

		assert_eq!(TransactionOutputValueOverflow::new(&test_data::TransactionBuilder::with_output(max_value as u64)
			.into(), &consensus).check(), Ok(()));

		assert_eq!(TransactionOutputValueOverflow::new(&test_data::TransactionBuilder::with_sapling(Sapling {
				balancing_value: max_value,
				..Default::default()
			}).into(), &consensus).check(), Ok(()));

		assert_eq!(TransactionOutputValueOverflow::new(&test_data::TransactionBuilder::with_sapling(Sapling {
				balancing_value: max_value + 1,
				..Default::default()
			}).into(), &consensus).check(), Err(TransactionError::OutputValueOverflow));

		assert_eq!(TransactionOutputValueOverflow::new(&test_data::TransactionBuilder::with_output(max_value as u64 / 2 + 1)
			.set_sapling(Sapling {
				balancing_value: -max_value / 2,
				..Default::default()
			}).into(), &consensus).check(), Err(TransactionError::OutputValueOverflow));

		assert_eq!(TransactionOutputValueOverflow::new(&test_data::TransactionBuilder::with_join_split(JoinSplit {
				descriptions: vec![JoinSplitDescription {
					value_pub_old: max_value as u64,
					value_pub_new: 0,
					..Default::default()
				}],
				..Default::default()
			}).into(), &consensus).check(), Ok(()));

		assert_eq!(TransactionOutputValueOverflow::new(&test_data::TransactionBuilder::with_join_split(JoinSplit {
				descriptions: vec![JoinSplitDescription {
					value_pub_old: max_value as u64 + 1,
					value_pub_new: 0,
					..Default::default()
				}],
				..Default::default()
			}).into(), &consensus).check(), Err(TransactionError::OutputValueOverflow));

		assert_eq!(TransactionOutputValueOverflow::new(&test_data::TransactionBuilder::with_join_split(JoinSplit {
				descriptions: vec![JoinSplitDescription {
					value_pub_old: 0,
					value_pub_new: max_value as u64,
					..Default::default()
				}],
				..Default::default()
			}).into(), &consensus).check(), Ok(()));

		assert_eq!(TransactionOutputValueOverflow::new(&test_data::TransactionBuilder::with_join_split(JoinSplit {
				descriptions: vec![JoinSplitDescription {
					value_pub_old: 0,
					value_pub_new: max_value as u64 + 1,
					..Default::default()
				}],
				..Default::default()
			}).into(), &consensus).check(), Err(TransactionError::OutputValueOverflow));

		assert_eq!(TransactionOutputValueOverflow::new(&test_data::TransactionBuilder::with_output(max_value as u64 / 2 + 1)
			.set_join_split(JoinSplit {
				descriptions: vec![JoinSplitDescription {
					value_pub_old: max_value as u64 / 2,
					value_pub_new: 0,
					..Default::default()
				}],
				..Default::default()
			}).into(), &consensus).check(), Err(TransactionError::OutputValueOverflow));
	}

	#[test]
	fn transaction_input_value_overflow_works() {
		let consensus = ConsensusParams::new(Network::Mainnet);
		let max_value = consensus.max_transaction_value();

		assert_eq!(TransactionInputValueOverflow::new(&test_data::TransactionBuilder::with_join_split(JoinSplit {
				descriptions: vec![JoinSplitDescription {
					value_pub_new: max_value as u64,
					..Default::default()
				}],
				..Default::default()
			}).into(), &consensus).check(), Ok(()));

		assert_eq!(TransactionInputValueOverflow::new(&test_data::TransactionBuilder::with_join_split(JoinSplit {
				descriptions: vec![JoinSplitDescription {
					value_pub_new: max_value as u64 + 1,
					..Default::default()
				}],
				..Default::default()
			}).into(), &consensus).check(), Err(TransactionError::InputValueOverflow));

		assert_eq!(TransactionInputValueOverflow::new(&test_data::TransactionBuilder::with_sapling(Sapling {
				balancing_value: max_value,
				..Default::default()
			}).into(), &consensus).check(), Ok(()));

		assert_eq!(TransactionInputValueOverflow::new(&test_data::TransactionBuilder::with_sapling(Sapling {
				balancing_value: max_value + 1,
				..Default::default()
			}).into(), &consensus).check(), Err(TransactionError::InputValueOverflow));

		assert_eq!(TransactionInputValueOverflow::new(&test_data::TransactionBuilder::with_join_split(JoinSplit {
				descriptions: vec![JoinSplitDescription {
					value_pub_new: max_value as u64 / 2 + 1,
					..Default::default()
				}],
				..Default::default()
			}).set_sapling(Sapling {
				balancing_value: max_value / 2,
				..Default::default()
			}).into(), &consensus).check(), Err(TransactionError::InputValueOverflow));
	}

	#[test]
	fn transaction_expiry_works() {
		let consensus = ConsensusParams::new(Network::Mainnet);

		assert_eq!(TransactionExpiry::new(&test_data::TransactionBuilder::overwintered()
			.set_expiry_height(consensus.transaction_expiry_height_threshold() - 1).into(), &consensus).check(),
			Ok(()));

		assert_eq!(TransactionExpiry::new(&test_data::TransactionBuilder::overwintered()
			.set_expiry_height(consensus.transaction_expiry_height_threshold()).into(), &consensus).check(),
			Err(TransactionError::ExpiryHeightTooHigh));
	}

	#[test]
	fn transaction_sapling_works() {
		assert_eq!(TransactionSapling::new(&test_data::TransactionBuilder::with_sapling(Sapling {
				balancing_value: 100,
				spends: vec![Default::default()],
				..Default::default()
			}).into()).check(), Ok(()));

		assert_eq!(TransactionSapling::new(&test_data::TransactionBuilder::with_sapling(Sapling {
				balancing_value: 100,
				outputs: vec![Default::default()],
				..Default::default()
			}).into()).check(), Ok(()));

		assert_eq!(TransactionSapling::new(&test_data::TransactionBuilder::with_sapling(Sapling {
				balancing_value: 100,
				outputs: vec![Default::default()],
				spends: vec![Default::default()],
				..Default::default()
			}).into()).check(), Ok(()));

		assert_eq!(TransactionSapling::new(&test_data::TransactionBuilder::with_sapling(Sapling {
				balancing_value: 100,
				..Default::default()
			}).into()).check(), Err(TransactionError::EmptySaplingHasBalance));
	}

	#[test]
	fn transaction_join_split_works() {
		assert_eq!(TransactionJoinSplit::new(&test_data::TransactionBuilder::with_join_split(JoinSplit {
				descriptions: vec![JoinSplitDescription {
					value_pub_old: 100,
					value_pub_new: 0,
					..Default::default()
				}],
				..Default::default()
			}).into()).check(), Ok(()));

		assert_eq!(TransactionJoinSplit::new(&test_data::TransactionBuilder::with_join_split(JoinSplit {
				descriptions: vec![JoinSplitDescription {
					value_pub_old: 0,
					value_pub_new: 100,
					..Default::default()
				}],
				..Default::default()
			}).into()).check(), Ok(()));

		assert_eq!(TransactionJoinSplit::new(&test_data::TransactionBuilder::with_join_split(JoinSplit {
				descriptions: vec![JoinSplitDescription {
					value_pub_old: 100,
					value_pub_new: 100,
					..Default::default()
				}],
				..Default::default()
			}).into()).check(), Err(TransactionError::JoinSplitBothPubsNonZero));
	}

	#[test]
	fn transaction_duplicate_inputs_works() {
		assert_eq!(TransactionDuplicateInputs::new(&test_data::TransactionBuilder::with_default_input(0)
			.add_default_input(1).into()).check(), Ok(()));

		assert_eq!(TransactionDuplicateInputs::new(&test_data::TransactionBuilder::with_default_input(0)
			.add_default_input(0).into()).check(), Err(TransactionError::DuplicateInput(0, 1)));
	}

	#[test]
	fn transaction_duplicate_join_split_nullifiers_works() {
		assert_eq!(TransactionDuplicateJoinSplitNullifiers::new(&test_data::TransactionBuilder::with_join_split(JoinSplit {
			descriptions: vec![JoinSplitDescription {
				nullifiers: [[1; 32], [2; 32]],
				..Default::default()
			}],
			..Default::default()
		}).into()).check(), Ok(()));

		assert_eq!(TransactionDuplicateJoinSplitNullifiers::new(&test_data::TransactionBuilder::with_join_split(JoinSplit {
			descriptions: vec![Default::default(), Default::default()],
			..Default::default()
		}).into()).check(), Err(TransactionError::DuplicateJoinSplitNullifier(0, 0)));
	}

	#[test]
	fn transaction_duplicate_sapling_nullifiers_works() {
		assert_eq!(TransactionDuplicateSaplingNullifiers::new(&test_data::TransactionBuilder::with_sapling(Sapling {
			spends: vec![Default::default()],
			..Default::default()
		}).into()).check(), Ok(()));

		assert_eq!(TransactionDuplicateSaplingNullifiers::new(&test_data::TransactionBuilder::with_sapling(Sapling {
			spends: vec![Default::default(), Default::default()],
			..Default::default()
		}).into()).check(), Err(TransactionError::DuplicateSaplingSpendNullifier(0, 1)));
	}
}
