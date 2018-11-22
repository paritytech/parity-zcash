use ser::Serializable;
use storage::{TransactionMetaProvider, TransactionOutputProvider};
use network::{ConsensusParams};
use script::{Script, verify_script, VerificationFlags, TransactionSignatureChecker, TransactionInputSigner};
use duplex_store::DuplexTransactionOutputProvider;
use deployments::BlockDeployments;
use sigops::transaction_sigops;
use canon::CanonTransaction;
use constants::{COINBASE_MATURITY};
use error::TransactionError;
use VerificationLevel;

pub struct TransactionAcceptor<'a> {
	pub size: TransactionSize<'a>,
	pub bip30: TransactionBip30<'a>,
	pub missing_inputs: TransactionMissingInputs<'a>,
	pub maturity: TransactionMaturity<'a>,
	pub overspent: TransactionOverspent<'a>,
	pub double_spent: TransactionDoubleSpend<'a>,
	pub eval: TransactionEval<'a>,
}

impl<'a> TransactionAcceptor<'a> {
	pub fn new(
		// in case of block validation, it's only current block,
		meta_store: &'a TransactionMetaProvider,
		// previous transaction outputs
		// in case of block validation, that's database and currently processed block
		output_store: DuplexTransactionOutputProvider<'a>,
		consensus: &'a ConsensusParams,
		transaction: CanonTransaction<'a>,
		verification_level: VerificationLevel,
		height: u32,
		time: u32,
		transaction_index: usize,
		deployments: &'a BlockDeployments<'a>,
	) -> Self {
		trace!(target: "verification", "Tx verification {}", transaction.hash.to_reversed_str());
		TransactionAcceptor {
			size: TransactionSize::new(transaction, consensus, height),
			bip30: TransactionBip30::new_for_sync(transaction, meta_store),
			missing_inputs: TransactionMissingInputs::new(transaction, output_store, transaction_index),
			maturity: TransactionMaturity::new(transaction, meta_store, height),
			overspent: TransactionOverspent::new(transaction, output_store),
			double_spent: TransactionDoubleSpend::new(transaction, output_store),
			eval: TransactionEval::new(transaction, output_store, consensus, verification_level, height, time, deployments),
		}
	}

	pub fn check(&self) -> Result<(), TransactionError> {
		self.size.check()?;
		self.bip30.check()?;
		self.missing_inputs.check()?;
		self.maturity.check()?;
		self.overspent.check()?;
		self.double_spent.check()?;
		self.eval.check()?;
		Ok(())
	}
}

pub struct MemoryPoolTransactionAcceptor<'a> {
	pub missing_inputs: TransactionMissingInputs<'a>,
	pub maturity: TransactionMaturity<'a>,
	pub overspent: TransactionOverspent<'a>,
	pub sigops: TransactionSigops<'a>,
	pub double_spent: TransactionDoubleSpend<'a>,
	pub eval: TransactionEval<'a>,
}

impl<'a> MemoryPoolTransactionAcceptor<'a> {
	pub fn new(
		// TODO: in case of memory pool it should be db and memory pool
		meta_store: &'a TransactionMetaProvider,
		// in case of memory pool it should be db and memory pool
		output_store: DuplexTransactionOutputProvider<'a>,
		consensus: &'a ConsensusParams,
		transaction: CanonTransaction<'a>,
		height: u32,
		time: u32,
		deployments: &'a BlockDeployments<'a>,
	) -> Self {
		trace!(target: "verification", "Mempool-Tx verification {}", transaction.hash.to_reversed_str());
		let transaction_index = 0;
		let max_block_sigops = consensus.max_block_sigops();
		MemoryPoolTransactionAcceptor {
			missing_inputs: TransactionMissingInputs::new(transaction, output_store, transaction_index),
			maturity: TransactionMaturity::new(transaction, meta_store, height),
			overspent: TransactionOverspent::new(transaction, output_store),
			sigops: TransactionSigops::new(transaction, output_store, consensus, max_block_sigops, time),
			double_spent: TransactionDoubleSpend::new(transaction, output_store),
			eval: TransactionEval::new(transaction, output_store, consensus, VerificationLevel::Full, height, time, deployments),
		}
	}

	pub fn check(&self) -> Result<(), TransactionError> {
		// Bip30 is not checked because we don't need to allow tx pool acceptance of an unspent duplicate.
		// Tx pool validation is not strinctly a matter of consensus.
		try!(self.missing_inputs.check());
		try!(self.maturity.check());
		try!(self.overspent.check());
		try!(self.sigops.check());
		try!(self.double_spent.check());
		try!(self.eval.check());
		Ok(())
	}
}

/// Bip30 validation
///
/// A transaction hash that exists in the chain is not acceptable even if
/// the original is spent in the new block. This is not necessary nor is it
/// described by BIP30, but it is in the code referenced by BIP30. As such
/// the tx pool need only test against the chain, skipping the pool.
///
/// source:
/// https://github.com/libbitcoin/libbitcoin/blob/61759b2fd66041bcdbc124b2f04ed5ddc20c7312/src/chain/transaction.cpp#L780-L785
pub struct TransactionBip30<'a> {
	transaction: CanonTransaction<'a>,
	store: &'a TransactionMetaProvider,
}

impl<'a> TransactionBip30<'a> {
	fn new_for_sync(
		transaction: CanonTransaction<'a>,
		store: &'a TransactionMetaProvider,
	) -> Self {
		TransactionBip30 {
			transaction: transaction,
			store: store,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		match self.store.transaction_meta(&self.transaction.hash) {
			Some(ref meta) if !meta.is_fully_spent() => {
				Err(TransactionError::UnspentTransactionWithTheSameHash)
			},
			_ => Ok(())
		}
	}
}

pub struct TransactionMissingInputs<'a> {
	transaction: CanonTransaction<'a>,
	store: DuplexTransactionOutputProvider<'a>,
	transaction_index: usize,
}

impl<'a> TransactionMissingInputs<'a> {
	fn new(transaction: CanonTransaction<'a>, store: DuplexTransactionOutputProvider<'a>, transaction_index: usize) -> Self {
		TransactionMissingInputs {
			transaction: transaction,
			store: store,
			transaction_index: transaction_index,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		let missing_index = self.transaction.raw.inputs.iter()
			.position(|input| {
				let is_not_null = !input.previous_output.is_null();
				let is_missing = self.store.transaction_output(&input.previous_output, self.transaction_index).is_none();
				is_not_null && is_missing
			});

		match missing_index {
			Some(index) => Err(TransactionError::Input(index)),
			None => Ok(())
		}
	}
}

pub struct TransactionMaturity<'a> {
	transaction: CanonTransaction<'a>,
	store: &'a TransactionMetaProvider,
	height: u32,
}

impl<'a> TransactionMaturity<'a> {
	fn new(transaction: CanonTransaction<'a>, store: &'a TransactionMetaProvider, height: u32) -> Self {
		TransactionMaturity {
			transaction: transaction,
			store: store,
			height: height,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		// TODO: this is should also fail when we are trying to spend current block coinbase
		let immature_spend = self.transaction.raw.inputs.iter()
			.any(|input| match self.store.transaction_meta(&input.previous_output.hash) {
				Some(ref meta) if meta.is_coinbase() && self.height < meta.height() + COINBASE_MATURITY => true,
				_ => false,
			});

		if immature_spend {
			Err(TransactionError::Maturity)
		} else {
			Ok(())
		}
	}
}

pub struct TransactionOverspent<'a> {
	transaction: CanonTransaction<'a>,
	store: DuplexTransactionOutputProvider<'a>,
}

impl<'a> TransactionOverspent<'a> {
	fn new(transaction: CanonTransaction<'a>, store: DuplexTransactionOutputProvider<'a>) -> Self {
		TransactionOverspent {
			transaction: transaction,
			store: store,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		if self.transaction.raw.is_coinbase() {
			return Ok(());
		}

		let available_public = self.transaction.raw.inputs.iter()
			.map(|input| self.store.transaction_output(&input.previous_output, usize::max_value()).map(|o| o.value).unwrap_or(0))
			.sum::<u64>();

		let available_join_split = self.transaction.raw.join_split.iter()
			.flat_map(|js| &js.descriptions)
			.map(|d| d.value_pub_new)
			.sum::<u64>();

		let total_available = available_public + available_join_split;

		let spends = self.transaction.raw.total_spends();

		if spends > total_available {
			Err(TransactionError::Overspend)
		} else {
			Ok(())
		}
	}
}

pub struct TransactionSigops<'a> {
	transaction: CanonTransaction<'a>,
	store: DuplexTransactionOutputProvider<'a>,
	consensus_params: &'a ConsensusParams,
	max_sigops: usize,
	time: u32,
}

impl<'a> TransactionSigops<'a> {
	fn new(transaction: CanonTransaction<'a>, store: DuplexTransactionOutputProvider<'a>, consensus_params: &'a ConsensusParams, max_sigops: usize, time: u32) -> Self {
		TransactionSigops {
			transaction: transaction,
			store: store,
			consensus_params: consensus_params,
			max_sigops: max_sigops,
			time: time,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		let bip16_active = self.time >= self.consensus_params.bip16_time;
		let checkdatasig_active = false;
		let sigops = transaction_sigops(&self.transaction.raw, &self.store, bip16_active, checkdatasig_active);
		if sigops > self.max_sigops {
			Err(TransactionError::MaxSigops)
		} else {
			Ok(())
		}
	}
}

pub struct TransactionEval<'a> {
	transaction: CanonTransaction<'a>,
	store: DuplexTransactionOutputProvider<'a>,
	verification_level: VerificationLevel,
	verify_p2sh: bool,
	verify_strictenc: bool,
	verify_locktime: bool,
	verify_checksequence: bool,
	verify_dersig: bool,
	verify_nulldummy: bool,
	verify_monolith_opcodes: bool,
	verify_magnetic_anomaly_opcodes: bool,
	verify_sigpushonly: bool,
	verify_cleanstack: bool,
}

impl<'a> TransactionEval<'a> {
	fn new(
		transaction: CanonTransaction<'a>,
		store: DuplexTransactionOutputProvider<'a>,
		params: &ConsensusParams,
		verification_level: VerificationLevel,
		height: u32,
		time: u32,
		deployments: &'a BlockDeployments,
	) -> Self {
		let verify_p2sh = time >= params.bip16_time;
		let verify_strictenc = false;
		let verify_locktime = height >= params.bip65_height;
		let verify_dersig = height >= params.bip66_height;
		let verify_monolith_opcodes = false;
		let verify_magnetic_anomaly_opcodes = false;

		let verify_checksequence = deployments.csv();
		let verify_sigpushonly = verify_magnetic_anomaly_opcodes;
		let verify_cleanstack = verify_magnetic_anomaly_opcodes;

		TransactionEval {
			transaction: transaction,
			store: store,
			verification_level: verification_level,
			verify_p2sh: verify_p2sh,
			verify_strictenc: verify_strictenc,
			verify_locktime: verify_locktime,
			verify_checksequence: verify_checksequence,
			verify_dersig: verify_dersig,
			verify_nulldummy: false,
			verify_monolith_opcodes: verify_monolith_opcodes,
			verify_magnetic_anomaly_opcodes: verify_magnetic_anomaly_opcodes,
			verify_sigpushonly: verify_sigpushonly,
			verify_cleanstack: verify_cleanstack,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		if self.verification_level == VerificationLevel::Header
			|| self.verification_level == VerificationLevel::NoVerification {
			return Ok(());
		}

		if self.transaction.raw.is_coinbase() {
			return Ok(());
		}

		let signer: TransactionInputSigner = self.transaction.raw.clone().into();

		let mut checker = TransactionSignatureChecker {
			signer: signer,
			input_index: 0,
			input_amount: 0,
		};

		for (index, input) in self.transaction.raw.inputs.iter().enumerate() {
			let output = self.store.transaction_output(&input.previous_output, usize::max_value())
				.ok_or_else(|| TransactionError::UnknownReference(input.previous_output.hash.clone()))?;

			checker.input_index = index;
			checker.input_amount = output.value;

			let input: Script = input.script_sig.clone().into();
			let output: Script = output.script_pubkey.into();

			let flags = VerificationFlags::default()
				.verify_p2sh(self.verify_p2sh)
				.verify_strictenc(self.verify_strictenc)
				.verify_locktime(self.verify_locktime)
				.verify_checksequence(self.verify_checksequence)
				.verify_dersig(self.verify_dersig)
				.verify_nulldummy(self.verify_nulldummy)
				.verify_concat(self.verify_monolith_opcodes)
				.verify_split(self.verify_monolith_opcodes)
				.verify_and(self.verify_monolith_opcodes)
				.verify_or(self.verify_monolith_opcodes)
				.verify_xor(self.verify_monolith_opcodes)
				.verify_div(self.verify_monolith_opcodes)
				.verify_mod(self.verify_monolith_opcodes)
				.verify_bin2num(self.verify_monolith_opcodes)
				.verify_num2bin(self.verify_monolith_opcodes)
				.verify_checkdatasig(self.verify_magnetic_anomaly_opcodes)
				.verify_sigpushonly(self.verify_sigpushonly)
				.verify_cleanstack(self.verify_cleanstack);

			verify_script(&input, &output, &flags, &checker)
				.map_err(|e| TransactionError::Signature(index, e))?;
		}

		Ok(())
	}
}

pub struct TransactionDoubleSpend<'a> {
	transaction: CanonTransaction<'a>,
	store: DuplexTransactionOutputProvider<'a>,
}

impl<'a> TransactionDoubleSpend<'a> {
	fn new(transaction: CanonTransaction<'a>, store: DuplexTransactionOutputProvider<'a>) -> Self {
		TransactionDoubleSpend {
			transaction: transaction,
			store: store,
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		for input in &self.transaction.raw.inputs {
			if self.store.is_spent(&input.previous_output) {
				return Err(TransactionError::UsingSpentOutput(
					input.previous_output.hash.clone(),
					input.previous_output.index
				))
			}
		}
		Ok(())
	}
}

/// The encoded size of the transaction MUST be less than or equal to current max limit.
pub struct TransactionSize<'a> {
	transaction: CanonTransaction<'a>,
	max_size: usize,
}

impl<'a> TransactionSize<'a> {
	fn new(transaction: CanonTransaction<'a>, consensus: &'a ConsensusParams, height: u32) -> Self {
		TransactionSize {
			transaction: transaction,
			max_size: consensus.max_transaction_size(height),
		}
	}

	fn check(&self) -> Result<(), TransactionError> {
		let size = self.transaction.raw.serialized_size();
		if size > self.max_size {
			Err(TransactionError::MaxSize)
		} else {
			Ok(())
		}
	}
}

/// Check the joinsplit proof of the transaction
pub struct JoinSplitProof<'a> {
	join_split: &'a chain::JoinSplit,
}

impl<'a> JoinSplitProof<'a> {
	fn new(join_split: &'a chain::JoinSplit) -> Self { JoinSplitProof { join_split: join_split }}

	fn check(&self) -> Result<(), TransactionError> {
		Ok(())
	}
}

#[cfg(test)]
mod tests {

	use chain::Transaction;
	use script::{Script, VerificationFlags, TransactionSignatureChecker, TransactionInputSigner, verify_script};

	#[test]
	fn join_split() {

		let input_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff05021d010101ffffffff021070d90000000000232102bdbbb2eb3066bb138d31349ce32b7f05871ac08cfb382023155249b213417d82ac045c36000000000017a9147d46a730d31f97b1930d3368a967c309bd4d136a8700000000";
		let output_hex = "02000000010a141a3f21ed57fa8449ceac0b11909f1b5560f06b772753ca008d49675d45310000000048473044022041aaea8391c0182bf71bd974662e99534d99849b167062f7e8372c4f1a16c2d50220291b2ca6ae7616cd1f1bfddcda5ef2f53d78c2e153d3a8db571885f9adb5f05401ffffffff0000000000011070d900000000000000000000000000d7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd2597ae7c48e86173b231e84fbdcb4d8f569f28f71ebf0f9b5867f9d4c12e031a2acc0108235936d2fa2d2c968654fbea2a89fde8522ec7c227d2ff3c10bff9c1197d8a290cca91f23792df8e56aed6c142eaa322e66360b5c49132b940689fb2bc5e77f7877bba6d2c4425d9861515cbe8a5c87dfd7cf159e9d4ac9ff63c096fbcd91d2a459877b1ed40748e2f020cdc678cf576a62c63138d820aba3df4074014bb1624b703774e138c706ba394698fd33c58424bb1a8d22be0d7bc8fe58d369e89836fe673c246d8d0cb1d7e1cc94acfa5b8d76010db8d53a36a3f0e33f0ccbc0f861b5e3d0a92e1c05c6bca775ba7389f6444f0e6cbd34141953220718594664022cbbb59465c880f50d42d0d49d6422197b5f823c2b3ffdb341869b98ed2eb2fd031b271702bda61ff885788363a7cf980a134c09a24c9911dc94cbe970bd613b700b0891fe8b8b05d9d2e7e51df9d6959bdf0a3f2310164afb197a229486a0e8e3808d76c75662b568839ebac7fbf740db9d576523282e6cdd1adf8b0f9c183ae95b0301fa1146d35af869cc47c51cfd827b7efceeca3c55884f54a68e38ee7682b5d102131b9b1198ed371e7e3da9f5a8b9ad394ab5a29f67a1d9b6ca1b8449862c69a5022e5d671e6989d33c182e0a6bbbe4a9da491dbd93ca3c01490c8f74a780479c7c031fb473670cacde779713dcd8cbdad802b8d418e007335919837becf46a3b1d0e02120af9d926bed2b28ed8a2b8307b3da2a171b3ee1bc1e6196773b570407df6b43b51b52c43f834ee0854577cd3a57f8fc23b02a3845cc1f0f42410f363d862e436bf06dbc5f94eddd3b83cdf47cf0acbd7750dff5cba86ea6f1f46a5013e0dc76715d7230e44a038a527cb9033f3eeaeac661264dc6a384788a7cd8aed59589bca6205fe1bd683fa392e7a3c6cc364bba36ad75ee9babf90f7b94071953df95effc0b1c3f542913ed1eb68e15534f9ceb7777c946edf55f129df128c3f767d8d60c4aa0c5e61d00f8e495e78334e2a9feddd9302e9880cb6174d201c89a1d6bc6e83a80cbf80ab3959dcc6cdd12e3d2f6f14d226e6948954f05544941d16ed1d498532722fa39bb985c3224915dd42d70be61217fdcb4aa023251af38b5576ff9eb865a471f2cb2dbc674e401d18014e6119464768778ddcd00907f20279bdecda3880fbbb4d00bb6c5aa3e06113a2f12fcc298f34ccb6bc2c2887b0b064f3bc2e2b507d31e022e65800dd7d30f25266914646bfc07c1eafbbf1e1163c439774b47e8e844799bc8fd06db050f97f5c74ca833e81bcdcf9d864be5746f965ef41838a3535666df867ef79e07068dc7ef809fb0e08e1629bab3215fe36d0f0e0f8c6bb319f93a0f408ff4abbd88c21afaec2e7720674eaceb27efb9144f619bad6f033cbefcebfbe66cabe8286f2ff97b91f4aeef5cbd99a9b862cb904dc085d96238caaad259280ff35caa211e00324f51ff03b6a1cd159cd501faef780ef7f25a98cdcd05ef67596d58d4aea1f9f3e95aae44fd4d4ea679c5e393d4670fb35bf12d036ea731bdfad297303239251a91f9a900e06987eb8e9f5bb1fb847f5ae47e6724ddeb5a3ac01b706a02e494c5547ce338302b4906cf2c91d59a87324322763a12e13a512ace3afb897510ad9ec95aa14ca568a9962da64e5bc7fd15b3e103ab461ee7db3fc9da0a523fc403c11254cd567ca48c8dac5e5b54953e5c754e31def90fff6c56d589a5c4b9a710ccb43cd24988b2fb9336b5508aa553cfdbd1f32dfb4ff16eae066b5fb244bc9058a91898c4ae893eaf0006dae1185c7f553e6e09d12a0a2a9c181c5e4d87c8895b74b0e23a8dc87faf5d6acd5e98cb1df5585f026ae94b77db0e95c5fe22692bd2e70e8e87d07d92b98cdfcc5367e52014163a6e4511d482816259215ee7df246e493523ee51617c318e1a9825f82e73e640fbc2d25c12ce5a07875d489db6a111afdc87061047077030d32de45cd4e575c02a60c4048560bd02cf9203426f589f429b413390ace832b3ddd3dd371750d94f9c34f60a0f1b621b445525d2190a185feaab9e56a079c46236161559713d585a07e94f2316a92fffa7838f1aea39d7846638d16f9b4d1a7dc053e0ddc6620f30e3e798eba900fd25c10c5d6672c9ed7d4d2fa80c0f0137ff24933c37fcd91b19bc7cdd828f7f3f1df0e45cafca795d847e83bca8baa321006581b024306e24c4c2294c0f41b932c1e9f7602f377e8484c7eeb184fab1f747b1dff5b6e2e89f1e5c4232b5a0a41ed6a3775f8942217078b7e035747891cabd2099bfcbf6a8d4680f51265d9e7d05794514f02470e0eb003ad1222cd4fe8bcd077310c5aff274b19608c31f77453d01c9aa9c21a8d9b71de44386aee2145648f7ead471cabed297b8610bba370baa42603f21f5f4640e5bc1a0402d40394e176a0db8cedb33a9d84c48b58d3851617046511946a3700aabe8f69cdb0469ee67776480be090cad2c7adc0bf59551ef6f1ac3119e5c29ab3b82dd945dab00dc4a91d3826c4e488047a4f3ab2d57c0abe1ee7aba304784e7ad211c32c4058fca7b1db2e282132e5ccafe79fc51ab37334f03715f4ad8735b6e03f01";

		// deserialize && check tx
		// this is tx # 31455d67498d00ca5327776bf060551b9f90110bacce4984fa57ed213f1a140a
		let coinbase_tx: Transaction = input_hex.into();
		// this is tx # ec31a1b3e18533702c74a67d91c49d622717bd53d6192c5cb23b9bdf080416a5
		let spending_tx: Transaction = output_hex.into();

		let output_script: Script = coinbase_tx.outputs()[0].script_pubkey.clone().into();
		let input_script: Script = spending_tx.inputs()[0].script_sig.clone().into();

		let signer: TransactionInputSigner = spending_tx.into();

		let checker = TransactionSignatureChecker {
			signer: signer,
			input_index: 0,
			input_amount: 0,
		};

		let flags = VerificationFlags::default()
			.verify_p2sh(true);
		assert_eq!(verify_script(&input_script, &output_script, &flags, &checker), Ok(()));
	}
}