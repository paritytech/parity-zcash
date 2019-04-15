use keys::Address;
use network::{ConsensusParams};
use storage::{DuplexTransactionOutputProvider, TransactionOutputProvider, BlockHeaderProvider,
	TreeStateProvider, SaplingTreeState};
use script::{self, Builder};
use sigops::transaction_sigops;
use deployments::BlockDeployments;
use canon::CanonBlock;
use error::Error;
use timestamp::median_timestamp;
use fee::checked_transaction_fee;

/// Flexible verification of ordered block
pub struct BlockAcceptor<'a> {
	pub finality: BlockFinality<'a>,
	pub serialized_size: BlockSerializedSize<'a>,
	pub sigops: BlockSigops<'a>,
	pub miner_reward: BlockCoinbaseMinerReward<'a>,
	pub founder_reward: BlockFounderReward<'a>,
	pub coinbase_script: BlockCoinbaseScript<'a>,
	pub sapling_root: BlockSaplingRoot<'a>,
}

impl<'a> BlockAcceptor<'a> {
	pub fn new(
		tx_out_store: &'a TransactionOutputProvider,
		tree_state_store: &'a TreeStateProvider,
		consensus: &'a ConsensusParams,
		block: CanonBlock<'a>,
		height: u32,
		deployments: &'a BlockDeployments<'a>,
		headers: &'a BlockHeaderProvider,
	) -> Self {
		BlockAcceptor {
			finality: BlockFinality::new(block, height, deployments, headers),
			serialized_size: BlockSerializedSize::new(block, consensus),
			coinbase_script: BlockCoinbaseScript::new(block, consensus, height),
			miner_reward: BlockCoinbaseMinerReward::new(block, tx_out_store, consensus, height),
			founder_reward: BlockFounderReward::new(block, consensus, height),
			sigops: BlockSigops::new(block, tx_out_store, consensus),
			sapling_root: BlockSaplingRoot::new(block, tree_state_store, consensus, height),
		}
	}

	pub fn check(&self) -> Result<(), Error> {
		self.finality.check()?;
		self.sigops.check()?;
		self.serialized_size.check()?;
		self.miner_reward.check()?;
		self.founder_reward.check()?;
		self.coinbase_script.check()?;
		self.sapling_root.check()?;
		Ok(())
	}
}

pub struct BlockFinality<'a> {
	block: CanonBlock<'a>,
	height: u32,
	csv_active: bool,
	headers: &'a BlockHeaderProvider,
}

impl<'a> BlockFinality<'a> {
	fn new(block: CanonBlock<'a>, height: u32, deployments: &'a BlockDeployments<'a>, headers: &'a BlockHeaderProvider) -> Self {
		let csv_active = deployments.csv();

		BlockFinality {
			block: block,
			height: height,
			csv_active: csv_active,
			headers: headers,
		}
	}

	fn check(&self) -> Result<(), Error> {
		let time_cutoff = if self.csv_active {
			median_timestamp(&self.block.header.raw, self.headers)
		} else {
			self.block.header.raw.time
		};

		if self.block.transactions.iter().all(|tx| tx.raw.is_final_in_block(self.height, time_cutoff)) {
			Ok(())
		} else {
			Err(Error::NonFinalBlock)
		}
	}
}

pub struct BlockSerializedSize<'a> {
	block: CanonBlock<'a>,
	max_block_size: usize,
}

impl<'a> BlockSerializedSize<'a> {
	fn new(block: CanonBlock<'a>, consensus: &'a ConsensusParams) -> Self {
		BlockSerializedSize {
			block: block,
			max_block_size: consensus.max_block_size(),
		}
	}

	fn check(&self) -> Result<(), Error> {
		let size = self.block.size();

		if size > self.max_block_size {
			return Err(Error::Size(size));
		}

		Ok(())
	}
}

pub struct BlockSigops<'a> {
	block: CanonBlock<'a>,
	store: &'a TransactionOutputProvider,
	bip16_active: bool,
	max_block_sigops: usize,
}

impl<'a> BlockSigops<'a> {
	fn new(
		block: CanonBlock<'a>,
		store: &'a TransactionOutputProvider,
		consensus: &'a ConsensusParams,
	) -> Self {
		let bip16_active = block.header.raw.time >= consensus.bip16_time;

		BlockSigops {
			block: block,
			store: store,
			bip16_active,
			max_block_sigops: consensus.max_block_sigops(),
		}
	}

	fn check(&self) -> Result<(), Error> {
		let store = DuplexTransactionOutputProvider::new(self.store, &*self.block);
		let sigops = self.block.transactions.iter()
			.map(|tx| transaction_sigops(&tx.raw, &store, self.bip16_active))
			.fold(0, |acc, tx_sigops| (acc + tx_sigops));

		if sigops > self.max_block_sigops {
			return Err(Error::MaximumSigops);
		}

		Ok(())
	}
}

pub struct BlockCoinbaseMinerReward<'a> {
	block: CanonBlock<'a>,
	store: &'a TransactionOutputProvider,
	max_reward: u64,
}

impl<'a> BlockCoinbaseMinerReward<'a> {
	fn new(
		block: CanonBlock<'a>,
		store: &'a TransactionOutputProvider,
		consensus: &ConsensusParams,
		height: u32,
	) -> Self {
		BlockCoinbaseMinerReward {
			block: block,
			store: store,
			max_reward: consensus.block_reward(height),
		}
	}

	fn check(&self) -> Result<(), Error> {
		let store = DuplexTransactionOutputProvider::new(self.store, &*self.block);

		let mut fees: u64 = 0;

		for (tx_idx, tx) in self.block.transactions.iter().enumerate().skip(1) {
			let tx_fee = checked_transaction_fee(&store, tx_idx, &tx.raw)
				.map_err(|tx_err| Error::Transaction(tx_idx, tx_err))?;

			// Adding to total fees (with possible overflow)
			let (sum, overflow) = fees.overflowing_add(tx_fee);
			if overflow {
				return Err(Error::TransactionFeesOverflow)
			}

			fees = sum;
		}

		let claim = self.block.transactions[0].raw.total_spends();

		let (max_reward, overflow) = fees.overflowing_add(self.max_reward);
		if overflow {
			return Err(Error::TransactionFeeAndRewardOverflow);
		}

		if claim > max_reward {
			Err(Error::CoinbaseOverspend { expected_max: max_reward, actual: claim })
		} else {
			Ok(())
		}
	}
}

pub struct BlockCoinbaseScript<'a> {
	block: CanonBlock<'a>,
	bip34_active: bool,
	height: u32,
}

impl<'a> BlockCoinbaseScript<'a> {
	fn new(block: CanonBlock<'a>, consensus_params: &ConsensusParams, height: u32) -> Self {
		BlockCoinbaseScript {
			block: block,
			bip34_active: height >= consensus_params.bip34_height,
			height: height,
		}
	}

	fn check(&self) -> Result<(), Error> {
		if !self.bip34_active {
			return Ok(())
		}

		let prefix = script::Builder::default()
			.push_i64(self.height.into())
			.into_script();

		let matches = self.block.transactions.first()
			.and_then(|tx| tx.raw.inputs.first())
			.map(|input| input.script_sig.starts_with(&prefix))
			.unwrap_or(false);

		if matches {
			Ok(())
		} else {
			Err(Error::CoinbaseScript)
		}
	}
}

pub struct BlockFounderReward<'a> {
	block: CanonBlock<'a>,
	founder_address: Option<Address>,
	founder_reward: u64,
}

impl<'a> BlockFounderReward<'a> {
	fn new(block: CanonBlock<'a>, consensus_params: &ConsensusParams, height: u32) -> Self {
		BlockFounderReward {
			block: block,
			founder_address: consensus_params.founder_address(height),
			founder_reward: consensus_params.founder_reward(height),
		}
	}

	fn check(&self) -> Result<(), Error> {
		if let Some(ref founder_address) = self.founder_address {
			let script = Builder::build_p2sh(&founder_address.hash);
			let has_founder_reward = self.block.transactions.first()
				.map(|tx| tx.raw.outputs.iter().any(|output|
					**output.script_pubkey == *script &&
					output.value == self.founder_reward))
				.unwrap_or(false);

			if !has_founder_reward {
				return Err(Error::MissingFoundersReward);
			}
		}

		Ok(())
	}
}

pub struct BlockSaplingRoot<'a> {
	block: CanonBlock<'a>,
	tree_state_store: &'a TreeStateProvider,
	is_sapling_active: bool,
}

impl<'a> BlockSaplingRoot<'a> {
	fn new(
		block: CanonBlock<'a>,
		tree_state_store: &'a TreeStateProvider,
		consensus_params: &ConsensusParams,
		height: u32,
	) -> Self {
		BlockSaplingRoot {
			block: block,
			tree_state_store: tree_state_store,
			is_sapling_active: consensus_params.is_sapling_active(height),
		}
	}

	fn check(&self) -> Result<(), Error> {
		if !self.is_sapling_active {
			return Ok(());
		}

		let mut sapling_tree = if self.block.header.raw.previous_header_hash.is_zero() {
			SaplingTreeState::new()
		} else {
			self.tree_state_store.sapling_tree_at_block(&self.block.header.raw.previous_header_hash)
				.ok_or(Error::MissingSaplingCommitmentTree)?
		};

		for tx in &self.block.transactions {
			if let Some(ref sapling) = tx.raw.sapling {
				for out in &sapling.outputs {
					sapling_tree.append(out.note_commitment.into())
						.map_err(|e| Error::FailedToAppendSaplingCommitmentNote(e.into()))?;
				}
			}
		}

		let sapling_tree_root = sapling_tree.root();
		if sapling_tree_root != self.block.header.raw.final_sapling_root {
			return Err(Error::InvalidFinalSaplingRootHash {
				expected: sapling_tree_root,
				actual: self.block.header.raw.final_sapling_root,
			});
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	extern crate test_data;

	use std::collections::HashMap;
	use chain::{OutPoint, TransactionOutput};
	use db::BlockChainDatabase;
	use network::{ConsensusParams, Network};
	use storage::{SaplingTreeState, TransactionOutputProvider};
	use {Error, CanonBlock};
	use super::{BlockCoinbaseScript, BlockSaplingRoot, BlockCoinbaseMinerReward};

	#[test]
	fn test_block_coinbase_script() {
		// transaction from block 461373
		// https://blockchain.info/rawtx/7cf05175ce9c8dbfff9aafa8263edc613fc08f876e476553009afcf7e3868a0c?format=hex
		let tx = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3f033d0a070004b663ec58049cba630608733867a0787a02000a425720537570706f727420384d200a666973686572206a696e78696e092f425720506f6f6c2fffffffff01903d9d4e000000001976a914721afdf638d570285d02d3076d8be6a03ee0794d88ac00000000".into();
		let block_number = 461373;
		let block = test_data::block_builder()
			.with_transaction(tx)
			.header().build()
			.build()
			.into();

		let coinbase_script_validator = BlockCoinbaseScript {
			block: CanonBlock::new(&block),
			bip34_active: true,
			height: block_number,
		};

		assert_eq!(coinbase_script_validator.check(), Ok(()));

		let coinbase_script_validator2 = BlockCoinbaseScript {
			block: CanonBlock::new(&block),
			bip34_active: true,
			height: block_number - 1,
		};

		assert_eq!(coinbase_script_validator2.check(), Err(Error::CoinbaseScript));
	}

	#[test]
	fn test_block_sapling_root() {
		let storage = BlockChainDatabase::init_test_chain(vec![test_data::genesis().into()]);

		// when sapling is inactive
		let block = test_data::block_builder().header().build().build().into();
		assert_eq!(BlockSaplingRoot {
			block: CanonBlock::new(&block),
			tree_state_store: &storage,
			is_sapling_active: false,
		}.check(), Ok(()));

		// when sapling is active and root matches
		let block = test_data::block_builder()
			.header().final_sapling_root(SaplingTreeState::empty_root()).build()
			.build()
			.into();
		assert_eq!(BlockSaplingRoot {
			block: CanonBlock::new(&block),
			tree_state_store: &storage,
			is_sapling_active: true,
		}.check(), Ok(()));

		// when sapling is active and root mismatches
		let block = test_data::block_builder().header().build().build().into();
		assert_eq!(BlockSaplingRoot {
			block: CanonBlock::new(&block),
			tree_state_store: &storage,
			is_sapling_active: true,
		}.check(), Err(Error::InvalidFinalSaplingRootHash {
			expected: "fbc2f4300c01f0b7820d00e3347c8da4ee614674376cbc45359daa54f9b5493e".into(),
			actual: "0000000000000000000000000000000000000000000000000000000000000000".into(),
		}));
	}

	#[test]
	fn test_coinbase_overspend_b419221() {
		struct Store(HashMap<OutPoint, TransactionOutput>);

		impl TransactionOutputProvider for Store {
			fn transaction_output(&self, outpoint: &OutPoint, _transaction_index: usize) -> Option<TransactionOutput> {
				self.0.get(outpoint).cloned()
			}

			fn is_spent(&self, _outpoint: &OutPoint) -> bool {
				false
			}
		}

		let (block, donors) = test_data::block_h419221_with_donors();
		let store = Store(donors.into_iter().flat_map(|donor| {
			let hash = donor.hash();
			donor.outputs.into_iter().enumerate().map(move |(index, output)| (OutPoint {
				hash: hash.clone(),
				index: index as u32,
			}, output))
		}).collect());
		let consensus = ConsensusParams::new(Network::Mainnet);
		assert_eq!(BlockCoinbaseMinerReward::new(CanonBlock::new(&block.into()), &store, &consensus, 419221).check(), Ok(()));
	}
}
