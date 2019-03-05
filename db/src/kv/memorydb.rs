use std::collections::HashMap;
use std::sync::Arc;
use std::mem::replace;
use parking_lot::RwLock;
use hash::H256;
use bytes::Bytes;
use ser::List;
use chain::{Transaction as ChainTransaction, BlockHeader};
use kv::{Transaction, Key, KeyState, Operation, Value, KeyValueDatabase, KeyValue};
use storage::{TransactionMeta, EpochTag, EpochRef, SproutTreeState, SaplingTreeState};

#[derive(Default, Debug)]
struct InnerDatabase {
	meta: HashMap<&'static str, KeyState<Bytes>>,
	block_hash: HashMap<u32, KeyState<H256>>,
	sprout_block_root: HashMap<H256, KeyState<H256>>,
	sapling_block_root: HashMap<H256, KeyState<H256>>,
	block_header: HashMap<H256, KeyState<BlockHeader>>,
	block_transactions: HashMap<H256, KeyState<List<H256>>>,
	transaction: HashMap<H256, KeyState<ChainTransaction>>,
	transaction_meta: HashMap<H256, KeyState<TransactionMeta>>,
	block_number: HashMap<H256, KeyState<u32>>,
	configuration: HashMap<&'static str, KeyState<Bytes>>,
	sprout_nullifiers: HashMap<H256, KeyState<()>>,
	sapling_nullifiers: HashMap<H256, KeyState<()>>,
	sprout_tree_state: HashMap<H256, KeyState<SproutTreeState>>,
	sapling_tree_state: HashMap<H256, KeyState<SaplingTreeState>>,
}

#[derive(Default, Debug)]
pub struct MemoryDatabase {
	db: RwLock<InnerDatabase>,
}

impl MemoryDatabase {
	pub fn drain_transaction(&self) -> Transaction {
		let mut db = self.db.write();
		let meta = replace(&mut db.meta, HashMap::default()).into_iter()
			.flat_map(|(key, state)| state.into_operation(key, KeyValue::Meta, Key::Meta));

		let block_hash = replace(&mut db.block_hash, HashMap::default()).into_iter()
			.flat_map(|(key, state)| state.into_operation(key, KeyValue::BlockHash, Key::BlockHash));

		let block_header = replace(&mut db.block_header, HashMap::default()).into_iter()
			.flat_map(|(key, state)| state.into_operation(key, KeyValue::BlockHeader, Key::BlockHeader));

		let block_transactions = replace(&mut db.block_transactions, HashMap::default()).into_iter()
			.flat_map(|(key, state)| state.into_operation(key, KeyValue::BlockTransactions, Key::BlockTransactions));

		let transaction = replace(&mut db.transaction, HashMap::default()).into_iter()
			.flat_map(|(key, state)| state.into_operation(key, KeyValue::Transaction, Key::Transaction));

		let transaction_meta = replace(&mut db.transaction_meta, HashMap::default()).into_iter()
			.flat_map(|(key, state)| state.into_operation(key, KeyValue::TransactionMeta, Key::TransactionMeta));

		let block_number = replace(&mut db.block_number, HashMap::default()).into_iter()
			.flat_map(|(key, state)| state.into_operation(key, KeyValue::BlockNumber, Key::BlockNumber));

		let configuration = replace(&mut db.configuration, HashMap::default()).into_iter()
			.flat_map(|(key, state)| state.into_operation(key, KeyValue::Configuration, Key::Configuration));

		let sprout_nullifiers = replace(&mut db.sprout_nullifiers, HashMap::default()).into_iter()
			.flat_map(|(key, state)|
				state.into_operation(key,
					|k, _| KeyValue::Nullifier(EpochRef::new(EpochTag::Sprout, k)),
					|h| Key::Nullifier(EpochRef::new(EpochTag::Sprout, h))
				)
			);

		let sapling_nullifiers = replace(&mut db.sapling_nullifiers, HashMap::default()).into_iter()
			.flat_map(|(key, state)|
				state.into_operation(key,
					|k, _| KeyValue::Nullifier(EpochRef::new(EpochTag::Sapling, k)),
					|h| Key::Nullifier(EpochRef::new(EpochTag::Sapling, h))
				)
			);

		let sprout_tree_state = replace(&mut db.sprout_tree_state, HashMap::default()).into_iter()
			.flat_map(|(key, state)|
				state.into_operation(key,
					KeyValue::SproutTreeState,
					|k| Key::TreeRoot(EpochRef::new(EpochTag::Sprout, k))));

		let sprout_block_root = replace(&mut db.sprout_block_root, HashMap::default()).into_iter()
			.flat_map(|(key, state)|
				state.into_operation(key,
					|k, v| KeyValue::BlockRoot(EpochRef::new(EpochTag::Sprout, k), v),
					|k| Key::BlockRoot(EpochRef::new(EpochTag::Sprout, k))));

		let sapling_tree_state = replace(&mut db.sapling_tree_state, HashMap::default()).into_iter()
			.flat_map(|(key, state)|
				state.into_operation(key,
					KeyValue::SaplingTreeState,
					|k| Key::TreeRoot(EpochRef::new(EpochTag::Sapling, k))));

		let sapling_block_root = replace(&mut db.sapling_block_root, HashMap::default()).into_iter()
			.flat_map(|(key, state)|
				state.into_operation(key,
					|k, v| KeyValue::BlockRoot(EpochRef::new(EpochTag::Sapling, k), v),
					|k| Key::BlockRoot(EpochRef::new(EpochTag::Sprout, k))));

		Transaction {
			operations: meta
				.chain(block_hash)
				.chain(block_header)
				.chain(block_transactions)
				.chain(transaction)
				.chain(transaction_meta)
				.chain(block_number)
				.chain(configuration)
				.chain(sprout_tree_state)
				.chain(sapling_tree_state)
				.chain(sprout_block_root)
				.chain(sapling_block_root)
				.chain(sprout_nullifiers)
				.chain(sapling_nullifiers)
				.collect()
		}
	}
}

impl KeyValueDatabase for MemoryDatabase {
	fn write(&self, tx: Transaction) -> Result<(), String> {
		let mut db = self.db.write();
		for op in tx.operations.into_iter() {
			match op {
				Operation::Insert(insert) => match insert {
					KeyValue::Meta(key, value) => { db.meta.insert(key, KeyState::Insert(value)); },
					KeyValue::BlockHash(key, value) => { db.block_hash.insert(key, KeyState::Insert(value)); },
					KeyValue::BlockHeader(key, value) => { db.block_header.insert(key, KeyState::Insert(value)); },
					KeyValue::BlockTransactions(key, value) => { db.block_transactions.insert(key, KeyState::Insert(value)); },
					KeyValue::Transaction(key, value) => { db.transaction.insert(key, KeyState::Insert(value)); },
					KeyValue::TransactionMeta(key, value) => { db.transaction_meta.insert(key, KeyState::Insert(value)); },
					KeyValue::BlockNumber(key, value) => { db.block_number.insert(key, KeyState::Insert(value)); },
					KeyValue::Configuration(key, value) => { db.configuration.insert(key, KeyState::Insert(value)); },
					KeyValue::Nullifier(key) => match key.epoch() {
						EpochTag::Sprout => { db.sprout_nullifiers.insert(*key.hash(), KeyState::Insert(())); },
						EpochTag::Sapling => { db.sapling_nullifiers.insert(*key.hash(), KeyState::Insert(())); },
					},
					KeyValue::SproutTreeState(key, value) => { db.sprout_tree_state.insert(key, KeyState::Insert(value)); },
					KeyValue::SaplingTreeState(key, value) => { db.sapling_tree_state.insert(key, KeyState::Insert(value)); },
					KeyValue::BlockRoot(key, value) => match key.epoch() {
						EpochTag::Sprout => { db.sprout_block_root.insert(*key.hash(), KeyState::Insert(value)); },
						EpochTag::Sapling => { db.sapling_block_root.insert(*key.hash(), KeyState::Insert(value)); },
					},
				},
				Operation::Delete(delete) => match delete {
					Key::Meta(key) => { db.meta.insert(key, KeyState::Delete); }
					Key::BlockHash(key) => { db.block_hash.insert(key, KeyState::Delete); }
					Key::BlockHeader(key) => { db.block_header.insert(key, KeyState::Delete); }
					Key::BlockTransactions(key) => { db.block_transactions.insert(key, KeyState::Delete); }
					Key::Transaction(key) => { db.transaction.insert(key, KeyState::Delete); }
					Key::TransactionMeta(key) => { db.transaction_meta.insert(key, KeyState::Delete); }
					Key::BlockNumber(key) => { db.block_number.insert(key, KeyState::Delete); }
					Key::Configuration(key) => { db.configuration.insert(key, KeyState::Delete); }
					Key::Nullifier(key) => match key.epoch() {
						EpochTag::Sprout => { db.sprout_nullifiers.insert(*key.hash(), KeyState::Delete); },
						EpochTag::Sapling => { db.sapling_nullifiers.insert(*key.hash(), KeyState::Delete); },
					},
					Key::TreeRoot(key) => match key.epoch() {
						EpochTag::Sprout => { db.sprout_tree_state.insert(*key.hash(), KeyState::Delete); },
						EpochTag::Sapling => { db.sapling_tree_state.insert(*key.hash(), KeyState::Delete); },
					},
					Key::BlockRoot(key) => match key.epoch() {
						EpochTag::Sprout => { db.sprout_block_root.insert(*key.hash(), KeyState::Delete); },
						EpochTag::Sapling => { db.sapling_block_root.insert(*key.hash(), KeyState::Delete); },
					},
				},
			}
		}
		Ok(())
	}

	fn get(&self, key: &Key) -> Result<KeyState<Value>, String> {
		let db = self.db.read();
		let result = match *key {
			Key::Meta(ref key) => db.meta.get(key).cloned().unwrap_or_default().map(Value::Meta),
			Key::BlockHash(ref key) => db.block_hash.get(key).cloned().unwrap_or_default().map(Value::BlockHash),
			Key::BlockHeader(ref key) => db.block_header.get(key).cloned().unwrap_or_default().map(Value::BlockHeader),
			Key::BlockTransactions(ref key) => db.block_transactions.get(key).cloned().unwrap_or_default().map(Value::BlockTransactions),
			Key::Transaction(ref key) => db.transaction.get(key).cloned().unwrap_or_default().map(Value::Transaction),
			Key::TransactionMeta(ref key) => db.transaction_meta.get(key).cloned().unwrap_or_default().map(Value::TransactionMeta),
			Key::BlockNumber(ref key) => db.block_number.get(key).cloned().unwrap_or_default().map(Value::BlockNumber),
			Key::Configuration(ref key) => db.configuration.get(key).cloned().unwrap_or_default().map(Value::Configuration),
			Key::Nullifier(ref key) => match key.epoch() {
				EpochTag::Sprout => db.sprout_nullifiers.get(key.hash()).cloned().unwrap_or_default().map(|_| Value::Empty),
				EpochTag::Sapling => db.sapling_nullifiers.get(key.hash()).cloned().unwrap_or_default().map(|_| Value::Empty),
			},
			Key::TreeRoot(ref key) => match key.epoch() {
				EpochTag::Sprout => db.sprout_tree_state.get(key.hash()).cloned().unwrap_or_default().map(Value::SproutTreeState),
				EpochTag::Sapling => db.sapling_tree_state.get(key.hash()).cloned().unwrap_or_default().map(Value::SaplingTreeState),
			},
			Key::BlockRoot(ref key) => match key.epoch() {
				EpochTag::Sprout => db.sprout_block_root.get(key.hash()).cloned().unwrap_or_default().map(Value::TreeRoot),
				EpochTag::Sapling => db.sapling_block_root.get(key.hash()).cloned().unwrap_or_default().map(Value::TreeRoot),
			},
		};

		Ok(result)
	}
}

#[derive(Debug)]
pub struct SharedMemoryDatabase {
	db: Arc<MemoryDatabase>,
}

impl Default for SharedMemoryDatabase {
	fn default() -> Self {
		SharedMemoryDatabase {
			db: Arc::default(),
		}
	}
}

impl Clone for SharedMemoryDatabase {
	fn clone(&self) -> Self {
		SharedMemoryDatabase {
			db: self.db.clone(),
		}
	}
}

impl KeyValueDatabase for SharedMemoryDatabase {
	fn write(&self, tx: Transaction) -> Result<(), String> {
		self.db.write(tx)
	}

	fn get(&self, key: &Key) -> Result<KeyState<Value>, String> {
		self.db.get(key)
	}
}
