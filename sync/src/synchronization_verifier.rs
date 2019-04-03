use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::mpsc::{channel, Sender, Receiver, TryRecvError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use parking_lot::Mutex;
use time::get_time;
use chain::{IndexedBlockHeader, IndexedBlock, IndexedTransaction};
use network::ConsensusParams;
use primitives::hash::H256;
use verification::{BackwardsCompatibleChainVerifier as ChainVerifier, Verify as VerificationVerify,
	Error as VerificationError, VerificationLevel};
use types::{PeerIndex, BlockHeight, StorageRef, MemoryPoolRef};
use utils::MemoryPoolTransactionOutputProvider;
use VerificationParameters;

//// Block that is (possibly) partially verified.
#[derive(Debug)]
pub enum PartiallyVerifiedBlock {
	/// Block that isn't verified at all.
	NotVerified(IndexedBlock),
	/// Block that has its header pre-verified (mind that AcceptHeader isn't called).
	HeaderPreVerified(IndexedBlock),
}

/// Headers verification events sink
pub trait HeadersVerificationSink : Send + Sync + 'static {
	/// When headers verification has completed successfully.
	fn on_headers_verification_success(&self, headers: Vec<IndexedBlockHeader>);
	/// When headers verification has failed.
	fn on_headers_verification_error(&self, peer: PeerIndex, error: String, hash: H256);
}

/// Block verification events sink
pub trait BlockVerificationSink : Send + Sync + 'static {
	/// When block verification has completed successfully.
	fn on_block_verification_success(&self, block: IndexedBlock) -> Option<Vec<VerificationTask>>;
	/// When block verification has failed.
	fn on_block_verification_error(&self, err: &str, hash: &H256);
}

/// Transaction verification events sink
pub trait TransactionVerificationSink : Send + Sync + 'static {
	/// When transaction verification has completed successfully.
	fn on_transaction_verification_success(&self, transaction: IndexedTransaction);
	/// When transaction verification has failed.
	fn on_transaction_verification_error(&self, err: &str, hash: &H256);
}

/// Verification events sink
pub trait VerificationSink : HeadersVerificationSink + BlockVerificationSink + TransactionVerificationSink {
}

/// Verification thread tasks
#[derive(Debug)]
pub enum VerificationTask {
	/// Verify headers
	VerifyHeaders(PeerIndex, Vec<IndexedBlockHeader>),
	/// Verify single block
	VerifyBlock(PartiallyVerifiedBlock),
	/// Verify single transaction
	VerifyTransaction(BlockHeight, IndexedTransaction),
	/// Stop verification thread
	Stop,
}

/// Synchronization verifier
pub trait Verifier : Send + Sync + 'static {
	/// Returns true if there are no scheduled or currently executing tasks.
	fn is_idle(&self) -> bool;
	/// Verify headers
	fn verify_headers(&self, peer: PeerIndex, headers: Vec<IndexedBlockHeader>);
	/// Verify block
	fn verify_block(&self, block: PartiallyVerifiedBlock);
	/// Verify transaction
	fn verify_transaction(&self, height: BlockHeight, transaction: IndexedTransaction);
}

/// Asynchronous synchronization verifier
pub struct AsyncVerifier {
	/// Is verification thread idle?
	is_idle: Arc<AtomicBool>,
	/// Verification work transmission channel.
	verification_work_sender: Mutex<Sender<VerificationTask>>,
	/// Verification thread.
	verification_worker_thread: Option<thread::JoinHandle<()>>,
}

/// Chain verifier wrapper to deal with verification parameters.
pub struct ChainVerifierWrapper {
	/// Original verifier.
	pub verifier: Arc<ChainVerifier>,
	/// Verification parameters.
	verification_params: VerificationParameters,
	/// True if we have passed verification edge && full verification is required.
	pub enforce_full_verification: AtomicBool,
}

impl PartiallyVerifiedBlock {
	/// Returns hash of the block.
	pub fn hash(&self) -> &H256 {
		match *self {
			PartiallyVerifiedBlock::NotVerified(ref block)
				| PartiallyVerifiedBlock::HeaderPreVerified(ref block) => block.hash(),
		}
	}
}

impl From<PartiallyVerifiedBlock> for IndexedBlock {
	fn from(block: PartiallyVerifiedBlock) -> Self {
		match block {
			PartiallyVerifiedBlock::NotVerified(block) => block,
			PartiallyVerifiedBlock::HeaderPreVerified(block) => block,
		}
	}
}

#[cfg(test)]
impl From<IndexedBlock> for PartiallyVerifiedBlock {
	fn from(block: IndexedBlock) -> Self {
		PartiallyVerifiedBlock::NotVerified(block)
	}
}

impl ChainVerifierWrapper {
	/// Create new chain verifier wrapper.
	pub fn new(verifier: Arc<ChainVerifier>, storage: &StorageRef, verification_params: VerificationParameters) -> Self {
		let enforce_full_verification = AtomicBool::new(storage.contains_block(verification_params.verification_edge.clone().into()));
		ChainVerifierWrapper {
			verifier: verifier,
			verification_params: verification_params,
			enforce_full_verification: enforce_full_verification,
		}
	}

	/// Verify header.
	pub fn verify_block_header(&self, header: &IndexedBlockHeader) -> Result<(), VerificationError> {
		self.verifier.verify_block_header(header)
	}

	/// Verify block.
	pub fn verify_block(&self, block: &PartiallyVerifiedBlock) -> Result<(), VerificationError> {
		let enforce_full_verification = if block.hash() == &self.verification_params.verification_edge {
			self.enforce_full_verification.store(true, Ordering::Relaxed);
			true
		} else {
			self.enforce_full_verification.load(Ordering::Relaxed)
		};

		// select base verification level
		let mut verification_level = if enforce_full_verification {
			VerificationLevel::FULL
		} else {
			self.verification_params.verification_level
		};

		// update verification level with hints, if necessary
		let block = match *block {
			PartiallyVerifiedBlock::NotVerified(ref block) => block,
			PartiallyVerifiedBlock::HeaderPreVerified(ref block) => {
				verification_level.insert(VerificationLevel::HINT_HEADER_PRE_VERIFIED);
				block
			},
		};

		self.verifier.verify(verification_level, block)
	}
}

impl VerificationTask {
	/// Returns transaction reference if it is transaction verification task
	pub fn transaction(&self) -> Option<&IndexedTransaction> {
		match *self {
			VerificationTask::VerifyTransaction(_, ref transaction) => Some(transaction),
			_ => None,
		}
	}
}

impl AsyncVerifier {
	/// Create new async verifier
	pub fn new<T: VerificationSink>(verifier: Arc<ChainVerifier>, storage: StorageRef, memory_pool: MemoryPoolRef, sink: Arc<T>, verification_params: VerificationParameters) -> Self {
		let is_idle = Arc::new(AtomicBool::new(true));
		let (verification_work_sender, verification_work_receiver) = channel();
		AsyncVerifier {
			is_idle: is_idle.clone(),
			verification_work_sender: Mutex::new(verification_work_sender),
			verification_worker_thread: Some(thread::Builder::new()
				.name("Sync verification thread".to_string())
				.spawn(move || {
					let verifier = ChainVerifierWrapper::new(verifier, &storage, verification_params);
					AsyncVerifier::verification_worker_proc(sink, storage, memory_pool, verifier, verification_work_receiver, is_idle)
				})
				.expect("Error creating sync verification thread"))
		}
	}

	/// Thread procedure for handling verification tasks
	fn verification_worker_proc<T: VerificationSink>(
		sink: Arc<T>,
		storage: StorageRef,
		memory_pool: MemoryPoolRef,
		verifier: ChainVerifierWrapper,
		work_receiver: Receiver<VerificationTask>,
		is_idle: Arc<AtomicBool>,
	) {
		loop {
			let task = match work_receiver.try_recv() {
				Ok(task) => task,
				Err(TryRecvError::Empty) => {
					is_idle.store(true, Ordering::SeqCst);
					match work_receiver.recv() {
						Ok(task) => task,
						Err(_) => break,
					}
				},
				Err(TryRecvError::Disconnected) => break,
			};

			is_idle.store(false, Ordering::SeqCst);
			if !AsyncVerifier::execute_single_task(&sink, &storage, &memory_pool, &verifier, task) {
				break;
			}
		}

		trace!(target: "sync", "Stopping sync verification thread");
	}

	/// Execute single verification task
	pub fn execute_single_task<T: VerificationSink>(
		sink: &Arc<T>,
		storage: &StorageRef,
		memory_pool: &MemoryPoolRef,
		verifier: &ChainVerifierWrapper,
		task: VerificationTask,
	) -> bool {
		// block verification && insertion can lead to reorganization
		// => transactions from decanonized blocks should be put back to the MemoryPool
		// => they must be verified again
		// => here's sub-tasks queue
		let mut tasks_queue: VecDeque<VerificationTask> = VecDeque::new();
		tasks_queue.push_back(task);

		while let Some(task) = tasks_queue.pop_front() {
			match task {
				VerificationTask::VerifyHeaders(peer, headers) => {
					let result = headers.iter()
						.try_for_each(|header| verifier.verify_block_header(header)
							.map_err(|error| (error, header.hash)));
					match result {
						Ok(_) => sink.on_headers_verification_success(headers),
						Err((error, hash)) => sink.on_headers_verification_error(peer, format!("{:?}", error), hash),
					}
				},
				VerificationTask::VerifyBlock(block) => {
					// verify block
					match verifier.verify_block(&block) {
						Ok(_) => {
							if let Some(tasks) = sink.on_block_verification_success(block.into()) {
								tasks_queue.extend(tasks);
							}
						},
						Err(e) => {
							sink.on_block_verification_error(&format!("{:?}", e), block.hash())
						}
					}
				},
				VerificationTask::VerifyTransaction(height, transaction) => {
					// output provider must check previous outputs in both storage && memory pool
					match MemoryPoolTransactionOutputProvider::for_transaction(storage.clone(), memory_pool, &transaction.raw) {
						Err(e) => {
							sink.on_transaction_verification_error(&format!("{:?}", e), &transaction.hash);
							continue; // with new verification sub-task
						},
						Ok(tx_output_provider) => {
							let time: u32 = get_time().sec as u32;
							match verifier.verifier.verify_mempool_transaction(storage.as_block_header_provider(), &tx_output_provider, height, time, &transaction) {
								Ok(_) => sink.on_transaction_verification_success(transaction.into()),
								Err(e) => sink.on_transaction_verification_error(&format!("{:?}", e), &transaction.hash),
							}
						},
					};
				},
				VerificationTask::Stop => return false,
			}
		}

		true
	}
}

impl Drop for AsyncVerifier {
	fn drop(&mut self) {
		if let Some(join_handle) = self.verification_worker_thread.take() {
			{
				let verification_work_sender = self.verification_work_sender.lock();
				// ignore send error here <= destructing anyway
				let _ = verification_work_sender.send(VerificationTask::Stop);
			}
			join_handle.join().expect("Clean shutdown.");
		}
	}
}

impl Verifier for AsyncVerifier {
	fn is_idle(&self) -> bool {
		self.is_idle.load(Ordering::SeqCst)
	}

	fn verify_headers(&self, peer: PeerIndex, headers: Vec<IndexedBlockHeader>) {
		self.verification_work_sender.lock()
			.send(VerificationTask::VerifyHeaders(peer, headers))
			.expect("Verification thread have the same lifetime as `AsyncVerifier`");
	}

	fn verify_block(&self, block: PartiallyVerifiedBlock) {
		self.verification_work_sender.lock()
			.send(VerificationTask::VerifyBlock(block))
			.expect("Verification thread have the same lifetime as `AsyncVerifier`");
	}

	fn verify_transaction(&self, height: BlockHeight, transaction: IndexedTransaction) {
		self.verification_work_sender.lock()
			.send(VerificationTask::VerifyTransaction(height, transaction))
			.expect("Verification thread have the same lifetime as `AsyncVerifier`");
	}
}

/// Synchronous synchronization verifier
pub struct SyncVerifier<T: VerificationSink> {
	/// Verifier
	verifier: ChainVerifierWrapper,
	/// Verification sink
	sink: Arc<T>,
}

impl<T> SyncVerifier<T> where T: VerificationSink {
	/// Create new sync verifier
	pub fn new(consensus: ConsensusParams, storage: StorageRef, sink: Arc<T>, verification_params: VerificationParameters) -> Self {
		let verifier = ChainVerifier::new(storage.clone(), consensus);
		let verifier = ChainVerifierWrapper::new(Arc::new(verifier), &storage, verification_params);
		SyncVerifier {
			verifier: verifier,
			sink: sink,
		}
	}
}

impl<T> Verifier for SyncVerifier<T> where T: VerificationSink {
	fn is_idle(&self) -> bool {
		true
	}

	/// Verify headers
	fn verify_headers(&self, _peer: PeerIndex, _headers: Vec<IndexedBlockHeader>) {
		unreachable!("SyncVerifier is used only for blocks verification")
	}

	/// Verify block
	fn verify_block(&self, block: PartiallyVerifiedBlock) {
		match self.verifier.verify_block(&block) {
			Ok(_) => {
				// SyncVerifier is used for bulk blocks import only
				// => there is no memory pool
				// => we could ignore decanonized transactions
				self.sink.on_block_verification_success(block.into());
			},
			Err(e) => self.sink.on_block_verification_error(&format!("{:?}", e), block.hash()),
		}
	}

	/// Verify transaction
	fn verify_transaction(&self, _height: BlockHeight, _transaction: IndexedTransaction) {
		unreachable!("SyncVerifier is used only for blocks verification")
	}
}

#[cfg(test)]
pub mod tests {
	extern crate test_data;

	use std::sync::Arc;
	use std::sync::atomic::Ordering;
	use std::collections::{HashSet, HashMap};
	use db::BlockChainDatabase;
	use network::{Network, ConsensusParams};
	use verification::{VerificationLevel, BackwardsCompatibleChainVerifier as ChainVerifier, Error as VerificationError, TransactionError};
	use script::Error as ScriptError;
	use synchronization_client_core::CoreVerificationSink;
	use synchronization_executor::tests::DummyTaskExecutor;
	use primitives::hash::H256;
	use chain::{IndexedBlockHeader, IndexedBlock, IndexedTransaction};
	use super::{Verifier, HeadersVerificationSink, BlockVerificationSink, TransactionVerificationSink,
		AsyncVerifier, VerificationTask, ChainVerifierWrapper, PartiallyVerifiedBlock};
	use types::{PeerIndex, BlockHeight, StorageRef, MemoryPoolRef};
	use VerificationParameters;

	#[derive(Default)]
	pub struct DummyVerifier {
		sink: Option<Arc<CoreVerificationSink<DummyTaskExecutor>>>,
		errors: HashMap<H256, String>,
		actual_checks: HashSet<H256>,
		storage: Option<StorageRef>,
		memory_pool: Option<MemoryPoolRef>,
		verifier: Option<ChainVerifierWrapper>,
	}

	impl DummyVerifier {
		pub fn set_sink(&mut self, sink: Arc<CoreVerificationSink<DummyTaskExecutor>>) {
			self.sink = Some(sink);
		}

		pub fn set_storage(&mut self, storage: StorageRef) {
			self.storage = Some(storage);
		}

		pub fn set_memory_pool(&mut self, memory_pool: MemoryPoolRef) {
			self.memory_pool = Some(memory_pool);
		}

		pub fn set_verifier(&mut self, verifier: Arc<ChainVerifier>) {
			self.verifier = Some(ChainVerifierWrapper::new(verifier, self.storage.as_ref().unwrap(), VerificationParameters {
				verification_level: VerificationLevel::FULL,
				verification_edge: 0u8.into(),
			}));
		}

		pub fn error_when_verifying(&mut self, hash: H256, err: &str) {
			self.errors.insert(hash, err.into());
		}

		pub fn actual_check_when_verifying(&mut self, hash: H256) {
			self.actual_checks.insert(hash);
		}
	}

	impl Verifier for DummyVerifier {
		fn is_idle(&self) -> bool {
			true
		}

		fn verify_headers(&self, _peer: PeerIndex, headers: Vec<IndexedBlockHeader>) {
			match self.sink {
				Some(ref sink) => sink.on_headers_verification_success(headers),
				_ => (),
			}
		}

		fn verify_block(&self, block: PartiallyVerifiedBlock) {
			match self.sink {
				Some(ref sink) => match self.errors.get(&block.hash()) {
					Some(err) => sink.on_block_verification_error(&err, &block.hash()),
					None => {
						if self.actual_checks.contains(block.hash()) {
							AsyncVerifier::execute_single_task(sink, self.storage.as_ref().unwrap(), self.memory_pool.as_ref().unwrap(), self.verifier.as_ref().unwrap(), VerificationTask::VerifyBlock(block));
						} else {
							sink.on_block_verification_success(block.into());
						}
					},
				},
				None => panic!("call set_sink"),
			}
		}

		fn verify_transaction(&self, _height: BlockHeight, transaction: IndexedTransaction) {
			match self.sink {
				Some(ref sink) => match self.errors.get(&transaction.hash) {
					Some(err) => sink.on_transaction_verification_error(&err, &transaction.hash),
					None => {
						if self.actual_checks.contains(&transaction.hash) {
							let next_block_height = self.storage.as_ref().unwrap().best_block().number + 1;
							AsyncVerifier::execute_single_task(sink, self.storage.as_ref().unwrap(), self.memory_pool.as_ref().unwrap(), self.verifier.as_ref().unwrap(), VerificationTask::VerifyTransaction(next_block_height, transaction));
						} else {
							sink.on_transaction_verification_success(transaction.into());
						}
					},
				},
				None => panic!("call set_sink"),
			}
		}
	}

	#[test]
	fn verifier_wrapper_switches_to_full_mode() {
		let storage: StorageRef = Arc::new(BlockChainDatabase::init_test_chain(vec![test_data::genesis().into()]));
		let verifier = Arc::new(ChainVerifier::new(storage.clone(), ConsensusParams::new(Network::Unitest)));

		// switching to full verification when block is already in db
		assert_eq!(ChainVerifierWrapper::new(verifier.clone(), &storage, VerificationParameters {
			verification_level: VerificationLevel::NO_VERIFICATION,
			verification_edge: test_data::genesis().hash(),
		}).enforce_full_verification.load(Ordering::Relaxed), true);

		// switching to full verification when block with given hash is coming
		let wrapper = ChainVerifierWrapper::new(verifier, &storage, VerificationParameters {
			verification_level: VerificationLevel::NO_VERIFICATION,
			verification_edge: test_data::block_h1().hash(),
		});
		assert_eq!(wrapper.enforce_full_verification.load(Ordering::Relaxed), false);
		let block: IndexedBlock = test_data::block_h1().into();
		let _ = wrapper.verify_block(&block.into());
		assert_eq!(wrapper.enforce_full_verification.load(Ordering::Relaxed), true);
	}

	#[test]
	fn verification_level_header_accept_incorrect_transaction() {
		let consensus = ConsensusParams::new(Network::Unitest);
		let mut blocks: Vec<IndexedBlock> = vec![test_data::genesis().into()];
		let mut rolling_hash = blocks[0].hash().clone();
		for i in 1..101 {
			let next_block = test_data::block_builder()
				.transaction()
					.coinbase()
					.founder_reward(&consensus, i)
					.version(i as i32)
					.output().value(5000000000).build()
					.build()
				.merkled_header()
					.parent(rolling_hash.clone())
					.bits(Network::Unitest.max_bits().into())
					.time(consensus.pow_target_spacing * 7 * i)
					.build()
				.build();
			rolling_hash = next_block.hash();
			blocks.push(next_block.into());
		}

		let coinbase_transaction_hash = blocks[1].transactions[0].hash.clone();
		let last_block_hash = blocks[blocks.len() - 1].hash().clone();
		let storage: StorageRef = Arc::new(BlockChainDatabase::init_test_chain(blocks));
		let verifier = Arc::new(ChainVerifier::new(storage.clone(), ConsensusParams::new(Network::Unitest)));
		let bad_transaction_block: IndexedBlock = test_data::block_builder()
			.transaction().coinbase()
				.founder_reward(&consensus, 101)
				.output().value(50).build()
				.build()
			.transaction()
				.input().hash(coinbase_transaction_hash).build()
				.output().value(1000).build()
				.build()
			.merkled_header()
				.parent(last_block_hash)
				.bits(Network::Unitest.max_bits().into())
				.time(consensus.pow_target_spacing * 7 * 102)
				.build()
			.build().into();


		// Ok(()) when tx script is not checked
		let wrapper = ChainVerifierWrapper::new(verifier.clone(), &storage, VerificationParameters {
			verification_level: VerificationLevel::HEADER,
			verification_edge: 1.into(),
		});
		assert_eq!(wrapper.verify_block(&bad_transaction_block.clone().into()), Ok(()));

		// Error when tx script is checked
		let wrapper = ChainVerifierWrapper::new(verifier, &storage, VerificationParameters {
			verification_level: VerificationLevel::FULL,
			verification_edge: 1.into(),
		});
		assert_eq!(wrapper.verify_block(&bad_transaction_block.into()), Err(VerificationError::Transaction(1, TransactionError::Signature(0, ScriptError::InvalidStackOperation))));
	}

	#[test]
	fn verification_level_none_accept_incorrect_block() {
		let storage: StorageRef = Arc::new(BlockChainDatabase::init_test_chain(vec![test_data::genesis().into()]));
		let verifier = Arc::new(ChainVerifier::new(storage.clone(), ConsensusParams::new(Network::Unitest)));
		let bad_block: IndexedBlock = test_data::block_builder().header().build().build().into();

		// Ok(()) when nothing is verified
		let wrapper = ChainVerifierWrapper::new(verifier.clone(), &storage, VerificationParameters {
			verification_level: VerificationLevel::NO_VERIFICATION,
			verification_edge: 1.into(),
		});
		assert_eq!(wrapper.verify_block(&bad_block.clone().into()), Ok(()));

		// Error when everything is verified
		let wrapper = ChainVerifierWrapper::new(verifier, &storage, VerificationParameters {
			verification_level: VerificationLevel::FULL,
			verification_edge: 1.into(),
		});
		assert_eq!(wrapper.verify_block(&bad_block.into()), Err(VerificationError::Empty));
	}
}
