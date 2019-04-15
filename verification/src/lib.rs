//! Bitcoin consensus verification
//!
//!	Full block verification consists of two phases:
//!	- pre-verification
//! - full-verification
//!
//! In this library, pre-verification is done by `VerifyXXX` structures
//! Full-verification is done by `AcceptXXX` structures
//!
//! Use cases:
//!
//! --> A. on_new_block:
//!
//! A.1 VerifyHeader
//! A.2 VerifyBlock,
//! A.3 VerifyTransaction for each tx
//!
//! A.4.a if it is block from canon chain
//! A.4.a.1 AcceptHeader
//! A.4.a.2 AcceptBlock
//! A.4.a.3 AcceptTransaction for each tx
//!
//! A.4.b if it is block from side chain becoming canon
//! decanonize old canon chain blocks
//! canonize new canon chain blocks (without currently processed block)
//! A.4.b.1 AcceptHeader for each header
//! A.4.b.2 AcceptBlock for each block
//! A.4.b.3 AcceptTransaction for each tx in each block
//! A.4.b.4 AcceptHeader
//! A.4.b.5 AcceptBlock
//! A.4.b.6 AcceptTransaction for each tx
//! if any step failed, revert chain back to old canon
//!
//! A.4.c if it is block from side chain do nothing
//!
//! --> B. on_memory_pool_transaction
//!
//! B.1 VerifyMemoryPoolTransaction
//! B.2 AcceptMemoryPoolTransaction
//!
//! --> C. on_block_header
//!
//! C.1 VerifyHeader
//! C.2 AcceptHeader (?)
//!
//! --> D. after successful chain_reorganization
//!
//! D.1 AcceptMemoryPoolTransaction on each tx in memory pool
//!
//! --> E. D might be super inefficient when memory pool is large
//! so instead we might want to call AcceptMemoryPoolTransaction on each tx
//! that is inserted into assembled block

extern crate time;
#[macro_use]
extern crate log;
extern crate parking_lot;
extern crate rayon;
extern crate byteorder;
#[cfg(test)]
extern crate rand;
extern crate rustc_hex as hex;
#[macro_use]
extern crate bitflags;

extern crate storage;
extern crate chain;
extern crate keys;
extern crate network;
extern crate primitives;
extern crate serialization as ser;
extern crate script;
extern crate bitcrypto as crypto;
extern crate bitvec;

#[cfg(test)]
extern crate db;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

pub mod constants;
mod canon;
mod deployments;
mod equihash;
mod error;
mod fee;
mod sapling;
mod sigops;
mod sprout;
mod timestamp;
mod work;

// pre-verification
mod verify_block;
mod verify_chain;
mod verify_header;
mod verify_transaction;

// full verification
mod accept_block;
mod accept_chain;
mod accept_header;
mod accept_transaction;

// backwards compatibility
mod chain_verifier;

mod tree_cache;

pub use primitives::{bigint, hash, compact};

pub use canon::{CanonBlock, CanonHeader, CanonTransaction};
pub use accept_block::BlockAcceptor;
pub use accept_chain::ChainAcceptor;
pub use accept_header::HeaderAcceptor;
pub use accept_transaction::{TransactionAcceptor, MemoryPoolTransactionAcceptor};

pub use verify_block::BlockVerifier;
pub use verify_chain::ChainVerifier;
pub use verify_header::HeaderVerifier;
pub use verify_transaction::{TransactionVerifier, MemoryPoolTransactionVerifier};

pub use chain_verifier::BackwardsCompatibleChainVerifier;
pub use error::{Error, TransactionError, FeeError};
pub use fee::checked_transaction_fee;
pub use sigops::transaction_sigops;
pub use timestamp::{median_timestamp, median_timestamp_inclusive};
pub use work::{work_required, is_valid_proof_of_work, is_valid_proof_of_work_hash};
pub use deployments::Deployments;
pub use tree_cache::TreeCache;

/// Blocks verification level.
bitflags! {
	pub struct VerificationLevel: u32 {
		/// Base level: perform full block verification.
		const FULL = 0x00000001;
		/// Base level: transaction scripts are not checked.
		const HEADER = 0x00000002;
		/// Base level: no blocks verification at all.
		const NO_VERIFICATION = 0x00000004;

		/// This bit is set if header pre-verification (non-context) has already been performed for the block.
		const HINT_HEADER_PRE_VERIFIED = 0x10000000;
	}
}

/// Interface for block verification
pub trait Verify : Send + Sync {
	fn verify(&self, level: VerificationLevel, block: &chain::IndexedBlock) -> Result<(), Error>;
}
