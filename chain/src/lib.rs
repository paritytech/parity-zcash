extern crate rustc_hex as hex;
extern crate heapsize;
extern crate primitives;
extern crate bitcrypto as crypto;
extern crate serialization as ser;
#[macro_use]
extern crate serialization_derive;

pub mod constants;

mod block;
mod block_header;
mod solution;
mod join_split;
mod merkle_root;
mod sapling;
mod transaction;

/// `IndexedBlock` extension
mod read_and_hash;
mod indexed_block;
mod indexed_header;
mod indexed_transaction;

pub trait RepresentH256 {
	fn h256(&self) -> hash::H256;
}

pub use primitives::{hash, bytes, bigint, compact};

pub use transaction::{BTC_TX_VERSION, SPROUT_TX_VERSION, OVERWINTER_TX_VERSION, SAPLING_TX_VERSION};
pub use transaction::{OVERWINTER_TX_VERSION_GROUP_ID, SAPLING_TX_VERSION_GROUP_ID};

pub use block::Block;
pub use block_header::BlockHeader;
pub use solution::EquihashSolution;
pub use join_split::{JoinSplit, JoinSplitDescription, JoinSplitProof};
pub use merkle_root::{merkle_root, merkle_node_hash};
pub use sapling::{Sapling, SaplingSpendDescription, SaplingOutputDescription};
pub use transaction::{Transaction, TransactionInput, TransactionOutput, OutPoint};

pub use read_and_hash::{ReadAndHash, HashedData};
pub use indexed_block::IndexedBlock;
pub use indexed_header::IndexedBlockHeader;
pub use indexed_transaction::IndexedTransaction;

pub type ShortTransactionID = hash::H48;
