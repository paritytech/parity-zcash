extern crate elastic_array;
extern crate parking_lot;
extern crate bit_vec;
extern crate lru_cache;
#[macro_use]
extern crate display_derive;

extern crate primitives;
extern crate serialization as ser;
extern crate chain;
extern crate bitcrypto as crypto;
#[macro_use] extern crate lazy_static;

mod best_block;
mod block_ancestors;
mod block_chain;
mod block_impls;
mod block_iterator;
mod block_origin;
mod block_provider;
mod block_ref;
mod error;
mod store;
mod transaction_meta;
mod transaction_provider;
mod nullifier;
mod tree_state;

pub use primitives::{hash, bytes};

pub use best_block::BestBlock;
pub use block_ancestors::BlockAncestors;
pub use block_chain::{BlockChain, ForkChain, Forkable};
pub use block_iterator::BlockIterator;
pub use block_origin::{BlockOrigin, SideChainOrigin};
pub use block_provider::{BlockHeaderProvider, BlockProvider, IndexedBlockProvider};
pub use block_ref::BlockRef;
pub use error::Error;
pub use store::{AsSubstore, Store, SharedStore, CanonStore, ConfigStore};
pub use transaction_meta::TransactionMeta;
pub use transaction_provider::{TransactionProvider, TransactionOutputProvider, TransactionMetaProvider};
pub use nullifier::{Nullifier, NullifierTracker};
pub use tree_state::{TreeState, H32 as H32TreeDim, Dim as TreeDim, RegularTreeState};

/// Epoch tag.
///
/// Sprout and Sapling nullifiers/commitments are considered disjoint,
/// even if they have the same bit pattern.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EpochTag {
	/// Sprout nullifier.
	Sprout,
	/// Sapling nullifier.
	Sapling,
}
