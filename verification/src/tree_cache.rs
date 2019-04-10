use std::{collections::HashMap, sync::Arc};

use parking_lot::RwLock;

use chain::hash::H256;
use storage::{TreeStateProvider, SproutTreeState, SaplingTreeState};
use error::TransactionError;


#[derive(Clone)]
pub struct TreeCache<'a> {
	persistent: &'a TreeStateProvider ,
	interstitial: HashMap<H256, SproutTreeState>,
}

struct NoPersistentStorage;

const NO_PERSISTENT: &'static NoPersistentStorage = &NoPersistentStorage;

impl TreeStateProvider for NoPersistentStorage {
	fn sprout_tree_at(&self, _root: &H256) -> Option<SproutTreeState> { None }

	fn sapling_tree_at(&self, _root: &H256) -> Option<SaplingTreeState> { None }

	fn sprout_block_root(&self, _block_hash: &H256) -> Option<H256> { None }

	fn sapling_block_root(&self, _block_hash: &H256) -> Option<H256> { None }
}

impl<'a> TreeCache<'a> {
	pub fn new(persistent: &'a TreeStateProvider) -> Self {
		TreeCache {
			persistent: persistent,
			interstitial: Default::default(),
		}
	}

	pub fn new_empty() -> TreeCache<'static> {
		TreeCache {
			persistent: NO_PERSISTENT,
			interstitial: Default::default(),
		}
	}

	pub fn continue_root(&mut self, root: &H256, commitments: &[[u8; 32]; 2]) -> Result<(), TransactionError> {
		let mut tree = match self.interstitial.get(root) {
			Some(tree) => tree.clone(),
			None => {
				self.persistent.sprout_tree_at(root).ok_or(TransactionError::UnknownAnchor(*root))?
			}
		};

		tree.append(commitments[0].into()).expect("Unrecoverable error: merkle tree full");
		tree.append(commitments[1].into()).expect("Unrecoverable error: merkle tree full");

		self.interstitial.insert(tree.root(), tree);

		Ok(())
	}

}