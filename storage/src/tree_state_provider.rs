use hash::H256;
use {SproutTreeState, SaplingTreeState};

pub trait TreeStateProvider : Send + Sync {
	fn sprout_tree_at(&self, root: &H256) -> Option<SproutTreeState>;

	fn sapling_tree_at(&self, root: &H256) -> Option<SaplingTreeState>;

	fn sprout_block_root(&self, block_hash: &H256) -> Option<H256>;

	fn sapling_block_root(&self, block_hash: &H256) -> Option<H256>;

	fn sprout_tree_at_block(&self, block_hash: &H256) -> Option<SproutTreeState> {
		self.sprout_block_root(block_hash).and_then(|h| self.sprout_tree_at(&h))
	}

	fn sapling_tree_at_block(&self, block_hash: &H256) -> Option<SaplingTreeState> {
		self.sapling_block_root(block_hash).and_then(|h| self.sapling_tree_at(&h))
	}
}
