use hash::H256;
use SproutTreeState;

pub trait TreeStateProvider {
	fn tree_at(&self, root: &H256) -> Option<SproutTreeState>;

	fn block_root(&self, block_hash: &H256) -> Option<H256>;

	fn tree_at_block(&self, block_hash: &H256) -> Option<SproutTreeState> {
		self.block_root(block_hash).and_then(|h| self.tree_at(&h))
	}
}
