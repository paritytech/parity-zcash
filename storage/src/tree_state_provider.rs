use hash::H256;
use bytes::Bytes;
use RegularTreeState;

pub trait TreeStateProvider {
	fn tree_bytes_at(&self, root: &H256) -> Option<Bytes>;

	fn tree_at(&self, root: &H256) -> Option<RegularTreeState> {
		self.tree_bytes_at(root)
			.map(
				|bytes| serialization::Reader::new(&bytes[..])
					.read::<RegularTreeState>()
					.expect("Corrupted database: wrong tree state format!")
			)
	}

	fn block_root(&self, block_hash: &H256) -> Option<H256>;

	fn tree_at_block(&self, block_hash: &H256) -> Option<RegularTreeState> {
		self.block_root(block_hash).and_then(|h| self.tree_at(&h))
	}
}
