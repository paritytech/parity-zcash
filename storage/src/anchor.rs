use hash::H256;
use bytes::Bytes;
use {EpochTag, RegularTreeState};

pub trait AnchorProvider {
	fn tree_bytes_at(&self, root: &H256) -> Option<Bytes>;

	fn tree_at(&self, root: &H256) -> Option<RegularTreeState> {
		self.tree_bytes_at(root)
			.map(
				|bytes| serialization::Reader::new(&bytes[..])
					.read::<RegularTreeState>()
					.expect("Corrupted database: wrong tree state format!")
			)
	}
}
