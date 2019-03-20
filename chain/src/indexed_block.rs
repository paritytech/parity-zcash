use std::cmp;
use hash::H256;
use hex::FromHex;
use ser::{Serializable, serialized_list_size, deserialize};
use block::Block;
use transaction::Transaction;
use merkle_root::merkle_root;
use indexed_header::IndexedBlockHeader;
use indexed_transaction::IndexedTransaction;

#[derive(Debug, Clone, Deserializable)]
pub struct IndexedBlock {
	pub header: IndexedBlockHeader,
	pub transactions: Vec<IndexedTransaction>,
}

#[cfg(feature = "test-helpers")]
impl From<Block> for IndexedBlock {
	fn from(block: Block) -> Self {
		Self::from_raw(block)
	}
}
impl cmp::PartialEq for IndexedBlock {
	fn eq(&self, other: &Self) -> bool {
		self.header.hash == other.header.hash
	}
}

impl IndexedBlock {
	pub fn new(header: IndexedBlockHeader, transactions: Vec<IndexedTransaction>) -> Self {
		IndexedBlock {
			header: header,
			transactions: transactions,
		}
	}

	/// Explicit conversion of the raw Block into IndexedBlock.
	///
	/// Hashes block header + transactions.
	pub fn from_raw(block: Block) -> Self {
		let Block { block_header, transactions } = block;
		Self::new(
			IndexedBlockHeader::from_raw(block_header),
			transactions.into_iter().map(IndexedTransaction::from_raw).collect(),
		)
	}

	pub fn hash(&self) -> &H256 {
		&self.header.hash
	}

	pub fn to_raw_block(self) -> Block {
		Block::new(self.header.raw, self.transactions.into_iter().map(|tx| tx.raw).collect())
	}

	pub fn size(&self) -> usize {
		let header_size = self.header.raw.serialized_size();
		let transactions = self.transactions.iter().map(|tx| &tx.raw).collect::<Vec<_>>();
		let txs_size = serialized_list_size::<Transaction, &Transaction>(&transactions);
		header_size + txs_size
	}

	pub fn merkle_root(&self) -> H256 {
		merkle_root(&self.transactions.iter().map(|tx| &tx.hash).collect::<Vec<&H256>>())
	}

	pub fn is_final(&self, height: u32) -> bool {
		self.transactions.iter().all(|tx| tx.raw.is_final_in_block(height, self.header.raw.time))
	}
}

impl From<&'static str> for IndexedBlock {
	fn from(s: &'static str) -> Self {
		deserialize(&s.from_hex::<Vec<u8>>().unwrap() as &[u8]).unwrap()
	}
}
