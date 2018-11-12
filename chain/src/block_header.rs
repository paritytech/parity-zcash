use std::io;
use std::fmt;
use hex::{ToHex, FromHex};
use ser::{deserialize, serialize};
use crypto::dhash256;
use compact::Compact;
use hash::H256;
use primitives::bytes::Bytes;
use ser::{Error, Serializable, Deserializable, Stream, Reader};

#[derive(Debug, PartialEq, Default, Clone)]
pub struct EquihashSolution(pub Vec<u8>); // TODO: len = 1344

#[derive(PartialEq, Clone)]
pub struct BlockHeader {
	pub version: u32,
	pub previous_header_hash: H256,
	pub merkle_root_hash: H256,
	pub time: u32,
	pub bits: Compact,
	pub nonce: BlockHeaderNonce,
	pub hash_final_sapling_root: Option<H256>,
	pub equihash_solution: Option<EquihashSolution>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum BlockHeaderNonce {
	U32(u32),
	H256(H256),
}

impl From<u32> for BlockHeaderNonce {
	fn from(nonce: u32) -> Self {
		BlockHeaderNonce::U32(nonce)
	}
}

impl BlockHeader {
	pub fn hash(&self) -> H256 {
		dhash256(&serialize(self))
	}

	pub fn equihash_input(&self) -> Bytes {
		let mut stream = Stream::new();
		stream
			.append(&self.version)
			.append(&self.previous_header_hash)
			.append(&self.merkle_root_hash);

		if let Some(hash_final_sapling_root) = self.hash_final_sapling_root.as_ref() {
			stream.append(hash_final_sapling_root);
		}

		stream
			.append(&self.time)
			.append(&self.bits);
		
		match self.nonce {
			BlockHeaderNonce::U32(ref v) => stream.append(v),
			BlockHeaderNonce::H256(ref v) => stream.append(v),
		};

		stream.out()
	}
}

impl fmt::Debug for BlockHeader {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("BlockHeader")
			.field("version", &self.version)
			.field("previous_header_hash", &self.previous_header_hash.reversed())
			.field("merkle_root_hash", &self.merkle_root_hash.reversed())
			.field("hash_final_sapling_root", &self.hash_final_sapling_root)
			.field("time", &self.time)
			.field("bits", &self.bits)
			.field("nonce", &self.nonce)
			.field("equihash_solution", &self.equihash_solution.as_ref().map(|s| s.0.to_hex::<String>()))
			.finish()
	}
}

impl From<&'static str> for BlockHeader {
	fn from(s: &'static str) -> Self {
		deserialize(&s.from_hex::<Vec<u8>>().unwrap() as &[u8]).unwrap()
	}
}

impl Serializable for BlockHeader {
	fn serialize(&self, stream: &mut Stream) {
		stream
			.append(&self.version)
			.append(&self.previous_header_hash)
			.append(&self.merkle_root_hash);
		if let Some(hash_final_sapling_root) = self.hash_final_sapling_root.as_ref() {
			stream.append(hash_final_sapling_root);
		}
		stream
			.append(&self.time)
			.append(&self.bits);
		
		match self.nonce {
			BlockHeaderNonce::U32(ref v) => stream.append(v),
			BlockHeaderNonce::H256(ref v) => stream.append(v),
		};

		if let Some(ref equihash_solution) = self.equihash_solution {
			stream.append_list(&equihash_solution.0);
		}
	}
}

impl Deserializable for BlockHeader {
	fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error> where Self: Sized, T: io::Read {
		let is_zcash_format = reader.is_zcash_reader();

		let version = reader.read()?;
		let previous_header_hash = reader.read()?;
		let merkle_root_hash = reader.read()?;

		// TODO: rename to transaction format - original, witness, zcash, must be enum, not flags
		let hash_final_sapling_root = if is_zcash_format {
			Some(reader.read()?)
		} else {
			None
		};

		let time = reader.read()?;
		let bits = reader.read()?;
		let nonce = match is_zcash_format {
			true => BlockHeaderNonce::H256(reader.read()?),
			false => BlockHeaderNonce::U32(reader.read()?),
		};

		let equihash_solution = if is_zcash_format {
			Some(EquihashSolution(reader.read_list()?))
		} else {
			None
		};

		Ok(BlockHeader {
			version,
			previous_header_hash,
			merkle_root_hash,
			hash_final_sapling_root,
			time,
			bits,
			nonce,
			equihash_solution,
		})
	}
}


#[cfg(test)]
mod tests {
	use ser::{Reader, Error as ReaderError, Stream};
	use super::BlockHeader;

	#[test]
	fn test_block_header_stream() {
		let block_header = BlockHeader {
			version: 1,
			previous_header_hash: [2; 32].into(),
			merkle_root_hash: [3; 32].into(),
			time: 4,
			bits: 5.into(),
			nonce: 6.into(),
			equihash_solution: None,
		};

		let mut stream = Stream::new();
		stream.append(&block_header);

		let expected = vec![
			1, 0, 0, 0,
			2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
			4, 0, 0, 0,
			5, 0, 0, 0,
			6, 0, 0, 0,
		].into();

		assert_eq!(stream.out(), expected);
	}

	#[test]
	fn test_block_header_reader() {
		let buffer = vec![
			1, 0, 0, 0,
			2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
			4, 0, 0, 0,
			5, 0, 0, 0,
			6, 0, 0, 0,
		];

		let mut reader = Reader::new(&buffer, 0);

		let expected = BlockHeader {
			version: 1,
			previous_header_hash: [2; 32].into(),
			merkle_root_hash: [3; 32].into(),
			time: 4,
			bits: 5.into(),
			nonce: 6.into(),
			equihash_solution: None,
		};

		assert_eq!(expected, reader.read().unwrap());
		assert_eq!(ReaderError::UnexpectedEnd, reader.read::<BlockHeader>().unwrap_err());
	}
}
