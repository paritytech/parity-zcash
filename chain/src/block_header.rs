use std::io;
use std::fmt;
use hex::FromHex;
use ser::{deserialize, serialize};
use crypto::dhash256;
use compact::Compact;
use hash::H256;
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
	pub nonce: u32, // TODO: changed to H256 in Zcash
	pub equihash_solution: Option<EquihashSolution>,
}

impl BlockHeader {
	pub fn hash(&self) -> H256 {
		dhash256(&serialize(self))
	}
}

impl fmt::Debug for BlockHeader {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("BlockHeader")
			.field("version", &self.version)
			.field("previous_header_hash", &self.previous_header_hash.reversed())
			.field("merkle_root_hash", &self.merkle_root_hash.reversed())
			.field("time", &self.time)
			.field("bits", &self.bits)
			.field("nonce", &self.nonce)
			.finish()
	}
}

impl From<&'static str> for BlockHeader {
	fn from(s: &'static str) -> Self {
		deserialize(&s.from_hex().unwrap() as &[u8]).unwrap()
	}
}

impl Serializable for BlockHeader {
	fn serialize(&self, stream: &mut Stream) {
		unimplemented!()
	}
}

impl Deserializable for BlockHeader {
	fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error> where Self: Sized, T: io::Read {
		let version = reader.read()?;
		let previous_header_hash = reader.read()?;
		let merkle_root_hash = reader.read()?;

		// TODO: rename to transaction format - original, witness, zcash, must be enum, not flags
		if reader.read_transaction_joint_split() {
			let _reserved_hash: H256 = reader.read()?;
		}

		let time = reader.read()?;
		let bits = reader.read()?;
		let nonce = reader.read()?;

		let equihash_solution = if reader.read_transaction_joint_split() {
			Some(EquihashSolution(reader.read_list()?))
		} else {
			None
		};

		Ok(BlockHeader {
			version,
			previous_header_hash,
			merkle_root_hash,
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
			nonce: 6,
		};

		let mut stream = Stream::default();
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

		let mut reader = Reader::new(&buffer);

		let expected = BlockHeader {
			version: 1,
			previous_header_hash: [2; 32].into(),
			merkle_root_hash: [3; 32].into(),
			time: 4,
			bits: 5.into(),
			nonce: 6,
		};

		assert_eq!(expected, reader.read().unwrap());
		assert_eq!(ReaderError::UnexpectedEnd, reader.read::<BlockHeader>().unwrap_err());
	}
}
