use serde::{Serialize, Serializer};
use super::hash::H256;
use super::block::RawBlock;

/// Response to getblock RPC request
#[derive(Debug)]
pub enum GetBlockResponse {
	/// When asking for short response
	Raw(RawBlock),
	/// When asking for verbose response
	Verbose(VerboseBlock),
}

/// Verbose block information
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct VerboseBlock {
	/// Block hash
	pub hash: H256,
	/// Number of confirmations. -1 if block is on the side chain
	pub confirmations: i64,
	/// Block size
	pub size: u32,
	/// Block height
	/// TODO: bitcoind always returns value, but we hold this value for main chain blocks only
	pub height: Option<u32>,
	/// Block version
	pub version: u32,
	/// Merkle root of this block
	pub merkleroot: H256,
	/// The root of the Sapling commitment tree after applying this block.
	pub finalsaplingroot: H256,
	/// Transactions ids
	pub tx: Vec<H256>,
	/// Block time in seconds since epoch (Jan 1 1970 GMT)
	pub time: u32,
	/// Block nonce
	pub nonce: H256,
	/// Block nbits
	pub bits: u32,
	/// Block difficulty
	pub difficulty: f64,
	/// Hash of previous block
	pub previousblockhash: Option<H256>,
	/// Hash of next block
	pub nextblockhash: Option<H256>,
}

impl Serialize for GetBlockResponse {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
		match *self {
			GetBlockResponse::Raw(ref raw_block) => raw_block.serialize(serializer),
			GetBlockResponse::Verbose(ref verbose_block) => verbose_block.serialize(serializer),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::super::bytes::Bytes;
	use super::super::hash::H256;
	use serde_json;
	use super::*;

	#[test]
	fn verbose_block_serialize() {
		let block = VerboseBlock::default();
		assert_eq!(serde_json::to_string(&block).unwrap(), r#"{"hash":"0000000000000000000000000000000000000000000000000000000000000000","confirmations":0,"size":0,"height":null,"version":0,"merkleroot":"0000000000000000000000000000000000000000000000000000000000000000","finalsaplingroot":"0000000000000000000000000000000000000000000000000000000000000000","tx":[],"time":0,"nonce":"0000000000000000000000000000000000000000000000000000000000000000","bits":0,"difficulty":0.0,"previousblockhash":null,"nextblockhash":null}"#);

		let block = VerboseBlock {
			hash: H256::from(1),
			confirmations: -1,
			size: 500000,
			height: Some(3513513),
			version: 1,
			merkleroot: H256::from(2),
			tx: vec![H256::from(3), H256::from(4)],
			time: 111,
			nonce: 124.into(),
			bits: 13513,
			difficulty: 555.555,
			previousblockhash: Some(H256::from(4)),
			nextblockhash: Some(H256::from(5)),
			finalsaplingroot: H256::from(3),
		};
		assert_eq!(serde_json::to_string(&block).unwrap(), r#"{"hash":"0100000000000000000000000000000000000000000000000000000000000000","confirmations":-1,"size":500000,"height":3513513,"version":1,"merkleroot":"0200000000000000000000000000000000000000000000000000000000000000","finalsaplingroot":"0300000000000000000000000000000000000000000000000000000000000000","tx":["0300000000000000000000000000000000000000000000000000000000000000","0400000000000000000000000000000000000000000000000000000000000000"],"time":111,"nonce":"7c00000000000000000000000000000000000000000000000000000000000000","bits":13513,"difficulty":555.555,"previousblockhash":"0400000000000000000000000000000000000000000000000000000000000000","nextblockhash":"0500000000000000000000000000000000000000000000000000000000000000"}"#);
	}

	#[test]
	fn verbose_block_deserialize() {
		let block = VerboseBlock::default();
		assert_eq!(
			serde_json::from_str::<VerboseBlock>(r#"{"hash":"0000000000000000000000000000000000000000000000000000000000000000","confirmations":0,"size":0,"height":null,"version":0,"merkleroot":"0000000000000000000000000000000000000000000000000000000000000000","finalsaplingroot":"0000000000000000000000000000000000000000000000000000000000000000","tx":[],"time":0,"nonce":"0000000000000000000000000000000000000000000000000000000000000000","bits":0,"difficulty":0.0,"previousblockhash":null,"nextblockhash":null}"#).unwrap(),
			block);

		let block = VerboseBlock {
			hash: H256::from(1),
			confirmations: -1,
			size: 500000,
			height: Some(3513513),
			version: 1,
			merkleroot: H256::from(2),
			tx: vec![H256::from(3), H256::from(4)],
			time: 111,
			nonce: 124.into(),
			bits: 13513,
			difficulty: 555.555,
			previousblockhash: Some(H256::from(4)),
			nextblockhash: Some(H256::from(5)),
			finalsaplingroot: H256::from(3),
		};
		assert_eq!(
			serde_json::from_str::<VerboseBlock>(r#"{"hash":"0100000000000000000000000000000000000000000000000000000000000000","confirmations":-1,"size":500000,"height":3513513,"version":1,"merkleroot":"0200000000000000000000000000000000000000000000000000000000000000","finalsaplingroot":"0300000000000000000000000000000000000000000000000000000000000000","tx":["0300000000000000000000000000000000000000000000000000000000000000","0400000000000000000000000000000000000000000000000000000000000000"],"time":111,"nonce":"7c00000000000000000000000000000000000000000000000000000000000000","bits":13513,"difficulty":555.555,"previousblockhash":"0400000000000000000000000000000000000000000000000000000000000000","nextblockhash":"0500000000000000000000000000000000000000000000000000000000000000"}"#).unwrap(),
			block);
	}

	#[test]
	fn get_block_response_raw_serialize() {
		let raw_response = GetBlockResponse::Raw(Bytes::new(vec![0]));
		assert_eq!(serde_json::to_string(&raw_response).unwrap(), r#""00""#);
	}

	#[test]
	fn get_block_response_verbose_serialize() {
		let block = VerboseBlock::default();
		let verbose_response = GetBlockResponse::Verbose(block);
		assert_eq!(serde_json::to_string(&verbose_response).unwrap(), r#"{"hash":"0000000000000000000000000000000000000000000000000000000000000000","confirmations":0,"size":0,"height":null,"version":0,"merkleroot":"0000000000000000000000000000000000000000000000000000000000000000","finalsaplingroot":"0000000000000000000000000000000000000000000000000000000000000000","tx":[],"time":0,"nonce":"0000000000000000000000000000000000000000000000000000000000000000","bits":0,"difficulty":0.0,"previousblockhash":null,"nextblockhash":null}"#);
	}
}
