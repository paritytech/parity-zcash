use std::io;
use rustc_serialize::hex::ToHex;
use hash::{H256, H512};
use ser::{Error, Serializable, Deserializable, Stream, Reader, FixedArray_H256_2,
	FixedArray_u8_296, FixedArray_u8_601_2};

#[derive(Debug, PartialEq, Default, Clone)]
pub struct JointSplit {
	pub descriptions: Vec<JointSplitDescription>,
	pub pubkey: H256,
	pub sig: H512,
}

#[derive(Debug, PartialEq, Default, Clone, Serializable, Deserializable)]
pub struct JointSplitDescription {
	pub value_pub_old: u64,
	pub value_pub_new: u64,
	pub anchor: H256,
	pub nullifiers: FixedArray_H256_2,
	pub commitments: FixedArray_H256_2,
	pub ephemeral_key: H256,
	pub random_seed: H256,
	pub macs: FixedArray_H256_2,
	pub zkproof: FixedArray_u8_296,
	pub ciphertexts: FixedArray_u8_601_2,
}

pub fn serialize_joint_split(stream: &mut Stream, joint_split: &Option<JointSplit>) {
	if let &Some(ref joint_split) = joint_split {
		stream.append_list(&joint_split.descriptions)
			.append(&joint_split.pubkey)
			.append(&joint_split.sig);
	}
}

pub fn deserialize_joint_split<T>(reader: &mut Reader<T>) -> Result<Option<JointSplit>, Error> where T: io::Read {
	let descriptions: Vec<JointSplitDescription> = reader.read_list()?;
	if descriptions.is_empty() {
		return Ok(None);
	}

	let pubkey = reader.read()?;
	let sig = reader.read()?;

	Ok(Some(JointSplit {
		descriptions,
		pubkey,
		sig,
	}))
}
