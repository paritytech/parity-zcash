use std::io;
use rustc_serialize::hex::ToHex;
use hash::{H256, H512};
use ser::{Error, Serializable, Deserializable, Stream, Reader};

#[derive(Clone, Serializable, Deserializable)]
pub struct ZKProof(pub Vec<u8>); // TODO: len == 296

impl ::std::fmt::Debug for ZKProof {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
		write!(f, "ZKProof({})", self.0.to_hex())
	}
}

impl Default for ZKProof {
	fn default() -> Self {
		ZKProof([0; 296].to_vec())
	}
}

impl PartialEq for ZKProof {
	fn eq(&self, c: &ZKProof) -> bool {
		self.0.iter().zip(c.0.iter()).all(|(l, r)| l == r)
	}
}

#[derive(Clone, Serializable, Deserializable)]
pub struct CipherText(pub Vec<u8>); // TODO: len == 601

impl PartialEq for CipherText {
	fn eq(&self, c: &CipherText) -> bool {
		self.0.iter().zip(c.0.iter()).all(|(l, r)| l == r)
	}
}

impl ::std::fmt::Debug for CipherText {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
		write!(f, "CipherText({})", self.0.to_hex())
	}
}

impl Default for CipherText {
	fn default() -> Self {
		CipherText([0; 601].to_vec())
	}
}

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
	pub nullifiers: Vec<H256>,
	pub commitments: Vec<H256>,
	pub ephemeral_key: H256,
	pub random_seed: H256,
	pub macs: Vec<H256>,
	pub zkproof: ZKProof,
	pub ciphertexts: CipherText,
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
