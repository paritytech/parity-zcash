use std::{fmt, io};
use hash::{H256, H512};
use hex::ToHex;
use ser::{Error, Stream, Reader, CompactInteger};

#[derive(Clone)]
pub enum JointSplitProof {
	PHGR([u8; 296]),
	Groth([u8; 192]),
}

#[derive(Debug, PartialEq, Default, Clone)]
pub struct JointSplit {
	pub descriptions: Vec<JointSplitDescription>,
	pub pubkey: H256,
	pub sig: H512,
}

#[derive(Clone)]
pub struct JointSplitDescription {
	pub value_pub_old: u64,
	pub value_pub_new: u64,
	pub anchor: [u8; 32],
	pub nullifiers: [[u8; 32]; 2],
	pub commitments: [[u8; 32]; 2],
	pub ephemeral_key: [u8; 32],
	pub random_seed: [u8; 32],
	pub macs: [[u8; 32]; 2],
	pub zkproof: JointSplitProof,
	pub ciphertexts: [[u8; 601]; 2],
}

impl Default for JointSplitDescription {
	fn default() -> Self {
		JointSplitDescription {
			value_pub_old: Default::default(),
			value_pub_new: Default::default(),
			anchor: Default::default(),
			nullifiers: Default::default(),
			commitments: Default::default(),
			ephemeral_key: Default::default(),
			random_seed: Default::default(),
			macs: Default::default(),
			zkproof: Default::default(),
			ciphertexts: [[0; 601]; 2],
		}
	}
}

impl fmt::Debug for JointSplitDescription {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("JointSplitDescription")
			.field("value_pub_old", &self.value_pub_old)
			.field("value_pub_new", &self.value_pub_new)
			.field("anchor", &self.anchor.to_hex::<String>())
			.field("nullifiers[0]", &self.nullifiers[0].to_hex::<String>())
			.field("nullifiers[1]", &self.nullifiers[1].to_hex::<String>())
			.field("commitments[0]", &self.commitments[0].to_hex::<String>())
			.field("commitments[1]", &self.commitments[1].to_hex::<String>())
			.field("ephemeral_key", &self.ephemeral_key.to_hex::<String>())
			.field("random_seed", &self.random_seed.to_hex::<String>())
			.field("macs[0]", &self.macs[0].to_hex::<String>())
			.field("macs[1]", &self.macs[1].to_hex::<String>())
			.field("zkproof", &self.zkproof)
			.field("ciphertexts[0]", &self.ciphertexts[0].to_hex::<String>())
			.field("ciphertexts[1]", &self.ciphertexts[1].to_hex::<String>())
			.finish()
	}
}

impl PartialEq<JointSplitDescription> for JointSplitDescription {
	fn eq(&self, other: &JointSplitDescription) -> bool {
		self.value_pub_old == other.value_pub_old
			&& self.value_pub_new == other.value_pub_new
			&& self.anchor == other.anchor
			&& self.nullifiers == other.nullifiers
			&& self.commitments == other.commitments
			&& self.ephemeral_key == other.ephemeral_key
			&& self.random_seed == other.random_seed
			&& self.macs == other.macs
			&& self.zkproof == other.zkproof
			&& self.ciphertexts[0].as_ref() == other.ciphertexts[0].as_ref()
			&& self.ciphertexts[1].as_ref() == other.ciphertexts[1].as_ref()
	}
}

impl Default for JointSplitProof {
	fn default() -> Self {
		JointSplitProof::Groth([0; 192])
	}
}

impl fmt::Debug for JointSplitProof {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			JointSplitProof::PHGR(ref proof) => f.write_fmt(format_args!("PHGR({:?})", &proof.to_hex::<String>())),
			JointSplitProof::Groth(ref proof) => f.write_fmt(format_args!("Groth({:?})", &proof.to_hex::<String>())),
		}
	}
}

impl PartialEq<JointSplitProof> for JointSplitProof {
	fn eq(&self, other: &JointSplitProof) -> bool {
		match (self, other) {
			(&JointSplitProof::Groth(v1), &JointSplitProof::Groth(v2)) => v1.as_ref() == v2.as_ref(),
			(&JointSplitProof::PHGR(v1), &JointSplitProof::PHGR(v2)) => v1.as_ref() == v2.as_ref(),
			_ => false,
		}
	}
}

pub fn serialize_joint_split(stream: &mut Stream, joint_split: &Option<JointSplit>) {
	if let &Some(ref joint_split) = joint_split {
		let len: CompactInteger = joint_split.descriptions.len().into();
		stream.append(&len);
		if !joint_split.descriptions.is_empty() {
			for d in &joint_split.descriptions {
				stream.append(&d.value_pub_old)
					.append(&d.value_pub_new)
					.append(&d.anchor)
					.append(&d.nullifiers)
					.append(&d.commitments)
					.append(&d.ephemeral_key)
					.append(&d.random_seed)
					.append(&d.macs);
				match d.zkproof {
					JointSplitProof::PHGR(ref proof) => stream.append(proof),
					JointSplitProof::Groth(ref proof) => stream.append(proof),
				};
				stream.append(&d.ciphertexts);
			}
			stream.append(&joint_split.pubkey)
				.append(&joint_split.sig);
		}
	}
}

pub fn deserialize_joint_split<T>(reader: &mut Reader<T>, use_groth: bool) -> Result<Option<JointSplit>, Error> where T: io::Read {
	let len: usize = reader.read::<CompactInteger>()?.into();
	let mut descriptions = Vec::with_capacity(len);
	for _ in 0..len {
		descriptions.push(JointSplitDescription {
			value_pub_old: reader.read()?,
			value_pub_new: reader.read()?,
			anchor: reader.read()?,
			nullifiers: reader.read()?,
			commitments: reader.read()?,
			ephemeral_key: reader.read()?,
			random_seed: reader.read()?,
			macs: reader.read()?,
			zkproof: if use_groth {
				JointSplitProof::Groth(reader.read()?)
			} else {
				JointSplitProof::PHGR(reader.read()?)
			},
			ciphertexts: reader.read()?,
		});
	}

	let pubkey = reader.read()?;
	let sig = reader.read()?;

	Ok(Some(JointSplit {
		descriptions,
		pubkey,
		sig,
	}))
}
