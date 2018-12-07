//! Transaction signer

use byteorder::{ByteOrder, LittleEndian};
use bytes::Bytes;
use crypto::{dhash256, blake2b_personal};
use hash::H256;
use ser::Stream;
use chain::{Transaction, TransactionOutput, OutPoint, TransactionInput, JoinSplit,
	Sapling, SAPLING_TX_VERSION_GROUP_ID};
use Script;

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum SighashBase {
	All = 1,
	None = 2,
	Single = 3,
}

impl From<SighashBase> for u32 {
	fn from(s: SighashBase) -> Self {
		s as u32
	}
}

/// Signature portions cache.
#[derive(Debug, Default, PartialEq)]
pub struct SighashCache {
	pub hash_prevouts: H256,
	pub hash_sequence: H256,
	pub hash_outputs: H256,
	pub hash_join_split: H256,
	pub hash_sapling_spends: H256,
	pub hash_sapling_outputs: H256,
}

#[cfg_attr(feature="cargo-clippy", allow(doc_markdown))]
/// Signature hash type. [Documentation](https://en.bitcoin.it/wiki/OP_CHECKSIG#Procedure_for_Hashtype_SIGHASH_SINGLE)
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Sighash {
	pub base: SighashBase,
	pub anyone_can_pay: bool,
	pub fork_id: bool,
}

impl From<Sighash> for u32 {
	fn from(s: Sighash) -> Self {
		let base = s.base as u32;
		let base = if s.anyone_can_pay {
			base | 0x80
		} else {
			base
		};

		if s.fork_id {
			base | 0x40
		} else {
			base
		}
	}
}

impl Sighash {
	pub fn new(base: SighashBase, anyone_can_pay: bool, fork_id: bool) -> Self {
		Sighash {
			base: base,
			anyone_can_pay: anyone_can_pay,
			fork_id: fork_id,
		}
	}

	/// Used by SCRIPT_VERIFY_STRICTENC
	pub fn is_defined(u: u32) -> bool {
		// reset anyone_can_pay && fork_id (if applicable) bits
		let u = u & !(0x80);

		// Only exact All | None | Single values are passing this check
		match u {
			1 | 2 | 3 => true,
			_ => false,
		}
	}

	/// Creates Sighash from any u, even if is_defined() == false
	pub fn from_u32(u: u32) -> Self {
		let anyone_can_pay = (u & 0x80) == 0x80;
		let base = match u & 0x1f {
			2 => SighashBase::None,
			3 => SighashBase::Single,
			1 | _ => SighashBase::All,
		};

		Sighash::new(base, anyone_can_pay, false)
	}
}

#[derive(Debug)]
pub struct UnsignedTransactionInput {
	pub previous_output: OutPoint,
	pub sequence: u32,
}

/// Used for resigning and loading test transactions
impl From<TransactionInput> for UnsignedTransactionInput {
	fn from(i: TransactionInput) -> Self {
		UnsignedTransactionInput {
			previous_output: i.previous_output,
			sequence: i.sequence,
		}
	}
}

#[derive(Debug)]
pub struct TransactionInputSigner {
	pub overwintered: bool,
	pub version: i32,
	pub version_group_id: u32,
	pub inputs: Vec<UnsignedTransactionInput>,
	pub outputs: Vec<TransactionOutput>,
	pub lock_time: u32,
	pub expiry_height: u32,
	pub join_split: Option<JoinSplit>,
	pub sapling: Option<Sapling>,
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum SignatureVersion {
	Sprout,
	Overwinter,
	Sapling,
}

/// Used for resigning and loading test transactions
impl From<Transaction> for TransactionInputSigner {
	fn from(t: Transaction) -> Self {
		TransactionInputSigner {
			overwintered: t.overwintered,
			version: t.version,
			version_group_id: t.version_group_id,
			inputs: t.inputs.into_iter().map(Into::into).collect(),
			outputs: t.outputs,
			lock_time: t.lock_time,
			expiry_height: t.expiry_height,
			join_split: t.join_split,
			sapling: t.sapling,
		}
	}
}

impl TransactionInputSigner {
	/// Pass None as input_index to compute transparent input signature
	pub fn signature_hash(
		&self,
		cache: &mut Option<SighashCache>,
		input_index: Option<usize>,
		input_amount: u64,
		script_pubkey: &Script,
		sighashtype: u32,
		consensus_branch_id: u32,
	) -> H256 {
		let sighash = Sighash::from_u32(sighashtype);
		let signature_version = self.signature_version();
		match signature_version {
			SignatureVersion::Sprout => self.signature_hash_sprout(input_index, script_pubkey, sighashtype, sighash),
			SignatureVersion::Overwinter | SignatureVersion::Sapling => self.signature_hash_post_overwinter(
				cache,
				input_index,
				input_amount,
				script_pubkey,
				sighashtype,
				sighash,
				consensus_branch_id,
				signature_version == SignatureVersion::Sapling
			),
		}
	}

	/// Sprout version of the signature.
	fn signature_hash_sprout(&self, input_index: Option<usize>, script_pubkey: &Script, sighashtype: u32, sighash: Sighash) -> H256 {
		let input_index = match input_index {
			Some(input_index) if input_index < self.inputs.len() => input_index,
			_ => return 1u8.into(),
		};
		let inputs = if sighash.anyone_can_pay {
			let input = &self.inputs[input_index];
			vec![TransactionInput {
				previous_output: input.previous_output.clone(),
				script_sig: script_pubkey.to_bytes(),
				sequence: input.sequence,
			}]
		} else {
			self.inputs.iter()
				.enumerate()
				.map(|(n, input)| TransactionInput {
					previous_output: input.previous_output.clone(),
					script_sig: if n == input_index {
						script_pubkey.to_bytes()
					} else {
						Bytes::default()
					},
					sequence: match sighash.base {
						SighashBase::Single | SighashBase::None if n != input_index => 0,
						_ => input.sequence,
					},
				})
				.collect()
		};

		let outputs = match sighash.base {
			SighashBase::All => self.outputs.clone(),
			SighashBase::Single => self.outputs.iter()
				.take(input_index + 1)
				.enumerate()
				.map(|(n, out)| if n == input_index {
					out.clone()
				} else {
					TransactionOutput::default()
				})
				.collect(),
			SighashBase::None => Vec::new(),
		};

		let tx = Transaction {
			overwintered: self.overwintered,
			version: self.version,
			version_group_id: self.version_group_id,
			inputs: inputs,
			outputs: outputs,
			lock_time: self.lock_time,
			expiry_height: self.expiry_height,
			join_split: self.join_split.as_ref().map(|js| {
				JoinSplit {
					descriptions: js.descriptions.clone(),
					pubkey: js.pubkey.clone(),
					sig: [0u8; 64].as_ref().into(), // null signature for signing
				}
			}),
			sapling: None,
		};

		let mut stream = Stream::default();
		stream.append(&tx);
		stream.append(&sighashtype);
		let out = stream.out();
		dhash256(&out)
	}

	/// Overwinter/sapling version of the signature.
	fn signature_hash_post_overwinter(
		&self,
		cache: &mut Option<SighashCache>,
		input_index: Option<usize>,
		input_amount: u64,
		script_pubkey: &Script,
		sighashtype: u32,
		sighash: Sighash,
		consensus_branch_id: u32,
		sapling: bool,
	) -> H256 {
		// compute signature portions that can be reused for other inputs
		let hash_prevouts = cache.as_ref().map(|c| c.hash_prevouts)
			.unwrap_or_else(|| compute_hash_prevouts(sighash, &self.inputs));
		let hash_sequence = cache.as_ref().map(|c| c.hash_sequence)
			.unwrap_or_else(|| compute_hash_sequence(sighash, &self.inputs));
		let hash_outputs = compute_hash_outputs(cache, sighash, input_index, &self.outputs);
		let hash_join_split = cache.as_ref().map(|c| c.hash_join_split)
			.unwrap_or_else(|| compute_hash_join_split(self.join_split.as_ref()));
		let hash_sapling_spends = if sapling {
			cache.as_ref().map(|c| c.hash_sapling_spends)
				.unwrap_or_else(|| compute_hash_sapling_spends(self.sapling.as_ref()))
		} else {
			0u8.into()
		};
		let hash_sapling_outputs = if sapling {
			cache.as_ref().map(|c| c.hash_sapling_spends)
				.unwrap_or_else(|| compute_hash_sapling_outputs(self.sapling.as_ref()))
		} else {
			0u8.into()
		};

		// update cache
		*cache = Some(SighashCache {
			hash_prevouts,
			hash_sequence,
			hash_outputs,
			hash_join_split,
			hash_sapling_spends,
			hash_sapling_outputs,
		});

		let mut personalization = [0u8; 16];
		personalization[..12].copy_from_slice(b"ZcashSigHash");
		LittleEndian::write_u32(&mut personalization[12..], consensus_branch_id);

		let mut version = self.version as u32;
		if self.overwintered {
			version = version | 0x80000000;
		}

		let mut stream = Stream::default();
		stream.append(&version);
		stream.append(&self.version_group_id);
		stream.append(&hash_prevouts);
		stream.append(&hash_sequence);
		stream.append(&hash_outputs);
		stream.append(&hash_join_split);
		if sapling {
			stream.append(&hash_sapling_spends);
			stream.append(&hash_sapling_outputs);
		}
		stream.append(&self.lock_time);
		stream.append(&self.expiry_height);
		if sapling {
			if let Some(ref sapling) = self.sapling {
				stream.append(&sapling.balancing_value);
			}
		}

		stream.append(&sighashtype);

		if let Some(input_index) = input_index {
			stream.append(&self.inputs[input_index].previous_output);
			stream.append_list(&**script_pubkey);
			stream.append(&input_amount);
			stream.append(&self.inputs[input_index].sequence);
		}

		blake2b_personal(&personalization, &stream.out())
	}

	fn signature_version(&self) -> SignatureVersion {
		if self.overwintered {
			if self.version_group_id == SAPLING_TX_VERSION_GROUP_ID {
				SignatureVersion::Sapling
			} else {
				SignatureVersion::Overwinter
			}
		} else {
			SignatureVersion::Sprout
		}
	}
}

fn compute_hash_prevouts(sighash: Sighash, inputs: &[UnsignedTransactionInput]) -> H256 {
	const PERSONALIZATION: &'static [u8; 16] = b"ZcashPrevoutHash";

	match sighash.anyone_can_pay {
		false => {
			let mut stream = Stream::default();
			for input in inputs {
				stream.append(&input.previous_output);
			}
			blake2b_personal(PERSONALIZATION, &stream.out())
		},
		true => 0u8.into(),
	}
}

fn compute_hash_sequence(sighash: Sighash, inputs: &[UnsignedTransactionInput]) -> H256 {
	const PERSONALIZATION: &'static [u8; 16] = b"ZcashSequencHash";

	match sighash.base {
		SighashBase::All if !sighash.anyone_can_pay => {
			let mut stream = Stream::default();
			for input in inputs {
				stream.append(&input.sequence);
			}
			blake2b_personal(PERSONALIZATION, &stream.out())
		},
		_ => 0u8.into(),
	}
}

fn compute_hash_outputs(
	cache: &mut Option<SighashCache>,
	sighash: Sighash,
	input_index: Option<usize>,
	outputs: &[TransactionOutput]
) -> H256 {
	const PERSONALIZATION: &'static [u8; 16] = b"ZcashOutputsHash";

	match (sighash.base, input_index) {
		(SighashBase::All, _) => {
			cache.as_ref().map(|c| c.hash_outputs)
				.unwrap_or_else(|| {
					let mut stream = Stream::default();
					for output in outputs {
						stream.append(output);
					}
					blake2b_personal(PERSONALIZATION, &stream.out())
				})
		},
		(SighashBase::Single, Some(input_index)) if input_index < outputs.len() => {
			let mut stream = Stream::default();
			stream.append(&outputs[input_index]);
			blake2b_personal(PERSONALIZATION, &stream.out())
		},
		_ => 0u8.into(),
	}
}

fn compute_hash_join_split(join_split: Option<&JoinSplit>) -> H256 {
	const PERSONALIZATION: &'static [u8; 16] = b"ZcashJSplitsHash";

	match join_split {
		Some(join_split) if !join_split.descriptions.is_empty() => {
			let mut stream = Stream::default();
			for description in &join_split.descriptions {
				stream.append(description);
			}
			stream.append(&join_split.pubkey);
			blake2b_personal(PERSONALIZATION, &stream.out())
		},
		_ => 0u8.into(),
	}
}

fn compute_hash_sapling_spends(sapling: Option<&Sapling>) -> H256 {
	const PERSONALIZATION: &'static [u8; 16] = b"ZcashSSpendsHash";

	match sapling {
		Some(sapling) if !sapling.spends.is_empty() => {
			let mut stream = Stream::default();
			for spend in &sapling.spends {
				stream.append(&spend.value_commitment);
				stream.append(&spend.anchor);
				stream.append(&spend.nullifier);
				stream.append(&spend.randomized_key);
				stream.append(&spend.zkproof);
			}
			blake2b_personal(PERSONALIZATION, &stream.out())
		},
		_ => 0u8.into(),
	}
}

fn compute_hash_sapling_outputs(sapling: Option<&Sapling>) -> H256 {
	const PERSONALIZATION: &'static [u8; 16] = b"ZcashSOutputHash";

	match sapling {
		Some(sapling) if !sapling.outputs.is_empty() => {
			let mut stream = Stream::default();
			for output in &sapling.outputs {
				stream.append(output);
			}
			blake2b_personal(PERSONALIZATION, &stream.out())
		},
		_ => 0u8.into(),
	}
}

#[cfg(test)]
mod tests {
	use hex::FromHex;
	use serde_json::{Value, from_slice};
	use bytes::Bytes;
	use hash::H256;
	use keys::{KeyPair, Private, Address};
	use chain::{OutPoint, TransactionOutput, Transaction};
	use script::Script;
	use ser::deserialize;
	use super::{Sighash, UnsignedTransactionInput, TransactionInputSigner, SighashBase};

	// http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
	// https://blockchain.info/rawtx/81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48
	// https://blockchain.info/rawtx/3f285f083de7c0acabd9f106a43ec42687ab0bebe2e6f0d529db696794540fea
	#[test]
	fn test_signature_hash_simple() {
		let private: Private = "5HusYj2b2x4nroApgfvaSfKYZhRbKFH41bVyPooymbC6KfgSXdD".into();
		let previous_tx_hash = H256::from_reversed_str("81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48");
		let previous_output_index = 0;
		let from: Address = "1MMMMSUb1piy2ufrSguNUdFmAcvqrQF8M5".into();
		let to: Address = "1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa".into();
		let previous_output = "76a914df3bd30160e6c6145baaf2c88a8844c13a00d1d588ac".into();
		let current_output: Bytes = "76a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac".into();
		let value = 91234;
		let expected_signature_hash = "5fda68729a6312e17e641e9a49fac2a4a6a680126610af573caab270d232f850".into();

		// this is irrelevant
		let kp = KeyPair::from_private(private).unwrap();
		assert_eq!(kp.address(), from);
		assert_eq!(&current_output[3..23], &*to.hash);

		let unsigned_input = UnsignedTransactionInput {
			sequence: 0xffff_ffff,
			previous_output: OutPoint {
				index: previous_output_index,
				hash: previous_tx_hash,
			},
		};

		let output = TransactionOutput {
			value: value,
			script_pubkey: current_output,
		};

		let input_signer = TransactionInputSigner {
			overwintered: false,
			version: 1,
			version_group_id: 0,
			lock_time: 0,
			expiry_height: 0,
			inputs: vec![unsigned_input],
			outputs: vec![output],
			join_split: None,
			sapling: None,
		};

		let mut cache = None;
		let hash = input_signer.signature_hash(&mut cache, Some(0), 0, &previous_output, SighashBase::All.into(), 0);
		assert_eq!(hash, expected_signature_hash);
	}

	#[test]
	fn test_sighash_forkid_from_u32() {
		assert!(!Sighash::is_defined(0xFFFFFF82));
		assert!(!Sighash::is_defined(0x00000182));
		assert!(!Sighash::is_defined(0x00000080));
		assert!( Sighash::is_defined(0x00000001));
		assert!( Sighash::is_defined(0x00000082));
		assert!( Sighash::is_defined(0x00000003));
	}

	fn run_test_sighash(
		idx: usize,
		tx: &str,
		script: &str,
		input_index: usize,
		hash_type: i32,
		consensus_branch_id: u32,
		result: &str,
	) {
		let tx: Transaction = deserialize(&tx.from_hex::<Vec<u8>>().unwrap() as &[u8]).unwrap();
		let signer: TransactionInputSigner = tx.into();
		let script: Script = Script::new(script.parse().unwrap());
		let expected: H256 = result.parse().unwrap();
		let expected = expected.reversed();

		let mut cache = None;
		let input_index = if input_index as u64 == ::std::u64::MAX { None } else { Some(input_index) };
		let hash = signer.signature_hash(&mut cache, input_index, 0, &script, hash_type as u32, consensus_branch_id);
		if expected != hash {
			panic!("Test#{} of {:?} sighash failed: expected {}, got {}", idx, signer.signature_version(), expected, hash);
		} else {
			println!("Test#{} succeeded: expected {}, got {}", idx, expected, hash);
		}
	}

	// Official test vectors from ZCash codebase referenced by both sighash-related ZIPs
	// ZIP143 (https://github.com/zcash/zips/blob/9515d73aac0aea3494f77bcd634e1e4fbd744b97/zip-0143.rst)
	// ZIP243 (https://github.com/zcash/zips/blob/9515d73aac0aea3494f77bcd634e1e4fbd744b97/zip-0243.rst)
	// revision:
	// https://github.com/zcash/zcash/blob/9cd74866c72857145952bb9e3aa8e0c04a99b711/src/test/data/sighash.json
	#[test]
	fn test_sighash_overwinter() {
		let tests = include_bytes!("../data/sighash_tests.json");
		let tests: Vec<Value> = from_slice(tests).unwrap();
		for (idx, test) in tests.into_iter().skip(1).enumerate() {
			run_test_sighash(
				idx,
				test[0].as_str().unwrap(),
				test[1].as_str().unwrap(),
				test[2].as_u64().unwrap() as usize,
				test[3].as_i64().unwrap() as i32,
				test[4].as_u64().unwrap() as u32,
				test[5].as_str().unwrap(),
			);
		}
	}
}
