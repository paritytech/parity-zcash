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
			cache.as_ref().map(|c| c.hash_sapling_outputs)
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
	use {verify_script, VerificationFlags, TransactionSignatureChecker};

	#[test]
	fn test_signature_hash_simple() {
		let private: Private = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj".into();
		let previous_tx_hash = H256::from_reversed_str("81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48");
		let previous_output_index = 0;
		let from: Address = "t1h8SqgtM3QM5e2M8EzhhT1yL2PXXtA6oqe".into();
		let to: Address = "t1Xxa5ZVPKvs9bGMn7aWTiHjyHvR31XkUst".into();
		let previous_output = "76a914df3bd30160e6c6145baaf2c88a8844c13a00d1d588ac".into();
		let current_output: Bytes = "76a9149a823b698f778ece90b094dc3f12a81f5e3c334588ac".into();
		let value = 91234;
		let expected_signature_hash = "f6d326b3b48fd8f6d6e29b590d76507aebe647043b1588a35605e9405234e391".into();

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

	// Official test vectors from Zcash codebase referenced by both sighash-related ZIPs
	// ZIP143 (https://github.com/zcash/zips/blob/9515d73aac0aea3494f77bcd634e1e4fbd744b97/zip-0143.rst)
	// ZIP243 (https://github.com/zcash/zips/blob/9515d73aac0aea3494f77bcd634e1e4fbd744b97/zip-0243.rst)
	// revision:
	// https://github.com/zcash/zcash/blob/9cd74866c72857145952bb9e3aa8e0c04a99b711/src/test/data/sighash.json
	#[test]
	fn test_signature_hash() {
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

	// tx#1 from block#419201
	#[test]
	fn test_sighash_cache_works_correctly() {
		// tx#1 from block#419201
		// https://zcash.blockexplorer.com/api/rawblock/00000000014d117faa2ea701b24261d364a6c6a62e5bc4bc27335eb9b3c1e2a8
		let spend_tx: Transaction = "0400008085202f8901ddd8ddd4a8713d9443e11f1a79adb737e974bece08608b6b04017d9b436b9399010000006a473044022004cd1a5a48b015213fa0810028d98271d219aa4a7293928dea01946f9e3db53102206837946d92757a460c8d7a2d64872890abbfa3f572cd1e8fabf5a7ca8997de26012102fa947bb7cfa50aa6e83f6296d95334d7f55cd43e9c873404f2550f6ba006d5aaffffffff00000000009465060021f65ff9ffffffff0001b40f6b0d76653bc236b045c7dd16e0e8e1a8fa6fa9f7d5120c1e7289aee78d67f9d8ae3d9707dcb30064b8f7afcc2fc1aca8918f263c58da6c7806cfad133d11fedf35174cf837149b3f2559a70055398c6ab3eba99a3335f4d360488d88266fb533abea66784d930ff8f1574eca66374d4fa559f462d65c0d8af6e7b2770dfb804f9d29388b651b2af0d9d21ad3cd6aebeeb8ecdc98b208aa027e6dcc8f27a13d643d650934faa98a809fa0c61ea3f796f96565cbee80a176a9258621ec3574ce5e7f6ceb70db4bd36f2feb983648f8405ebda405645f005f455f3dd96ea7d5081ba13a6a90cae0aebc7ec7a4589058bf67dc35c511de423d0c29d95febeaf08a32f4e123f39d4bb964d836eeaf2eb825c68c0f7ce62ab8f048f61a28998c1f0340d9660c849b86d8f639955d5d2e15458875dd547c86fd96a74c48b3eb6fc3d31ffdfa24d78afdbb0dbfa8200e87562668293bbab1ca9fc67af4f7369f0e12b6e6e07388189381b38059737ddc3322cbbfd6d1bce912d2bacdfa66f3f22835fc0f3f213e6abef8eacfaffd4c204296900e1651d1c9cbf981364629250b4bafaa5e4d1cbba21a03f6270ddbcaed684caceea5b2870a856a11835923277e5648db0d92ad60f280c7dbb1c2820000fa3117f3e1e0a08cec9f3dfeaf2b6d8d714e072b674d5dbb53420dc9cf67c8f0010665119a8200dd774f0107b17a7398706cf10eecd219f252b2d6813f4d8a672a1dca61f68c75cefb9f2ba7653bdae0b2faa6e76afe9ff62d2ecdfc72d497210517a66f2bf39f402991e5608e754c551e75bd26e7f33474b68d690d5285bd949182731fc49b43d4673aaca20d665c0d0b6ad7cced361c91b06e114e46495400738ef9d528744267fd47d3239e4548a6a3ff6e43b6ca821f32fc261f2c649674a4dc2bac93d177e0c44f4c78694f50ce374978599de6aefbd37e892de81d8d6012675f31daa75fb35bbb339754355e67ea4cf0b8c67d573af3f4f3382b3f408682a50d58767a796ca1ed3dca4227f9d107dc08c0e53134d4fa6e06792182873aa895f3373c388b0c9c7d4a2c065b6f1cd807ef3f4d7b2737eeb90ebb557c859ff17b898d350d8cffc7ca1e08dcb9baba5a336f17e6eba7a2425da8c43caefbd7fa58390e78ad083c36720336fe824983d1fa17402e89d3c224e994248c88ec2f547aeb48227705fd8a4ac3f9f30b139b4e30bb0b82af9bae87800c875c19d6fbd45a26763d056bef6899e031442185ae50a5ed24b006a852f8ce3d55b2d2d9f4179797f93bbffd8905cc9ce69cebc8a17e1e8b8eb5e1e675620c70b22de348969b993246520c00bfa467125a2528a829120b3f64d2c1f58f45cb31a1d15ba368d7df55aa65e65ad4a8f5bc63e06396d40964b3aff6084a83f567b186b1c70072dfebc873638409".into();
		assert_eq!(spend_tx.hash().reversed(), "66e2e3dfb9c51eb961004e0eb8bfd3820239c4f11614b65a1fffb60e01858580".into());
		assert_eq!(spend_tx.inputs[0].previous_output.hash.reversed(), "99936b439b7d01046b8b6008cebe74e937b7ad791a1fe143943d71a8d4ddd8dd".into());
		assert_eq!(spend_tx.inputs[0].previous_output.index, 1);

		// donor tx for input #1:
		// tx#3 from block#409840
		// https://zcash.blockexplorer.com/api/rawblock/0000000002d83a0d7d5011a19d2bd89125dc22d63b6484f2792fd1d636c4d940
		let donor_tx: Transaction = "030000807082c4030b10d6644275fdb7553601349f524ce0a4fb6acc1d17551249b7cb87cb97e07f1f100000006b483045022100977b46b263f691777cb13b9b9c623ce15ccef2d5d5f1efcb7fd1f16aeac98fe20220090ecb6f82cccb37f295ec3c898c1c9b5bb3f46f7b524bc641137a9ce6277bbb012102be56007d075b0ae8e9de4027b61af2b0c8f458c5d1cc6c0a3e0a7f699cfb96c7feffffff8308f2430ed380564b53e7e4fdb16fbb30d1c482dc5fae68613e69d368608c44190000006a47304402201b5673ce6c541a42eac79742e7d1a1c9f51456d5012226985067eec93922f96f0220064c88fa17711860e5a06ebf8849cd4dcbb8f944c39ff227a99a91d8c82a4621012102be56007d075b0ae8e9de4027b61af2b0c8f458c5d1cc6c0a3e0a7f699cfb96c7feffffff5c89bda835f37289182b3123c49c7906629631e4c3c883de97fb637f92802c16580000006a47304402203533eca9827a92959ee7b8c0ea8154b62e9935bc8ca4c61020ff268bb336c59402200e14f6ea6f2e9e0bce19db50b2b10ed3d1e40db957aae3b491797540932dd8ea012102be56007d075b0ae8e9de4027b61af2b0c8f458c5d1cc6c0a3e0a7f699cfb96c7feffffff9b057ba8d3e81fa9c10a98c4ee258df57a9eb1a80f1fb22b08b1685d1ada17fc1f0000006b483045022100e845ab5355bd877641e8238d9f16ac1345af346e81fbeeedda128f23dec5f71002207367e2e38d32e6843aa8c52eedd6b1fbda08d8436e26e0e80e035cb2314710d7012102be56007d075b0ae8e9de4027b61af2b0c8f458c5d1cc6c0a3e0a7f699cfb96c7feffffff9e01f46736183d109a9739638cfff185f62aebf2e9a010f795d80a0b82daad50200000006b483045022100fdf3156db7f2cad51acfd4fcda6ec9f3608ba68f49d5d947e7504a00522f6a4102202f4c74cc34843efbecd53612fd8ea065d8f79b3419190e1792fe3fa03b8d5447012102be56007d075b0ae8e9de4027b61af2b0c8f458c5d1cc6c0a3e0a7f699cfb96c7fefffffffafa19844c386065fd650694ec15094a24e4a6499eb585a0c0544fbf5be9e002010000006a47304402205e2a73750d0ee3672184da65e356fbb95023586ef77c8f01d87eecab09aba5e7022015f8b13eece11b9c7a57bd869b5f44af3a4dfc07ebaf324f899b6541f7ffba050121025792386461f81e038989e4ac62a4142e1e987ae740906ab3032a04e4ac74967bfeffffff1ae4ec68f85c5d67797eccba7653c1a2bc5df34423366af7793bf1232c2bacb9000000006a47304402207501656ce6d97dbd5573953c117cb8fbdc61e09be58798cdab162304291311860220088945ac2142cf3689d7686b146720e4ac1c7f5292c13406fc2628a8e63ff221012103fbdca468248d731579fb6e756566d48903a84a16cd0f415cddfb5c41458bb262feffffff2d805a191e7699a2dcadf2444f682afe2be378b20e3b4b4431f57f32c7d554dd000000006b483045022100b39190d59a549f04f1e22d637f997b1b1ab7abda98d34a67fb616d380d247ea5022039feb0bf51e496dcfad037b0c675038d0c36793a26a66e58a9039524bd6e3e6c012103bb4932a7677891b8945557cb23530b6e9a688f0fa6deac31c9e323f0edf40439feffffff71934ffa32133dc62c7e4b2a8b10f51a8aa0a96099b4fc1e648ea9c676884c6f000000006b48304502210094af623575cec584e3d4406ed30a2f6364a0c6ba493cb77ea0f0d6e8d372cc5f02206ee94b089bfc4e347cf5de9de27785102e3bb146276868a4d9220d405d4e28e2012102cb666a57bb47dc4d447795e439f9d03d7b935f94fd92f80ecabc6a41061a50e8feffffff1bddd5649e33d1595c956b574d3dbb3883d25d1b9be93ef3ce7fad492534d8e4000000006b483045022100800c193e55b1234ed405248ebd69250fb0373bcfe6dda2da593c8f4213d10e5e02202c7b7387449b74125ee8d1f8c381d30f9474f0d5718e33ddd0a9179f5c6ca5ff0121020b2c90de955d7b4bf93415147b8bb43af3186b46e743316ee662ec9136899bf9fefffffffec3b71b6d478340583518ac04357d7a01e39ef311a9b7a9eed4bd3afe8a2a39010000006b483045022100b0e445d7bb23bf2400428d17d8b076d1ea6f415981ef9b806c714697538eaad402203b29f0108126b3345f48dfe22a8b743f3fd91b3c809272d8f81d566530540aa20121029506cd31b962743382a7c5b372d4a6ce66584f7aafefd358ad1b720902c3c907feffffff023d4a0f00000000001976a914e212f89515c07fc61c01fd9ccee566544956822088acef30a006000000001976a91414c42abe82c257103f4589e738f4f05b0f0c600e88ace54006000441060000".into();
		assert_eq!(donor_tx.hash().reversed(), "99936b439b7d01046b8b6008cebe74e937b7ad791a1fe143943d71a8d4ddd8dd".into());

		// prepare tx signature checker
		let consensus_branch_id = 0x76b809bb; // sapling starts from block#419200
		let signer: TransactionInputSigner = spend_tx.clone().into();
		let mut checker = TransactionSignatureChecker {
			signer,
			input_index: 0,
			input_amount: donor_tx.outputs[1].value,
			consensus_branch_id,
			cache: None,
		};

		// calculate signature => fill cache
		checker.signer.signature_hash(
			&mut checker.cache,
			None,
			0,
			&From::from(vec![]),
			::sign::SighashBase::All.into(),
			consensus_branch_id,
		);

		// and finally check input#0 (the cached signature portions are used here)
		let input: Script = spend_tx.inputs[0].script_sig.clone().into();
		let output: Script = donor_tx.outputs[1].script_pubkey.clone().into();
		let flags = VerificationFlags::default()
			.verify_p2sh(true)
			.verify_locktime(true)
			.verify_dersig(true);
		assert_eq!(verify_script(&input, &output, &flags, &mut checker), Ok(()));
	}
}
