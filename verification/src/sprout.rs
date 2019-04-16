use chain::{JoinSplit, JoinSplitProof, JoinSplitDescription};
use crypto::{Pghr13Proof, pghr13_verify, curve::bn, curve::bls};

/// Join split verification error kind
#[derive(Debug)]
pub enum ErrorKind {
	/// Invalid join split zkp statement of pghr type
	InvalidPGHRProof,
	/// Invalid join split zkp statement of groyh type
	InvalidGrothProof,
	/// Invalid raw bytes econding of proof
	InvalidEncoding,
}

// blake2 hash of (random_seed, nullifier[0], nullifier[1], pub_key_hash) with 'ZcashComputehSig' personal token
pub fn compute_hsig(random_seed: &[u8; 32], nullifiers: &[[u8; 32]; 2], pub_key_hash: &[u8; 32]) -> [u8; 32] {
	use crypto::blake2::Params;

	let res = Params::new()
		.hash_length(32)
		.personal(b"ZcashComputehSig")
		.to_state()
		.update(&random_seed[..])
		.update(&nullifiers[0][..])
		.update(&nullifiers[1][..])
		.update(&pub_key_hash[..])
		.finalize();

	let mut result = [0u8; 32];
	result.copy_from_slice(res.as_bytes());
	result
}

pub fn verify(
	desc: &JoinSplitDescription,
	join_split: &JoinSplit,
	sprout_verifying_key: &crypto::Pghr13VerifyingKey,
	sapling_verifying_key: &crypto::Groth16VerifyingKey,
) -> Result<(), ErrorKind>
{

	let hsig = compute_hsig(&desc.random_seed, &desc.nullifiers, &join_split.pubkey.into());

	let mut input = Input::new(2176);
	input.push_hash(&desc.anchor);
	input.push_hash(&hsig);

	input.push_hash(&desc.nullifiers[0]);
	input.push_hash(&desc.macs[0]);

	input.push_hash(&desc.nullifiers[1]);
	input.push_hash(&desc.macs[1]);

	input.push_hash(&desc.commitments[0]);
	input.push_hash(&desc.commitments[1]);

	input.push_u64(desc.value_pub_old);
	input.push_u64(desc.value_pub_new);

	match desc.zkproof {
		JoinSplitProof::PHGR(ref proof_raw) => {

			let proof = Pghr13Proof::from_raw(proof_raw).map_err(|_| ErrorKind::InvalidEncoding)?;

			if !pghr13_verify(sprout_verifying_key, &input.into_bn_frs(), &proof) {
				return Err(ErrorKind::InvalidPGHRProof);
			}
		},
		JoinSplitProof::Groth(ref proof) => {

			let input = input.into_bls_frs();
			assert_eq!(input.len(), 9);
			assert_eq!(sapling_verifying_key.0.ic.len(), 10);

			if !crypto::bellman::groth16::verify_proof(
				&sapling_verifying_key.0,
				&proof.to_bls_proof().map_err(|_| ErrorKind::InvalidEncoding)?,
				&input,
//			).map_err(|_| ErrorKind::InvalidGrothProof)? {
			).unwrap() {
				return Err(ErrorKind::InvalidGrothProof);
			}
		},
	}

	Ok(())
}

#[derive(Debug, Clone)]
pub struct Input {
	bits: bitvec::BitVec,
}

impl Input {
	fn new(size: usize) -> Self {
		Input { bits: bitvec::BitVec::with_capacity(size) }
	}

	fn push_hash(&mut self, val: &[u8; 32]) {
		self.push_bytes(&val[..])
	}

	fn push_u64(&mut self, val: u64) {
		self.push_bytes(&val.to_le_bytes()[..]);
	}

	fn push_bytes(&mut self, vals: &[u8]) {
		for b in vals.iter()
			.flat_map(|&m| (0..8).rev().map(move |i| m >> i & 1 == 1))
		{
			self.bits.push(b);
		}
	}

	#[cfg(test)]
	pub(crate) fn bits(&self) -> &bitvec::BitVec {
		&self.bits
	}

	pub fn into_bn_frs(self) -> Vec<bn::Fr> {
		let mut frs = Vec::new();

		for bits in self.bits.chunks(253)
		{
			let mut num = bn::Fr::zero();
			let mut coeff = bn::Fr::one();
			for bit in bits {
				num = if bit { num + coeff } else { num };
				coeff = coeff + coeff;
			}

			frs.push(num);
		}

		frs
	}

	pub fn into_bls_frs(self) -> Vec<bls::Fr> {
		use crypto::pairing::{Field, PrimeField};

		let mut frs = Vec::new();

		for bits in self.bits.chunks(bls::Fr::CAPACITY as usize)
		{
			let mut num = bls::Fr::zero();
			let mut coeff = bls::Fr::one();
			for bit in bits {
				if bit { num.add_assign(&coeff) }
				coeff.double();
			}

			frs.push(num);
		}

		frs
	}
}

#[cfg(test)]
mod tests {

	use super::{compute_hsig, verify};
	use crypto;
	use chain::{JoinSplit, JoinSplitProof, JoinSplitDescription};
	use crypto::{load_sapling_spend_verifying_key, load_sapling_output_verifying_key};

	fn hash(s: &'static str) -> [u8; 32] {
		use hex::FromHex;
		let mut bytes: Vec<u8> = s.from_hex().expect(&format!("hash '{}' is not actually a hash somehow", s));
		bytes.reverse();
		assert_eq!(bytes.len(), 32);
		let mut result = [0u8; 32];
		result.copy_from_slice(&bytes[..]);
		result
	}

	fn hash2(s: &'static str) -> [u8; 32] {
		use hex::FromHex;
		let bytes: Vec<u8> = s.from_hex().expect(&format!("hash '{}' is not actually a hash somehow", s));
		assert_eq!(bytes.len(), 32);
		let mut result = [0u8; 32];
		result.copy_from_slice(&bytes[..]);
		result
	}

	fn dummy_groth16_key() -> crypto::Groth16VerifyingKey {
		use crypto::pairing::{CurveAffine, bls12_381::{G1Affine, G2Affine}};
		use crypto::bellman::groth16::{VerifyingKey, prepare_verifying_key};

		crypto::Groth16VerifyingKey(prepare_verifying_key(&VerifyingKey {
			alpha_g1: G1Affine::zero(),
			beta_g1: G1Affine::zero(),
			beta_g2: G2Affine::zero(),
			gamma_g2: G2Affine::zero(),
			delta_g1: G1Affine::zero(),
			delta_g2: G2Affine::zero(),
			ic: vec![],
		}))
	}

	#[test]
	fn test_vectors() {
		assert_eq!(
			compute_hsig(
				&hash("6161616161616161616161616161616161616161616161616161616161616161"),
				&[
					hash("6262626262626262626262626262626262626262626262626262626262626262"),
					hash("6363636363636363636363636363636363636363636363636363636363636363"),
				],
				&hash("6464646464646464646464646464646464646464646464646464646464646464"),
			),
			hash("a8cba69f1fa329c055756b4af900f8a00b61e44f4cb8a1824ceb58b90a5b8113"),
		);

		assert_eq!(
			compute_hsig(
				&hash("0000000000000000000000000000000000000000000000000000000000000000"),
				&[
					hash("0000000000000000000000000000000000000000000000000000000000000000"),
					hash("0000000000000000000000000000000000000000000000000000000000000000"),
				],
				&hash("0000000000000000000000000000000000000000000000000000000000000000"),
			),
			hash("697322276b5dd93b12fb1fcbd2144b2960f24c73aac6c6a0811447be1e7f1e19"),
		);

		assert_eq!(
			compute_hsig(
				&hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
				&[
					hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
					hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
				],
				&hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
			),
			hash("b61110ec162693bc3d9ca7fb0eec3afd2e278e2f41394b3ff11d7cb761ad4b27"),
		);

		assert_eq!(
			compute_hsig(
				&hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
				&[
					hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
					hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
				],
				&hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
			),
			hash("4961048919f0ca79d49c9378c36a91a8767060001f4212fe6f7d426f3ccf9f32"),
		);


		assert_eq!(
			compute_hsig(
				&hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
				&[
					hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
					hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
				],
				&hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
			),
			hash("b61110ec162693bc3d9ca7fb0eec3afd2e278e2f41394b3ff11d7cb761ad4b27"),
		);
	}


	fn input_to_str(v: &super::Input) -> String {
		let mut s = String::new();
		for i in 0..v.bits().len() { if v.bits()[i] { s.push('1') } else { s.push('0') } }
		s
	}

	#[test]
	fn input1() {
		let mut input = super::Input::new(64);
		input.push_bytes(&[0x00, 0x01, 0x03, 0x12, 0xFF][..]);

		assert_eq!(
			&input_to_str(&input),
			"0000000000000001000000110001001011111111"
		);
	}

	#[test]
	fn input2() {
		let mut input = super::Input::new(64);
		input.push_u64(14250000);
		input.push_u64(0);
		assert_eq!(
			input.into_bn_frs()[0].into_u256(),
			10161672.into()
		);
	}

	fn vkey() -> crypto::Pghr13VerifyingKey {
		crypto::json::pghr13::decode(include_bytes!("../../res/sprout-verifying-key.json")).expect("known to be good").into()
	}

	fn pgh13_proof(hex: &'static str) -> JoinSplitProof {
		use hex::FromHex;

		assert_eq!(hex.len(), 296*2);

		let bytes: Vec<u8> = hex.from_hex().expect("is static and should be good");
		let mut arr = [0u8; 296];
		arr[..].copy_from_slice(&bytes[..]);

		JoinSplitProof::PHGR(arr)
	}

	fn groth16_proof(hex: &'static str) -> JoinSplitProof {
		use hex::FromHex;

		assert_eq!(hex.len(), 192*2);

		let bytes: Vec<u8> = hex.from_hex().expect("is static and should be good");
		let mut arr = [0u8; 192];
		arr[..].copy_from_slice(&bytes[..]);

		JoinSplitProof::Groth(arr.into())
	}

	fn sample_pghr_proof() -> JoinSplitProof {
		pgh13_proof("022cbbb59465c880f50d42d0d49d6422197b5f823c2b3ffdb341869b98ed2eb2fd031b271702bda61ff885788363a7cf980a134c09a24c9911dc94cbe970bd613b700b0891fe8b8b05d9d2e7e51df9d6959bdf0a3f2310164afb197a229486a0e8e3808d76c75662b568839ebac7fbf740db9d576523282e6cdd1adf8b0f9c183ae95b0301fa1146d35af869cc47c51cfd827b7efceeca3c55884f54a68e38ee7682b5d102131b9b1198ed371e7e3da9f5a8b9ad394ab5a29f67a1d9b6ca1b8449862c69a5022e5d671e6989d33c182e0a6bbbe4a9da491dbd93ca3c01490c8f74a780479c7c031fb473670cacde779713dcd8cbdad802b8d418e007335919837becf46a3b1d0e02120af9d926bed2b28ed8a2b8307b3da2a171b3ee1bc1e6196773b570407df6b4")
	}

	#[test]
	fn smoky_pghr() {
		let js = JoinSplit {
			descriptions: vec![
				JoinSplitDescription {
					value_pub_new: 0,
					value_pub_old: 14250000,
					anchor: hash2("d7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd259"),
					nullifiers: [
						hash2("7ae7c48e86173b231e84fbdcb4d8f569f28f71ebf0f9b5867f9d4c12e031a2ac"),
						hash2("c0108235936d2fa2d2c968654fbea2a89fde8522ec7c227d2ff3c10bff9c1197"),
					],
					commitments: [
						hash2("d8a290cca91f23792df8e56aed6c142eaa322e66360b5c49132b940689fb2bc5"),
						hash2("e77f7877bba6d2c4425d9861515cbe8a5c87dfd7cf159e9d4ac9ff63c096fbcd"),
					],
					ephemeral_key: [0u8; 32], // not used
					random_seed: hash2("b1624b703774e138c706ba394698fd33c58424bb1a8d22be0d7bc8fe58d369e8"),
					macs: [
						hash2("9836fe673c246d8d0cb1d7e1cc94acfa5b8d76010db8d53a36a3f0e33f0ccbc0"),
						hash2("f861b5e3d0a92e1c05c6bca775ba7389f6444f0e6cbd34141953220718594664"),
					],
					zkproof: sample_pghr_proof(),
					ciphertexts: [[0u8; 601]; 2],
				}
			],
			pubkey: hash2("cdb0469ee67776480be090cad2c7adc0bf59551ef6f1ac3119e5c29ab3b82dd9").into(),
			sig: [0u8; 64].into(), // not used
		};

		verify(&js.descriptions[0], &js, &vkey(), &dummy_groth16_key()).unwrap();
	}

	fn sample_groth_proof() -> JoinSplitProof {
		groth16_proof("989f643de6f823b5b7e7426ceec93f6477ce53a271b081a8f71736dd0e8cfb6906886f4de425ebdfa2b881a8a6678d38b5b26ade9f90a37fcf0d1fbb32605d0beaa2c286692ad588084234c85da43ed4968b2a4c651d384f4e37ecad5d0bac9d12bcf179ad359a675868cba94727fd85b486fc2eeb014b86d218870ca91a05e203bd29b660131bf101cbb8c207aba49b815b8cc26a17f5be2337b56f66905cb3437983d23641b4dbcc86b938ffff1bde769f060cdb0a0ba18a16e5503d6d1d32")
	}

	#[test]
	fn smoky_groth() {
		let js = JoinSplit {
			descriptions: vec![
				JoinSplitDescription {
					value_pub_new: 133720000,
					value_pub_old: 0,
					anchor: hash2("3e55eebe5c60dd6aafb9fef2fdca323e67226e64cefdf9f514ad714cdae9f6d4"),
					nullifiers: [
						hash2("5f929761b638f94f536985fff2b25e773b5b11cc798dccfe2edce67fe7b1a21e"),
						hash2("2c363c5285ea14e8ecdc71cb0505c014f2b82a03a70dc0d323ea2e260fc4b15e"),
					],
					commitments: [
						hash2("9821ad363ca35d33981a617bb7f9bccdc013d0719215ce0df9b235ac43d6734d"),
						hash2("47163e67274309197ef177cecb8bf31c4851d2f5cdf828558984401e7680646a"),
					],
					ephemeral_key: [0u8; 32], // not used
					random_seed: hash2("eab222220caeff4a484a7b88fa322392dffb795b2738b467db22f4ac50866e4e"),
					macs: [
						hash2("6555003c2f7e77bc415a184c1c7bb67a6649546ca7181232d0c12395995feecd"),
						hash2("660b7b78c77f68049808cac15ea079e3f12b7abe839b0ee8c80be94362c61179"),
					],
					zkproof: sample_groth_proof(),
					ciphertexts: [[0u8; 601]; 2],
				}
			],
			pubkey: hash2("99a01b54019222b7d1b4ec8b321313b0120fceb63b3915eb2a8434d816c1f8f7").into(),
			sig: [0u8; 64].into(), // not used
		};

		verify(
			&js.descriptions[0],
			&js,
			&vkey(),
			&load_sapling_spend_verifying_key().expect("Known to be good"),
		).unwrap();
	}

}
