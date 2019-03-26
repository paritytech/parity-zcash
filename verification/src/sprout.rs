
// blake2 hash of (random_seed, nullifier[0], nullifier[1], pub_key_hash) with 'ZcashComputehSig' personal token
pub fn compute_hsig(random_seed: [u8; 32], nullifiers: [[u8; 32]; 2], pub_key_hash: [u8; 32]) -> [u8; 32] {
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

#[derive(Debug, Clone)]
pub struct Input {
	bits: bitvec::BitVec,
}

impl Input {
	fn new(size: usize) -> Self {
		Input { bits: bitvec::BitVec::with_capacity(size) }
	}

	fn push_u256(&mut self, val: crypto::BnU256) {
		for i in 0..256 {
			self.bits.push(val.get_bit(i).expect("for 0..256 index range will always return some; qeed"))
		}
	}

	fn push_u64(&mut self, val: u64) {
		for i in 0..64 {
			self.bits.push(val & (1 << (63-i)) > 0)
		}
	}

	#[cfg(test)]
	pub(crate) fn bits(&self) -> &bitvec::BitVec {
		&self.bits
	}

	pub fn into_frs(self) -> Vec<crypto::Fr> {
		let mut res = Vec::new();
		let mut u256 = crypto::BnU256::zero();
		for i in 0..self.bits.len() {
			u256.set_bit(i % 256, self.bits[i]);
			if i % 256 == 255 {
				res.push(crypto::Fr::new_mul_factor(u256));
			}
		}
		if self.bits.len() % 256 != 0 {
			res.push(crypto::Fr::new_mul_factor(u256));
		}

		res
	}
}

#[cfg(test)]
mod tests {

	use super::compute_hsig;

	fn hash(s: &'static str) -> [u8; 32] {
		use hex::FromHex;
		let mut bytes: Vec<u8> = s.from_hex().expect(&format!("hash '{}' is not actually a hash somehow", s));
		bytes.reverse();
		assert_eq!(bytes.len(), 32);
		let mut result = [0u8; 32];
		result.copy_from_slice(&bytes[..]);
		result
	}

	#[test]
	fn test_vectors() {
		assert_eq!(
			compute_hsig(
				hash("6161616161616161616161616161616161616161616161616161616161616161"),
				[
					hash("6262626262626262626262626262626262626262626262626262626262626262"),
					hash("6363636363636363636363636363636363636363636363636363636363636363"),
				],
				hash("6464646464646464646464646464646464646464646464646464646464646464"),
			),
			hash("a8cba69f1fa329c055756b4af900f8a00b61e44f4cb8a1824ceb58b90a5b8113"),
		);

		assert_eq!(
			compute_hsig(
				hash("0000000000000000000000000000000000000000000000000000000000000000"),
				[
					hash("0000000000000000000000000000000000000000000000000000000000000000"),
					hash("0000000000000000000000000000000000000000000000000000000000000000"),
				],
				hash("0000000000000000000000000000000000000000000000000000000000000000"),
			),
			hash("697322276b5dd93b12fb1fcbd2144b2960f24c73aac6c6a0811447be1e7f1e19"),
		);

		assert_eq!(
			compute_hsig(
				hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
				[
					hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
					hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
				],
				hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
			),
			hash("b61110ec162693bc3d9ca7fb0eec3afd2e278e2f41394b3ff11d7cb761ad4b27"),
		);

		assert_eq!(
			compute_hsig(
				hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
				[
					hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
					hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
				],
				hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
			),
			hash("4961048919f0ca79d49c9378c36a91a8767060001f4212fe6f7d426f3ccf9f32"),
		);


		assert_eq!(
			compute_hsig(
				hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
				[
					hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
					hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
				],
				hash("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
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
	fn inputs() {
		let mut inputs = super::Input::new(128);
		inputs.push_u64(0x6dea2059e200bd39);
		inputs.push_u64(0xa953d79b83f6ab59);
		assert_eq!(
			&input_to_str(&inputs),
			"01101101111010100010000001011001111000100000000010111101001110011010100101010011110101111001101110000011111101101010101101011001"
		);
	}
}