#[allow(dead_code)]
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

}