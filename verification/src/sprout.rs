
// blake2 hash of ('ZcashComputehSig', random_seed, nullifier[0], nullifier[1], pub_key_hash)
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
		let bytes: Vec<u8> = s.from_hex().expect(&format!("hash '{}' is not actually a hash somehow", s));
		assert_eq!(bytes.len(), 32);
		let mut result = [0u8; 32];
		result.copy_from_slice(&bytes[..]);
		result
	}

	fn reversed_hash(s: &'static str) -> [u8; 32] {
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
			reversed_hash("a8cba69f1fa329c055756b4af900f8a00b61e44f4cb8a1824ceb58b90a5b8113"),
		);
	}

}