// https://github.com/zcash/zcash/commit/fdda3c5085199d2c2170887aa064fc42afdb0360

use blake2_rfc::blake2b::Blake2b;

pub struct EquihashParams {
	pub N: u32,
	pub K: u32,
}

impl EquihashParams {
	pub fn collision_bit_length(&self) -> usize {
		self.N / (self.K + 1)
	}

	pub fn solution_size(&self) -> usize {
		(1usize << self.K) * (self.collision_bit_length() + 1) / 8
	}
}

pub fn verify_equihash_solution(params: &EquihashParams, input: &[u8], solution: &[u8]) -> bool {
	if solution.len() != params.solution_size() {
		return false;
	}

	let mut context = Blake2b::new(64);
	context.update(input);
}

fn get_indices_from_minimal(solution: &[u8], collision_bit_length: usize) -> Vec<u32> {
	let indices_len = 8 * 4 * solution.len() / (collision_bit_length + 1);
	let byte_pad = 4 - ((collision_bit_length + 1 + 7) / 8);
	let mut array = Vec::new();
}

fn expand_array(data: &[u8], array: &mut Vec<u8>, bit_len: usize, byte_pad: usize) {
	
}

#[cfg(test)]
mod tests {
	fn test_equihash_verifier(n: u32, k: u32, input: &[u8], nonce: U256, solution: &[u32]) -> bool {

	}
	void TestEquihashValidator(unsigned int n, unsigned int k, const std::string &I, const arith_uint256 &nonce, std::vector<uint32_t> soln, bool expected) {

	#[test]
	fn verify_equihash_solution_works() {
		test_equihash_verifier(
			96, 5, "Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
			U256::one(), 
		);
	}
}