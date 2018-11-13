// https://github.com/zcash/zcash/commit/fdda3c5085199d2c2170887aa064fc42afdb0360

use blake2_rfc::blake2b::Blake2b;
use byteorder::{BigEndian, LittleEndian, ByteOrder};
use chain::BlockHeader;

#[allow(non_snake_case)]
pub struct EquihashParams {
	pub N: u32,
	pub K: u32,
}

impl EquihashParams {
	pub fn indices_per_hash_output(&self) -> usize {
		(512 / self.N) as usize
	}

	pub fn hash_output(&self) -> usize {
		(self.indices_per_hash_output() * self.N as usize / 8usize) as usize
	}

	pub fn collision_bit_length(&self) -> usize {
		(self.N / (self.K + 1)) as usize
	}

	pub fn collision_byte_length(&self) -> usize {
		(self.collision_bit_length() + 7) / 8
	}

	pub fn final_full_width(&self) -> usize {
		2 * self.collision_byte_length() + 4 * (1 << self.K)
	}

	pub fn solution_size(&self) -> usize {
		((1usize << self.K) * (self.collision_bit_length() + 1) / 8) as usize
	}

	pub fn hash_length(&self) -> usize {
		(self.K as usize + 1) * self.collision_byte_length()
	}
}

pub fn verify_block_equihash_solution(params: &EquihashParams, header: &BlockHeader) -> bool {
	let equihash_solution = header.solution.as_ref();
	let input = header.equihash_input();
	verify_equihash_solution(params, &input, equihash_solution)
}

pub fn verify_equihash_solution(params: &EquihashParams, input: &[u8], solution: &[u8]) -> bool {
	if solution.len() != params.solution_size() {
		return false;
	}

	let mut context = new_blake2(params);
	context.update(input);

	// pure equihash

	let collision_bit_length = params.collision_bit_length();
	let indices = get_indices_from_minimal(solution, collision_bit_length);

	let mut rows = Vec::new();
	for idx in indices {
		let hash = generate_hash(&context, (idx as usize / params.indices_per_hash_output()) as u32);
		let hash_begin = (idx as usize % params.indices_per_hash_output()) * params.N as usize / 8;
		let hash_end = hash_begin + params.N as usize / 8;

		let mut row = vec![0; params.final_full_width()];
		let expanded_hash = expand_array(
			&hash[hash_begin..hash_end],
			params.collision_bit_length(),
			0);
		row[0..expanded_hash.len()].clone_from_slice(&expanded_hash);
		row[params.hash_length()..params.hash_length() + 4].clone_from_slice(&to_big_endian(idx));
		rows.push(row);
	}

	let mut hash_len = params.hash_length();
	let mut indices_len = 4;
	while rows.len() > 1 {
		let mut rows_check = Vec::new();
		for i in 0..rows.len() / 2 {
			let row1 = &rows[i * 2];
			let row2 = &rows[i * 2 + 1];
			if !has_collision(row1, row2, params.collision_byte_length()) {
				return false;
			}
			if indices_before(row2, row1, hash_len, indices_len) {
				return false;
			}
			if !distinct_indices(row1, row2, hash_len, indices_len) {
				return false;
			}
			rows_check.push(merge_rows(row1, row2, hash_len, indices_len, params.collision_byte_length()));
		}

		rows = rows_check;
		hash_len -= params.collision_byte_length();
		indices_len *= 2;
	}

	rows[0].iter().take(hash_len).all(|x| *x == 0)
}

fn merge_rows(row1: &[u8], row2: &[u8], len: usize, indices_len: usize, trim: usize) -> Vec<u8> {
	let mut row = row1.to_vec();
	for i in trim..len {
		row[i - trim] = row1[i] ^ row2[i];
	}

	if indices_before(row1, row2, len, indices_len) {
		row[len - trim..len - trim + indices_len]
			.clone_from_slice(&row1[len..len + indices_len]);
		row[len - trim + indices_len..len - trim + indices_len + indices_len]
			.clone_from_slice(&row2[len..len + indices_len]);
	} else {
		row[len - trim..len - trim + indices_len]
			.clone_from_slice(&row2[len..len + indices_len]);
		row[len - trim + indices_len..len - trim + indices_len + indices_len]
			.clone_from_slice(&row1[len..len + indices_len]);
	}

	row
}

fn distinct_indices(row1: &[u8], row2: &[u8], len: usize, indices_len: usize) -> bool {
	let mut i = 0;
	let mut j = 0;
	while i < indices_len {
		while j < indices_len {
			if row1[len + i..len + i + 4] == row2[len + j..len + j + 4] {
				return false;
			}

			j += 4;
		}

		i += 4;
	}

	true
}

fn has_collision(row1: &[u8], row2: &[u8], collision_byte_length: usize) -> bool {
	for i in 0..collision_byte_length {
		if row1[i] != row2[i] {
			return false;
		}
	}

	true
}

fn indices_before(row1: &[u8], row2: &[u8], len: usize, indices_len: usize) -> bool {
	for i in 0..indices_len {
		if row1[len + i] < row2[len + i] {
			return true;
		} else if row1[len + i] > row2[len + i] {
			return false;
		}
	}

	false
}

fn generate_hash(context: &Blake2b, g: u32) -> Vec<u8> {
	let mut context = context.clone();
	context.update(&to_little_endian(g));
	context.finalize().as_bytes().to_vec()
}

fn get_indices_from_minimal(solution: &[u8], collision_bit_length: usize) -> Vec<u32> {
	let indices_len = 8 * 4 * solution.len() / (collision_bit_length + 1);
	let byte_pad = 4 - ((collision_bit_length + 1 + 7) / 8);
	let array = expand_array(solution, collision_bit_length + 1, byte_pad);

	let mut ret = Vec::new();
	for i in 0..indices_len / 4 {
		ret.push(array_to_eh_index(&array[i*4..i*4 + 4]));
	}
	ret
}

fn array_to_eh_index(data: &[u8]) -> u32 {
	BigEndian::read_u32(data)
}

fn expand_array(data: &[u8], bit_len: usize, byte_pad: usize) -> Vec<u8> {
	let mut array = Vec::new();
	let out_width = (bit_len + 7) / 8 + byte_pad;
	let bit_len_mask = (1u32 << bit_len) - 1;

	// The acc_bits least-significant bits of acc_value represent a bit sequence
	// in big-endian order.
	let mut acc_bits = 0usize;
	let mut acc_value = 0u32;

	for i in 0usize..data.len() {
		acc_value = (acc_value << 8) | (data[i] as u32);
		acc_bits += 8;

		// When we have bit_len or more bits in the accumulator, write the next
		// output element.
		if acc_bits >= bit_len {
			acc_bits -= bit_len;
			for _ in 0usize..byte_pad {
				array.push(0);
			}
			for x in byte_pad..out_width {
				array.push((
					// Big-endian
					(acc_value >> (acc_bits + (8 * (out_width - x - 1)))) as u8
				) & (
					// Apply bit_len_mask across byte boundaries
					((bit_len_mask >> (8 * (out_width - x - 1))) & 0xFF) as u8
				));
			}
		}
	}

	array
}

fn new_blake2(params: &EquihashParams) -> Blake2b {
	let mut personalization = [0u8; 16];
	personalization[0..8].clone_from_slice(b"ZcashPoW");
	personalization[8..12].clone_from_slice(&to_little_endian(params.N));
	personalization[12..16].clone_from_slice(&to_little_endian(params.K));
	Blake2b::with_params(params.hash_output(), &[], &[], &personalization)
}

fn to_little_endian(num: u32) -> [u8; 4] {
	let mut le_num = [0u8; 4];
	LittleEndian::write_u32(&mut le_num[..], num);
	le_num
}

fn to_big_endian(num: u32) -> [u8; 4] {
	let mut be_num = [0u8; 4];
	BigEndian::write_u32(&mut be_num[..], num);
	be_num
}

#[cfg(test)]
mod tests {
	use primitives::bigint::{U256, Uint};
	use byteorder::WriteBytesExt;
	use super::*;

	fn get_minimal_from_indices(indices: &[u32], collision_bit_length: usize) -> Vec<u8> {
		let indices_len = indices.len() * 4;
		let min_len = (collision_bit_length + 1) * indices_len / (8 * 4);
		let byte_pad = 4 - ((collision_bit_length + 1) + 7) / 8;

		let mut array = Vec::new();
		for i in 0..indices.len() {
			let mut be_index = Vec::new();
			be_index.write_u32::<BigEndian>(indices[i]).unwrap();
			array.extend(be_index);
		}

		let mut ret = vec![0u8; min_len];
		compress_array(&array, &mut ret, collision_bit_length + 1, byte_pad);
		ret
	}

	fn compress_array(data: &[u8], array: &mut Vec<u8>, bit_len: usize, byte_pad: usize) {
		let in_width = (bit_len + 7) / 8 + byte_pad;
		let bit_len_mask = (1u32 << bit_len) - 1;

		// The acc_bits least-significant bits of acc_value represent a bit sequence
		// in big-endian order.
		let mut acc_bits = 0usize;
		let mut acc_value = 0u32;

		let mut j = 0usize;
		for i in 0usize..array.len() {
			// When we have fewer than 8 bits left in the accumulator, read the next
			// input element.
			if acc_bits < 8 {
				acc_value = acc_value << bit_len;
				for x in byte_pad..in_width {
					acc_value = acc_value | ((
						data[j + x] & (((bit_len_mask >> (8 * (in_width - x - 1))) & 0xFF) as u8)
					) as u32) << (8 * (in_width - x - 1));
				}
				j += in_width;
				acc_bits += bit_len;
			}

			acc_bits -= 8;
			array[i] = ((acc_value >> acc_bits) & 0xFF) as u8;
		}
	}



	fn test_equihash_verifier(n: u32, k: u32, input: &[u8], nonce: U256, solution: &[u32]) -> bool {
		let solution = get_minimal_from_indices(solution, (n / (k + 1)) as usize);

		let mut le_nonce = vec![0; 32];
		nonce.to_little_endian(&mut le_nonce);
		let mut input = input.to_vec();
		input.extend(le_nonce);

		let params = EquihashParams { N: n, K: k };

		verify_equihash_solution(&params, &input, &solution)
	}

	#[test]
	fn verify_equihash_solution_works() {
		assert!(test_equihash_verifier(
			96, 5, b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
			U256::one(), &vec![
				2261, 15185, 36112, 104243, 23779, 118390, 118332, 130041, 32642, 69878, 76925, 80080, 45858, 116805, 92842, 111026, 15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132, 23460, 49807, 52426, 80391, 69567, 114474, 104973, 122568,
			],
		));
	}
}
