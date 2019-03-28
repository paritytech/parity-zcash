use chain::BlockHeader;
use crypto::Blake2b;

/// Verify equihash solution of the block header.
pub fn verify_block_equihash_solution(params: (u32, u32), header: &BlockHeader) -> bool {
	debug_assert_eq!(
		params,
		(OnChainEquihash::N, OnChainEquihash::K),
		"Wrong equihash parameters specified in consensus",
	);

	verify_equihash_solution::<OnChainEquihash>(
		&header.equihash_input(),
		header.solution.as_ref(),
	)
}

/// Equihash algorithm instance.
///
/// A brief, yet incomplete overview of the algorithm:
/// (1) prepare indexed set of 2^(N / (K + 1) + 1) N-bits strings (BSTR);
/// (2) select 2^K BSTRs from this set, such that their' XOR is zero;
/// (3) solution is indices of selected BSTRs.
///
/// In case of Zcash Equihash, the BSTR is the hash of block header (excluding solution itself) ++
/// the hash index. The hash could be/is splitted into several BSTRs, which are used as the input
/// for the Wagner's Generalized Birthday problem algorithm.
///
/// The Wagner's algorithm (https://people.eecs.berkeley.edu/~daw/papers/genbday-long.ps) itself
/// works with paded BSTRs (rows).
trait Equihash {
	/// Parameter N of Equihash algorithm.
	const N: u32;
	/// Parameter K of Equihash algorithm.
	const K: u32;
	/// Blake2b personalization used by the algorithm instance.
	const BLAKE2B_PERSONALIZATION: [u8; 16];

	/// The number of N-bit BSTRs that could be generated from the single computed hash.
	const BSTRS_PER_HASH: usize = (512 / Self::N) as usize;
	/// The size required to fit of every BSTR.
	const HASH_SIZE: usize = Self::BSTRS_PER_HASH * (Self::N as usize) / 8;
	/// Number of bits required to store single BSTR index.
	const BSTR_INDEX_BITS: usize = (Self::N / (Self::K + 1)) as usize;
	/// Number of bytes required to store single BSTR index (there could be extra bits in
	/// binary representation of the index).
	const BSTR_INDEX_BYTES: usize = (Self::BSTR_INDEX_BITS + 7) / 8;
	/// Number of BSTR indices in solution.
	const BSTR_INDICES_IN_SOLUTION: usize = 1usize << Self::K;
	/// The size (in bytes) of compressed Equihash solution (compressed array of BE-encoded BSTRs indices).
	const SOLUTION_COMPRESSED_SIZE: usize = Self::BSTR_INDICES_IN_SOLUTION * (Self::BSTR_INDEX_BITS + 1) / 8;
	/// Number of leading zero bytes to pad compressed BSTR index to fit into u32.
	const SOLUTION_PAD_BYTES: usize = 4 - (Self::BSTR_INDEX_BITS + 8) / 8;
	/// The size (in bytes) of single row used by Wagner algorithm.
	const ROW_SIZE: usize = 2 * Self::BSTR_INDEX_BYTES + 4 * Self::BSTR_INDICES_IN_SOLUTION;
	/// The size (in bytes) of the hash part of the row.
	const ROW_HASH_LENGTH: usize = (Self::K as usize + 1) * Self::BSTR_INDEX_BYTES;

	/// Type of hash (bytes of HASH_SIZE length). This should be [u8; Self::HASH_SIZE] when Rust will be able
	/// to interpret this.
	type Hash: Default + AsRef<[u8]> + AsMut<[u8]>;
}

/// Equihash algorithm instance that is used by all Zcash chains.
struct OnChainEquihash;

impl Equihash for OnChainEquihash {
	const N: u32 = 200;
	const K: u32 = 9;
	const BLAKE2B_PERSONALIZATION: [u8; 16] = [
		0x5a, 0x63, 0x61, 0x73, 0x68, 0x50, 0x6f, 0x57,		// b"ZcashPoW"
		0xc8, 0x00, 0x00, 0x00,								// LE(N)
		0x09, 0x00, 0x00, 0x00,								// LE(K)
	];

	type Hash = self::on_chain_equihash::Hash;
}

/// Verify equihash solution.
fn verify_equihash_solution<Algorithm: Equihash>(
	input: &[u8],
	solution: &[u8],
) -> bool {
	// prepare Blake2b context with personalization
	let mut context = Blake2b::with_params(Algorithm::HASH_SIZE, &[], &[], &Algorithm::BLAKE2B_PERSONALIZATION);
	context.update(input);

	// we're using two dynamic vectors here && swap pointers when required
	// for on-chain algorithm instance:
	// sizeof(*rows1) ~ 512 * 2054 ~ 1M
	// sizeof(*rows2) ~ 256 * 2054 ~ 512K
	let mut rows1 = vec![0u8; Algorithm::BSTR_INDICES_IN_SOLUTION * Algorithm::ROW_SIZE];
	let mut rows2 = vec![0u8; Algorithm::BSTR_INDICES_IN_SOLUTION * Algorithm::ROW_SIZE / 2];

	let mut current_rows = &mut rows1;
	let mut backup_rows = &mut rows2;

	let mut hash = Algorithm::Hash::default();
	let mut current_rows_pos = 0;
	for_each_solution_index::<Algorithm, _>(
		solution,
		&mut |index| {
			let hash_half_index = (index as usize / Algorithm::BSTRS_PER_HASH) as u32;
			generate_hash(&context, hash_half_index, hash.as_mut());

			let hash_begin = (index as usize % Algorithm::BSTRS_PER_HASH) * Algorithm::N as usize / 8;
			let hash_end = hash_begin + Algorithm::N as usize / 8;
			let sub_hash = &hash.as_ref()[hash_begin..hash_end];

			let mut current_rows_sub_pos = current_rows_pos;
			expand_array(
				sub_hash,
				Algorithm::BSTR_INDEX_BITS,
				0,
				&mut |buffer: &[u8; 4]| {
					current_rows[current_rows_sub_pos..current_rows_sub_pos+Algorithm::BSTR_INDEX_BYTES]
						.copy_from_slice(&buffer[0..Algorithm::BSTR_INDEX_BYTES]);
					current_rows_sub_pos += Algorithm::BSTR_INDEX_BYTES;
				},
			);
			current_rows[current_rows_pos+Algorithm::ROW_HASH_LENGTH..current_rows_pos+Algorithm::ROW_HASH_LENGTH+4]
				.copy_from_slice(&index.to_be_bytes());
			current_rows_pos += Algorithm::ROW_SIZE;
		}
	);

	let mut hash_len = Algorithm::ROW_HASH_LENGTH;
	let mut indices_len = 4;
	let mut current_rows_count = current_rows.len() / Algorithm::ROW_SIZE;
	loop {
		if current_rows_count <= 1 {
			break;
		}

		let mut current_row_begin = 0;
		let mut current_row_end = Algorithm::ROW_SIZE;
		let mut next_row_begin = Algorithm::ROW_SIZE;
		let mut next_row_end = Algorithm::ROW_SIZE + Algorithm::ROW_SIZE;
		let mut merged_row_begin = 0;
		let mut merged_row_end = Algorithm::ROW_SIZE;
		for _ in 0..current_rows_count / 2 {
			let row1 = &current_rows[current_row_begin..current_row_end];
			let row2 = &current_rows[next_row_begin..next_row_end];
			if !has_collision(row1, row2, Algorithm::BSTR_INDEX_BYTES) {
				return false;
			}
			if indices_before(row2, row1, hash_len, indices_len) {
				return false;
			}
			if !distinct_indices(row1, row2, hash_len, indices_len) {
				return false;
			}

			let merged_row = &mut backup_rows[merged_row_begin..merged_row_end];
			merge_rows(row1, row2, merged_row, hash_len, indices_len, Algorithm::BSTR_INDEX_BYTES);

			current_row_begin += Algorithm::ROW_SIZE + Algorithm::ROW_SIZE;
			current_row_end += Algorithm::ROW_SIZE + Algorithm::ROW_SIZE;
			next_row_begin += Algorithm::ROW_SIZE + Algorithm::ROW_SIZE;
			next_row_end += Algorithm::ROW_SIZE + Algorithm::ROW_SIZE;
			merged_row_begin += Algorithm::ROW_SIZE;
			merged_row_end += Algorithm::ROW_SIZE;
		}

		::std::mem::swap(&mut current_rows, &mut backup_rows);
		hash_len -= Algorithm::BSTR_INDEX_BYTES;
		indices_len *= 2;
		current_rows_count /= 2;
	}

	current_rows[0..Algorithm::ROW_SIZE].iter().take(hash_len).all(|x| *x == 0)
}

fn for_each_solution_index<Algorithm, ForEach>(solution: &[u8], for_each: &mut ForEach)
	where
		Algorithm: Equihash,
		ForEach: FnMut(u32),
{
	// consensus parameters enforces this
	debug_assert_eq!(
		solution.len(),
		Algorithm::SOLUTION_COMPRESSED_SIZE,
		"Wrong equihash parameters specified in consensus",
	);

	expand_array(
		solution,
		Algorithm::BSTR_INDEX_BITS + 1,
		Algorithm::SOLUTION_PAD_BYTES,
		&mut |buffer: &[u8; 4]| for_each(u32::from_be_bytes(*buffer)),
	);
}

fn expand_array<E: FnMut(&[u8; 4])>(
	compressed: &[u8],
	blen: usize,
	pad: usize,
	expand_single: &mut E,
) {
	let out_width = (blen + 7) / 8 + pad;
	let blen_mask = (1u32 << blen) - 1;

	// The acc_bits least-significant bits of acc_value represent a bit sequence
	// in big-endian order.
	let mut acc_buffer = [0u8; 4];
	let mut acc_bits = 0usize;
	let mut acc_value = 0u32;

	for i in 0usize..compressed.len() {
		acc_value = (acc_value << 8) | (compressed[i] as u32);
		acc_bits += 8;

		// When we have bit_len or more bits in the accumulator, write the next
		// output element.
		if acc_bits >= blen {
			acc_bits -= blen;
			for x in pad..out_width {
				acc_buffer[x] = (
					// Big-endian
					(acc_value >> (acc_bits + (8 * (out_width - x - 1)))) as u8
				) & (
					// Apply blen_mask across byte boundaries
					((blen_mask >> (8 * (out_width - x - 1))) & 0xFF) as u8
				);
			}

			expand_single(&acc_buffer)
		}
	}
}

fn generate_hash(context: &Blake2b, index: u32, hash: &mut [u8]) {
	let mut context = context.clone();
	context.update(&index.to_le_bytes());
	hash.copy_from_slice(context.finalize().as_bytes())
}

fn merge_rows(row1: &[u8], row2: &[u8], merged_row: &mut [u8], len: usize, indices_len: usize, trim: usize) {
	let mut merged_row_pos = 0;
	for i in trim..len {
		merged_row[merged_row_pos] = row1[i] ^ row2[i];
		merged_row_pos += 1;
	}

	if indices_before(row1, row2, len, indices_len) {
		merged_row[len - trim..len - trim + indices_len]
			.clone_from_slice(&row1[len..len + indices_len]);
		merged_row[len - trim + indices_len..len - trim + indices_len + indices_len]
			.clone_from_slice(&row2[len..len + indices_len]);
	} else {
		merged_row[len - trim..len - trim + indices_len]
			.clone_from_slice(&row2[len..len + indices_len]);
		merged_row[len - trim + indices_len..len - trim + indices_len + indices_len]
			.clone_from_slice(&row1[len..len + indices_len]);
	}
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

mod on_chain_equihash {
	pub struct Hash(pub [u8; 50]);

	impl Default for Hash {
		fn default() -> Self { Hash([0; 50]) }
	}

	impl AsRef<[u8]> for Hash {
		fn as_ref(&self) -> &[u8] { &self.0 }
	}

	impl AsMut<[u8]> for Hash {
		fn as_mut(&mut self) -> &mut [u8] { &mut self.0 }
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use primitives::bigint::U256;

	struct TestEquihash;

	impl Equihash for TestEquihash {
		const N: u32 = 96;
		const K: u32 = 5;
		const BLAKE2B_PERSONALIZATION: [u8; 16] = [
			0x5a, 0x63, 0x61, 0x73, 0x68, 0x50, 0x6f, 0x57,		// b"ZcashPoW"
			0x60, 0x00, 0x00, 0x00,								// LE(N)
			0x05, 0x00, 0x00, 0x00,								// LE(K)
		];

		type Hash = TestHash;
	}

	struct TestHash(pub [u8; 60]);

	impl Default for TestHash {
		fn default() -> Self { TestHash([0; 60]) }
	}

	impl AsRef<[u8]> for TestHash {
		fn as_ref(&self) -> &[u8] { &self.0 }
	}

	impl AsMut<[u8]> for TestHash {
		fn as_mut(&mut self) -> &mut [u8] { &mut self.0 }
	}

	fn get_minimal_from_indices(indices: &[u32], collision_bit_length: usize) -> Vec<u8> {
		let indices_len = indices.len() * 4;
		let min_len = (collision_bit_length + 1) * indices_len / (8 * 4);
		let byte_pad = 4 - ((collision_bit_length + 1) + 7) / 8;

		let mut array = Vec::new();
		for index in indices.iter() {
			array.extend_from_slice(&index.to_be_bytes());
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

	fn test_equihash_verifier(input: &[u8], nonce: U256, solution: &[u32]) -> bool {
		let solution = get_minimal_from_indices(solution, TestEquihash::BSTR_INDEX_BITS);

		let mut le_nonce = vec![0; 32];
		nonce.to_little_endian(&mut le_nonce);
		let mut input = input.to_vec();
		input.extend(le_nonce);

		verify_equihash_solution::<TestEquihash>(&input, &solution)
	}

	#[test]
	fn verify_equihash2_solution_works() {
		assert!(test_equihash_verifier(
			b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
			U256::one(), &vec![
				2261, 15185, 36112, 104243, 23779, 118390, 118332, 130041, 32642, 69878, 76925, 80080, 45858, 116805, 92842, 111026, 15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132, 23460, 49807, 52426, 80391, 69567, 114474, 104973, 122568,
			],
		));
	}

	#[test]
	fn test_equihash2_on_real_block() {
		let block = test_data::block_h170();
		assert!(verify_block_equihash_solution((200, 9), &block.block_header));
	}
}
