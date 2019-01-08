extern crate blake2_rfc;
extern crate crypto as rcrypto;
extern crate primitives;
extern crate serde_json;
extern crate siphasher;
extern crate bn;
extern crate serde;
extern crate rustc_hex as hex;

pub extern crate bellman;
pub extern crate pairing;
pub extern crate sapling_crypto;

#[macro_use] extern crate serde_derive;

mod json;
mod pghr13;

pub use rcrypto::digest::Digest;
pub use blake2_rfc::blake2b::Blake2b;

use std::hash::Hasher;
use rcrypto::sha1::Sha1;
use rcrypto::sha2::Sha256;
use rcrypto::ripemd160::Ripemd160;
use siphasher::sip::SipHasher24;
use primitives::hash::{H32, H160, H256};

pub use json::groth16::{
	load_sapling_spend_verifying_key, load_sapling_output_verifying_key,
};

pub use pghr13::{
	VerifyingKey as Pghr13VerifyingKey, Proof as Pghr13Proof, verify as pghr13_verify,
	G1, G2, Fr, Group,
};

pub struct Groth16VerifyingKey(pub bellman::groth16::PreparedVerifyingKey<pairing::bls12_381::Bls12>);

pub struct DHash160 {
	sha256: Sha256,
	ripemd: Ripemd160,
}

impl Default for DHash160 {
	fn default() -> Self {
		DHash160 {
			sha256: Sha256::new(),
			ripemd: Ripemd160::new(),
		}
	}
}

impl DHash160 {
	pub fn new() -> Self {
		DHash160::default()
	}
}

impl Digest for DHash160 {
	fn input(&mut self, d: &[u8]) {
		self.sha256.input(d)
	}

	fn result(&mut self, out: &mut [u8]) {
		let mut tmp = [0u8; 32];
		self.sha256.result(&mut tmp);
		self.ripemd.input(&tmp);
		self.ripemd.result(out);
		self.ripemd.reset();
	}

	fn reset(&mut self) {
		self.sha256.reset();
	}

	fn output_bits(&self) -> usize {
		160
	}

	fn block_size(&self) -> usize {
		64
	}
}

pub struct DHash256 {
	hasher: Sha256,
}

impl Default for DHash256 {
	fn default() -> Self {
		DHash256 {
			hasher: Sha256::new(),
		}
	}
}

impl DHash256 {
	pub fn new() -> Self {
		DHash256::default()
	}

	pub fn finish(mut self) -> H256 {
		let mut result = H256::default();
		self.result(&mut *result);
		result
	}
}

impl Digest for DHash256 {
	fn input(&mut self, d: &[u8]) {
		self.hasher.input(d)
	}

	fn result(&mut self, out: &mut [u8]) {
		self.hasher.result(out);
		self.hasher.reset();
		self.hasher.input(out);
		self.hasher.result(out);
	}

	fn reset(&mut self) {
		self.hasher.reset();
	}

	fn output_bits(&self) -> usize {
		256
	}

	fn block_size(&self) -> usize {
		64
	}
}

/// RIPEMD160
#[inline]
pub fn ripemd160(input: &[u8]) -> H160 {
	let mut result = H160::default();
	let mut hasher = Ripemd160::new();
	hasher.input(input);
	hasher.result(&mut *result);
	result
}

/// SHA-1
#[inline]
pub fn sha1(input: &[u8]) -> H160 {
	let mut result = H160::default();
	let mut hasher = Sha1::new();
	hasher.input(input);
	hasher.result(&mut *result);
	result
}

/// SHA-256
#[inline]
pub fn sha256(input: &[u8]) -> H256 {
	let mut result = H256::default();
	let mut hasher = Sha256::new();
	hasher.input(input);
	hasher.result(&mut *result);
	result
}

/// SHA-256
#[inline]
pub fn sha256_compress(left: &[u8], right: &[u8]) -> H256 {
	assert_eq!(left.len(), 32, "sha-256-compress 1st argument should be 32-byte length (half-block)");
	assert_eq!(right.len(), 32, "sha-256-compress 2nd argument should be 32-byte length (half-block)");

	let mut result = H256::default();
	let mut hasher = Sha256::new();
	hasher.input(left);
	hasher.input(right);
	hasher.result_no_padding(&mut *result);
	result
}

/// SHA-256 and RIPEMD160
#[inline]
pub fn dhash160(input: &[u8]) -> H160 {
	let mut result = H160::default();
	let mut hasher = DHash160::new();
	hasher.input(input);
	hasher.result(&mut *result);
	result
}

/// Double SHA-256
#[inline]
pub fn dhash256(input: &[u8]) -> H256 {
	let mut result = H256::default();
	let mut hasher = DHash256::new();
	hasher.input(input);
	hasher.result(&mut *result);
	result
}

/// SipHash-2-4
#[inline]
pub fn siphash24(key0: u64, key1: u64, input: &[u8]) -> u64 {
	let mut hasher = SipHasher24::new_with_keys(key0, key1);
	hasher.write(input);
	hasher.finish()
}

/// Blake2b with personalization.
#[inline]
pub fn blake2b_personal(personalization: &[u8], input: &[u8]) -> H256 {
	let mut hasher = Blake2b::with_params(32, &[], &[], personalization);
	hasher.update(input);
	hasher.finalize().as_bytes().into()
}

/// Data checksum
#[inline]
pub fn checksum(data: &[u8]) -> H32 {
	let mut result = H32::default();
	result.copy_from_slice(&dhash256(data)[0..4]);
	result
}

impl ::std::fmt::Debug for Groth16VerifyingKey {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
		f.write_str("Groth16VerifyingKey")
	}
}

#[cfg(test)]
mod tests {
	use primitives::bytes::Bytes;
	use primitives::hash::H256;
	use super::{ripemd160, sha1, sha256, dhash160, dhash256, siphash24, checksum, sha256_compress};

	#[test]
	fn test_ripemd160() {
		let expected = "108f07b8382412612c048d07d13f814118445acd".into();
		let result = ripemd160(b"hello");
		assert_eq!(result, expected);
	}

	#[test]
	fn test_sha1() {
		let expected = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d".into();
		let result = sha1(b"hello");
		assert_eq!(result, expected);
	}

	#[test]
	fn test_sha256() {
		let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".into();
		let result = sha256(b"hello");
		assert_eq!(result, expected);
	}

	#[test]
	fn test_dhash160() {
		let expected = "b6a9c8c230722b7c748331a8b450f05566dc7d0f".into();
		let result = dhash160(b"hello");
		assert_eq!(result, expected);

		let expected = "865c71bfc7e314709207ab9e7e205c6f8e453d08".into();
		let bytes: Bytes = "210292be03ed9475445cc24a34a115c641a67e4ff234ccb08cb4c5cea45caa526cb26ead6ead6ead6ead6eadac".into();
		let result = dhash160(&bytes);
		assert_eq!(result, expected);
	}

	#[test]
	fn test_dhash256() {
		let expected = "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50".into();
		let result = dhash256(b"hello");
		assert_eq!(result, expected);
	}

	#[test]
	fn test_siphash24() {
		let expected = 0x74f839c593dc67fd_u64;
		let result = siphash24(0x0706050403020100_u64, 0x0F0E0D0C0B0A0908_u64, &[0; 1]);
		assert_eq!(result, expected);
	}

	#[test]
	fn test_checksum() {
		assert_eq!(checksum(b"hello"), "9595c9df".into());
	}


	#[test]
	fn half_empty_compress() {
		let vectors = vec![
			"da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8",
			"dc766fab492ccf3d1e49d4f374b5235fa56506aac2224d39f943fcd49202974c",
			"3f0a406181105968fdaee30679e3273c66b72bf9a7f5debbf3b5a0a26e359f92",
			"26b0052694fc42fdff93e6fb5a71d38c3dd7dc5b6ad710eb048c660233137fab",
			"0109ecc0722659ff83450b8f7b8846e67b2859f33c30d9b7acd5bf39cae54e31",
			"3f909b8ce3d7ffd8a5b30908f605a03b0db85169558ddc1da7bbbcc9b09fd325",
			"40460fa6bc692a06f47521a6725a547c028a6a240d8409f165e63cb54da2d23f",
			"8c085674249b43da1b9a31a0e820e81e75f342807b03b6b9e64983217bc2b38e",
			"a083450c1ba2a3a7be76fad9d13bc37be4bf83bd3e59fc375a36ba62dc620298",
			"1ddddabc2caa2de9eff9e18c8c5a39406d7936e889bc16cfabb144f5c0022682",
			"c22d8f0b5e4056e5f318ba22091cc07db5694fbeb5e87ef0d7e2c57ca352359e",
			"89a434ae1febd7687eceea21d07f20a2512449d08ce2eee55871cdb9d46c1233",
			"7333dbffbd11f09247a2b33a013ec4c4342029d851e22ba485d4461851370c15",
			"5dad844ab9466b70f745137195ca221b48f346abd145fb5efc23a8b4ba508022",
			"507e0dae81cbfbe457fd370ef1ca4201c2b6401083ddab440e4a038dc1e358c4",
			"bdcdb3293188c9807d808267018684cfece07ac35a42c00f2c79b4003825305d",
			"bab5800972a16c2c22530c66066d0a5867e987bed21a6d5a450b683cf1cfd709",
			"11aa0b4ad29b13b057a31619d6500d636cd735cdd07d811ea265ec4bcbbbd058",
			"5145b1b055c2df02b95675e3797b91de1b846d25003c0a803d08900728f2cd6a",
			"0323f2850bf3444f4b4c5c09a6057ec7169190f45acb9e46984ab3dfcec4f06a",
			"671546e26b1da1af754531e26d8a6a51073a57ddd72dc472efb43fcb257cffff",
			"bb23a9bba56de57cb284b0d2b01c642cf79c9a5563f0067a21292412145bd78a",
			"f30cc836b9f71b4e7ee3c72b1fd253268af9a27e9d7291a23d02821b21ddfd16",
			"58a2753dade103cecbcda50b5ebfce31e12d41d5841dcc95620f7b3d50a1b9a1",
			"925e6d474a5d8d3004f29da0dd78d30ae3824ce79dfe4934bb29ec3afaf3d521",
			"08f279618616bcdd4eadc9c7a9062691a59b43b07e2c1e237f17bd189cd6a8fe",
			"c92b32db42f42e2bf0a59df9055be5c669d3242df45357659b75ae2c27a76f50",
			"c0db2a74998c50eb7ba6534f6d410efc27c4bb88acb0222c7906ea28a327b511",
			"d7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd259",
			"b22370106c67a17209f6130bc09f735d83aa2c04fc4fe72ea5d80b216723e7ce",
			"9f67d5f664664c901940eee3d02dd5b3e4b92e7b42820c42fc5159e91b41172a",
			"ac58cd1388fec290d398f1944b564449a63c815880566bd1d189f7839e3b0c8c",
			"5698eae7c8515ed05a70339bdf7c1028e7acca13a4fa97d9538f01ac8d889ae3",
			"2d4995770a76fb93314ca74b3524ea1db5688ad0a76183ea17204a8f024a9f3b",
			"5e8992c1b072c16e9e28a85358fb5fb6901a81587766dadb7aa0b973ded2f264",
			"e95db71e1f7291ba5499461bc715203e29b84bfa4283e3bb7f470a15d0e1584e",
			"41f078bd1824c8a4b71964f394aa595084d8eb17b97a3630433af70d10e0eff6",
			"a1913fe6b20132312f8c1f00ddd63cec7a03f5f1d7d83492fa284c0b5d6320b0",
			"ba9440c4dbfcf55ceb605a5b8990fc11f8ef22870d8d12e130f986491eae84b3",
			"49db2d5e22b8015cae4810d75e54014c5469862738e161ec96ec20218718828a",
			"d4851fb8431edfbb8b1e85ada6895967c2dac87df344992a05faf1ecf836eec9",
			"e4ab9f4470f00cd196d47c75c82e7adaf06fe17e042e3953d93bb5d56d8cd8fb",
			"7e4320434849ecb357f1afaaba21a54400ef2d11cff83b937d87fdafa49f8199",
			"020adc98d96cfbbcca15fc3aa03760ed286686c35b5d92c7cb64a999b394a854",
			"3a26b29fe1acfdd6c6a151bcc3dbcb95a10ebe2f0553f80779569b67b7244e77",
			"ec2d0986e6a0ddf43897b2d4f23bb034f538ffe00827f310dc4963f3267f0bfb",
			"d48073f8819f81f0358e3fc35a047cc74082ae1cb7ee22fb609c01649342d0e6",
			"ad8037601793f172441ecb00dc138d9fc5957125ecc382ec65e36f817dc799fb",
			"ca500a5441f36f4df673d6b8ed075d36dae2c7e6481428c70a5a76b7a9bebce8",
			"422b6ddd473231dc4d56fe913444ccd56f7c61f747ba57ca946d5fef72d840a0",
			"ab41f4ecb7d7089615800e19fcc53b8379ed05ee35c82567095583fd90ff3035",
			"bbf7618248354ceb1bc1fc9dbc42c426a4e2c1e0d443c5683a9256c62ecdc26f",
			"e50ae71479fc8ec569192a13072e011afc249f471af09500ea39f75d0af856bf",
			"e74c0b9220147db2d50a3b58d413775d16c984690be7d90f0bc43d99dba1b689",
			"29324a0a48d11657a51ba08b004879bfcfc66a1acb7ce36dfe478d2655484b48",
			"88952e3d0ac06cb16b665201122249659a22325e01c870f49e29da6b1757e082",
			"cdf879f2435b95af042a3bf7b850f7819246c805285803d67ffbf4f295bed004",
			"e005e324200b4f428c62bc3331e695c373607cd0faa9790341fa3ba1ed228bc5",
			"354447727aa9a53dd8345b6b6c693443e56ef4aeba13c410179fc8589e7733d5",
			"da52dda91f2829c15c0e58d29a95360b86ab30cf0cac8101832a29f38c3185f1",
			"c7da7814e228e1144411d78b536092fe920bcdfcc36cf19d1259047b267d58b5",
			"aba1f68b6c2b4db6cc06a7340e12313c4b4a4ea6deb17deb3e1e66cd8eacf32b",
			"c160ae4f64ab764d864a52ad5e33126c4b5ce105a47deedd75bc70199a5247ef",
			"eadf23fc99d514dd8ea204d223e98da988831f9b5d1940274ca520b7fb173d8a",
			"5b8e14facac8a7c7a3bfee8bae71f2f7793d3ad5fe3383f93ab6061f2a11bb02"
		];

		let mut next = H256::from(&[0u8; 32][..]);

		for idx in 0..vectors.len() {
			next = sha256_compress(&next[..], &next[..]);
			assert_eq!(next, H256::from(vectors[idx]));
		}
	}
}
