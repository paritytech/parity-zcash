pub use bn::{Fr, G1, G2, Group};
use bn::pairing;

#[derive(Clone)]
pub struct VerifyingKey {
	pub a: G2,
	pub b: G1,
	pub c: G2,
	pub z: G2,
	pub gamma: G2,
	pub gamma_beta_1: G1,
	pub gamma_beta_2: G2,
	pub ic: Vec<G1>,
}

impl ::std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
		write!(f, "[Verifying Key: TODO]")
	}
}

#[derive(Clone)]
pub struct Proof {
	pub a: G1,
	pub a_prime: G1,
	pub b: G2,
	pub b_prime: G1,
	pub c: G1,
	pub c_prime: G1,
	pub k: G1,
	pub h: G1,
}

pub fn verify(vk: &VerifyingKey, primary_input: &[Fr], proof: &Proof) -> bool {
	let p2 = G2::one();

	// 1. compute accumulated input circuit (evaluate the polynomial)
	let mut acc = vk.ic[0];
	for (&x, &ic) in primary_input.iter().zip(vk.ic[1..].iter()) {
		acc = acc + (ic * x);
	}

	// 2. check validity of knowledge commitments for A, B, C:
	pairing(proof.a, vk.a) == pairing(proof.a_prime, p2) &&
	pairing(vk.b, proof.b) == pairing(proof.b_prime, p2) &&
	pairing(proof.c, vk.c) == pairing(proof.c_prime, p2) &&

	// 3. check same coefficients were used:
	pairing(proof.k, vk.gamma) ==
	pairing(acc + proof.a + proof.c, vk.gamma_beta_2) * pairing(vk.gamma_beta_1, proof.b) &&

	// 4. check QAP divisibility
	pairing(acc + proof.a, proof.b) == pairing(proof.h, vk.z) * pairing(proof.c, p2)
}