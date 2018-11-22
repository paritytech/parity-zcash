extern crate bn;

use bn::{pairing, Fr, G1, G2, Group};

struct VerifyingKey {
	a: G2,
	b: G1,
	c: G2,
	z: G2,
	gamma: G2,
	gamma_beta_1: G1,
	gamma_beta_2: G2,
	ic: Vec<G1>,
}

struct Proof {
	a: G1,
	a_prime: G1,
	b: G2,
	b_prime: G1,
	c: G1,
	c_prime: G1,
	k: G1,
	h: G1,
}

fn verify(vk: &VerifyingKey, primary_input: &[Fr], proof: &Proof) -> bool {
	let p2 = G2::one();

	// 1. compute accumulated input circuit
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