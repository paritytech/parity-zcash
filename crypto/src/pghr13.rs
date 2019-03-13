pub use bn::{Fr, Fq, Fq2, G1, G2, Group, arith::U256, AffineG1};
use bn::pairing;
use std::ops::Neg;

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

#[derive(Debug)]
pub enum Error {
	InvalidFieldElement,
	InvalidCurvePoint,
	InvalidRawInput,
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

lazy_static! {
	pub static ref FQ: U256 = U256::from([
        0x3c208c16d87cfd47,
        0x97816a916871ca8d,
        0xb85045b68181585d,
        0x30644e72e131a029
    ]);

	pub static ref G1_B: Fq = Fq::from_u256(3.into()).expect("3 is a valid field element and static; qed");

	pub static ref FQ_MINUS3_DIV4: Fq =
		Fq::from_u256(3.into()).expect("3 is a valid field element and static; qed").neg() *
		Fq::from_u256(4.into()).expect("4 is a valid field element and static; qed").inverse()
			.expect("4 has inverse in Fq and is static; qed");

	pub static ref FQ_MINUS1_DIV2: Fq =
		Fq::from_u256(1.into()).expect("1 is a valid field element and static; qed").neg() *
		Fq::from_u256(2.into()).expect("2 is a valid field element and static; qed").inverse()
			.expect("2 has inverse in Fq and is static; qed");

}

// Shanks’s algorithm for q ≡ 3 (mod 4)
// (FQ mod 4 = 3)
fn fq_sqrt(a: Fq) -> Option<Fq> {
	let a1 = a.pow(*FQ_MINUS3_DIV4);
	let a1a = a1 * a;
	let a0 = a1 * (a1a);

	let mut am1 = *FQ;
	am1.sub(&1.into(), &*FQ);

	if a0 == Fq::from_u256(am1).unwrap() {
		None
	} else {
		Some(a1a)
	}
}

fn fq2_sqrt(a: Fq2) -> Option<Fq2> {
	let a1 = a.pow(FQ_MINUS3_DIV4.into_u256());
	let a1a = a1 * a;
	let alpha = a1 * a1a;
	let a0 = alpha.pow(*FQ) * alpha;

	if a0 == Fq2::one().neg() {
		return None;
	}

	if alpha == Fq2::one().neg() {
		Some(Fq2::i() * a1a)
	} else {
		let b = (alpha + Fq2::one()).pow(FQ_MINUS1_DIV2.into_u256());
		Some(b * a1a)
	}
}


fn g1_from_compressed(data: &[u8]) -> Result<G1, Error> {
	if data.len() != 33 { return Err(Error::InvalidRawInput); }

	let sign = data[0];
	let fq = deseerialize_fq(&data[1..])?;
	let x = fq;
	let y_squared = (fq * fq * fq) + *G1_B;
	let mut y = fq_sqrt(y_squared).ok_or(Error::InvalidFieldElement)?;

	if sign == 2 { y = y.neg(); }

	AffineG1::new(x, y).map_err(|_| Error::InvalidCurvePoint).map(Into::into)
}

fn deseerialize_fq(data: &[u8]) -> Result<Fq, Error> {
	Ok(Fq::from_slice(data).map_err(|_| Error::InvalidRawInput)?)
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

#[cfg(test)]
mod tests {

	use super::*;

	fn hex(s: &'static str) -> Vec<u8> {
		use hex::FromHex;
		s.from_hex().unwrap()
	}

	#[test]
	fn sqrt_fq() {
		let fq1 = Fq::from_str("5204065062716160319596273903996315000119019512886596366359652578430118331601").unwrap();
		let fq2 = Fq::from_str("348579348568").unwrap();

		assert_eq!(fq1, fq_sqrt(fq2).expect("348579348568 is quadratic residue"));
	}

	#[test]
	fn sqrt_fq2() {
		let x1 = Fq2::new(
			Fq::from_str("12844195307879678418043983815760255909500142247603239203345049921980497041944").unwrap(),
			Fq::from_str("7476417578426924565731404322659619974551724117137577781074613937423560117731").unwrap(),
		);

		let x2 = Fq2::new(
			Fq::from_str("3345897230485723946872934576923485762803457692345760237495682347502347589474").unwrap(),
			Fq::from_str("1234912378405347958234756902345768290345762348957605678245967234857634857676").unwrap(),
		);

		assert_eq!(fq2_sqrt(x2).unwrap(), x1);
	}

	#[test]
	fn g1_deserialize() {
		let g1 = g1_from_compressed(&hex("0230644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46")).expect("Invalid g1 decompress result");
		assert_eq!(g1.x(), Fq::from_str("21888242871839275222246405745257275088696311157297823662689037894645226208582").unwrap());
		assert_eq!(g1.y(), Fq::from_str("3969792565221544645472939191694882283483352126195956956354061729942568608776").unwrap());
		assert_eq!(g1.z(), Fq::one());
	}
}