use std::fmt;

use hex::ToHex;

use pairing::bls12_381::Bls12;
use bellman::groth16::Proof as BellmanProof;

#[derive(Clone)]
pub struct Proof([u8; 192]);

#[derive(Debug)]
pub enum Error {
	InvalidData,
}

impl fmt::Debug for Proof {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_fmt(format_args!("{:?}", &self.0.to_hex::<String>()))
	}
}

impl PartialEq<Proof> for Proof {
	fn eq(&self, other: &Proof) -> bool {
		self.0.as_ref() == other.0.as_ref()
	}
}

impl Default for Proof {
	fn default() -> Self {
		Self([0u8; 192])
	}
}

impl From<[u8; 192]> for Proof {
	fn from(val: [u8; 192]) -> Self {
		Proof(val)
	}
}

impl Into<[u8; 192]> for Proof {
	fn into(self) -> [u8; 192] {
		self.0
	}
}

impl<'a> Into<&'a [u8; 192]> for &'a Proof {
	fn into(self) -> &'a [u8; 192] {
		&self.0
	}
}

impl Proof {
	pub fn to_bls_proof(&self) -> Result<BellmanProof<Bls12>, Error> {
		BellmanProof::<Bls12>::read(&self.0[..])
			.map_err(|_| /* only invalid data possible, length is always ok */ Error::InvalidData)
	}
}