use std::fmt;
use hex::FromHex;
use bellman::groth16::{prepare_verifying_key, VerifyingKey as BellmanVerifyingKey};
use pairing::{EncodedPoint, bls12_381::{Bls12, G1Uncompressed, G2Uncompressed}};
use serde::de::{self, Visitor, Deserialize, Deserializer};

use json::pghr13::clean_0x;
use Groth16VerifyingKey;

/// Load Sapling spend verification key.
pub fn load_sapling_spend_verifying_key() -> Result<Groth16VerifyingKey, String> {
	let spend_vk_json = include_bytes!("../../../res/sapling-spend-verifying-key.json");
	let spend_vk = serde_json::from_slice::<VerifyingKey>(&spend_vk_json[..]).unwrap();
	Ok(Groth16VerifyingKey(prepare_verifying_key(&spend_vk.into())))
}

/// Load Sapling output verification key.
pub fn load_sapling_output_verifying_key() -> Result<Groth16VerifyingKey, String> {
	let output_vk_json = include_bytes!("../../../res/sapling-output-verifying-key.json");
	let output_vk = serde_json::from_slice::<VerifyingKey>(&output_vk_json[..]).unwrap();
	Ok(Groth16VerifyingKey(prepare_verifying_key(&output_vk.into())))
}

type G1 = Point<G1Uncompressed>;
type G2 = Point<G2Uncompressed>;

#[derive(Clone, Deserialize)]
struct VerifyingKey {
	#[serde(rename = "alphaG1")]
	pub alpha_g1: G1,
	#[serde(rename = "betaG1")]
	pub beta_g1: G1,
	#[serde(rename = "betaG2")]
	pub beta_g2: G2,
	#[serde(rename = "gammaG2")]
	pub gamma_g2: G2,
	#[serde(rename = "deltaG1")]
	pub delta_g1: G1,
	#[serde(rename = "deltaG2")]
	pub delta_g2: G2,
	#[serde(rename = "ic")]
	pub ic: Vec<G1>,
}

impl From<VerifyingKey> for BellmanVerifyingKey<Bls12> {
	fn from(vk: VerifyingKey) -> BellmanVerifyingKey<Bls12> {
		BellmanVerifyingKey {
			alpha_g1: vk.alpha_g1.0,
			beta_g1: vk.beta_g1.0,
			beta_g2: vk.beta_g2.0,
			gamma_g2: vk.gamma_g2.0,
			delta_g1: vk.delta_g1.0,
			delta_g2: vk.delta_g2.0,
			ic: vk.ic.into_iter().map(|p| p.0).collect(),
		}
	}
}

#[derive(Debug, Clone)]
struct Point<EP: EncodedPoint>(EP::Affine);

impl<'de, EP: EncodedPoint> Deserialize<'de> for Point<EP> {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct EncodedPointVisitor<EP: EncodedPoint>(::std::marker::PhantomData<EP>);

		impl<'de, EP: EncodedPoint> Visitor<'de> for EncodedPointVisitor<EP> {
			type Value = Point<EP>;

			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str("a hex string")
			}

			fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				let mut point = EP::empty();
				let point_raw = clean_0x(value).from_hex::<Vec<_>>()
					.map_err(|e| de::Error::custom(format!("Expected hex string: {}", e)))?;
				if point.as_ref().len() != point_raw.len() {
					return Err(de::Error::custom(format!("Expected hex string of length {}", point.as_ref().len())));
				}

				point.as_mut().copy_from_slice(&point_raw);
				point.into_affine()
					.map_err(|e| de::Error::custom(format!("Invalid curve point: {}", e)))
					.map(Point)
			}
		}

		deserializer.deserialize_str(EncodedPointVisitor::<EP>(Default::default()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn g1() {
		let valid = r#""0x0db882cf5db3e8567f16b4db1772d4d1f5a3fe8d62f0df2eb8a5cfa50806702afde8fc25335eb5ec859c2818b2610b2e19ab445dac720bb1f2b0cd3336f7a1acc62bf1b3a321826264dc7e469281e23b218394d598689da04e136878ff9a7897""#;
		serde_json::from_str::<G1>(valid).unwrap();
	}

	#[test]
	fn g1_messed() {
		// too few chars
		let invalid = r#""0xb882cf5db3e8567f16b4db1772d4d1f5a3fe8d62f0df2eb8a5cfa50806702afde8fc25335eb5ec859c2818b2610b2e19ab445dac720bb1f2b0cd3336f7a1acc62bf1b3a321826264dc7e469281e23b218394d598689da04e136878ff9a7897""#;
		serde_json::from_str::<G1>(invalid).unwrap_err();

		// too much chars
		let invalid = r#""0xFF0db882cf5db3e8567f16b4db1772d4d1f5a3fe8d62f0df2eb8a5cfa50806702afde8fc25335eb5ec859c2818b2610b2e19ab445dac720bb1f2b0cd3336f7a1acc62bf1b3a321826264dc7e469281e23b218394d598689da04e136878ff9a7897""#;
		serde_json::from_str::<G1>(invalid).unwrap_err();

		// invalid curve point
		let invalid = r#""0x19ab445dac720bb1f2b0cd3336f7a1acc62bf1b3a321826264dc7e469281e23b218394d598689da04e136878ff9a78970db882cf5db3e8567f16b4db1772d4d1f5a3fe8d62f0df2eb8a5cfa50806702afde8fc25335eb5ec859c2818b2610b2e""#;
		serde_json::from_str::<G1>(invalid).unwrap_err();
	}

	#[test]
	fn g2() {
		let valid = r#""0x050302fecf4d86671c66ed1ee097efccd2a2add6fd42c9d0a809bb6a3e0f8348bfac6cfa4427c83d5ed1ff844a5b1b1209c069a8a1ccd8c7c22b2a84fede0e53b536cabd7d4c7f0ddc53bec42eeda2b09190d43bcbaece88f7a2a1fc686076d20f2acbc06f28f913a2a77a731d96133aeb5282461cd452a3f3f1d3b63907840dc79b1066e898a335c3a676de9c97507c0c4824b4c9ac0dfc2b1b017e1ebe1b96920a80a7f7e61e39d2f275c51ea8c0b4a6aa86643ee4696af6611d027c58401c""#;
		serde_json::from_str::<G2>(valid).unwrap();
	}

	#[test]
	fn g2_messed() {
		// too few chars
		let invalid = r#""0x0302fecf4d86671c66ed1ee097efccd2a2add6fd42c9d0a809bb6a3e0f8348bfac6cfa4427c83d5ed1ff844a5b1b1209c069a8a1ccd8c7c22b2a84fede0e53b536cabd7d4c7f0ddc53bec42eeda2b09190d43bcbaece88f7a2a1fc686076d20f2acbc06f28f913a2a77a731d96133aeb5282461cd452a3f3f1d3b63907840dc79b1066e898a335c3a676de9c97507c0c4824b4c9ac0dfc2b1b017e1ebe1b96920a80a7f7e61e39d2f275c51ea8c0b4a6aa86643ee4696af6611d027c58401c""#;
		serde_json::from_str::<G2>(invalid).unwrap_err();

		// too much chars
		let invalid = r#""0xFF050302fecf4d86671c66ed1ee097efccd2a2add6fd42c9d0a809bb6a3e0f8348bfac6cfa4427c83d5ed1ff844a5b1b1209c069a8a1ccd8c7c22b2a84fede0e53b536cabd7d4c7f0ddc53bec42eeda2b09190d43bcbaece88f7a2a1fc686076d20f2acbc06f28f913a2a77a731d96133aeb5282461cd452a3f3f1d3b63907840dc79b1066e898a335c3a676de9c97507c0c4824b4c9ac0dfc2b1b017e1ebe1b96920a80a7f7e61e39d2f275c51ea8c0b4a6aa86643ee4696af6611d027c58401c""#;
		serde_json::from_str::<G2>(invalid).unwrap_err();

		// invalid curve point
		let invalid = r#""0x09c069a8a1ccd8c7c22b2a84fede0e53b536cabd7d4c7f0ddc53bec42eeda2b09190d43bcbaece88f7a2a1fc686076d2050302fecf4d86671c66ed1ee097efccd2a2add6fd42c9d0a809bb6a3e0f8348bfac6cfa4427c83d5ed1ff844a5b1b120c4824b4c9ac0dfc2b1b017e1ebe1b96920a80a7f7e61e39d2f275c51ea8c0b4a6aa86643ee4696af6611d027c58401c0f2acbc06f28f913a2a77a731d96133aeb5282461cd452a3f3f1d3b63907840dc79b1066e898a335c3a676de9c97507c""#;
		serde_json::from_str::<G2>(invalid).unwrap_err();
	}

	#[test]
	fn output_key() {
		let output_vk_json = include_bytes!("../../../res/sapling-output-verifying-key.json");
		serde_json::from_slice::<VerifyingKey>(&output_vk_json[..]).unwrap();
	}

	#[test]
	fn spend_key() {
		let spend_vk_json = include_bytes!("../../../res/sapling-spend-verifying-key.json");
		serde_json::from_slice::<VerifyingKey>(&spend_vk_json[..]).unwrap();
	}
}
