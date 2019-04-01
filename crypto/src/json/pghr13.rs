use hex::FromHex;
use bn::{self, Fq, AffineG1, Fq2, AffineG2};

use std::fmt;

use serde::de::{self, Visitor, Deserialize, Deserializer};

#[derive(Clone)]
pub struct G1(bn::G1);

impl Into<bn::G1> for G1 {
	fn into(self) -> bn::G1 {
		self.0
	}
}

struct G1Visitor;

pub(crate) fn clean_0x(s: &str) -> &str {
	if s.starts_with("0x") {
		&s[2..]
	} else {
		s
	}
}

fn pop_fq<'de, A: de::SeqAccess<'de>>(value: &mut A) -> Result<Fq, A::Error> {
	let x: Vec<u8> = value
		.next_element::<String>()?
		.as_ref()
		.map(|s| clean_0x(s))
		.ok_or(de::Error::custom("Expected next 256-bit number"))?
		.from_hex()
		.map_err(|e| de::Error::custom(format!("Invalid hex: {}", e)))?;

	Fq::from_slice(&x[..]).map_err(|e| de::Error::custom(format!("Invald fr: {:?}", e)))
}

impl<'de> Visitor<'de> for G1Visitor {
	type Value = G1;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		formatter.write_str("a sequence of 2 hex strings")
	}

	fn visit_seq<A>(self, mut value: A) -> Result<Self::Value, A::Error>
	where
		A: de::SeqAccess<'de>,
	{
		let x = pop_fq(&mut value)?;
		let y = pop_fq(&mut value)?;
		let affine_g1 = AffineG1::new(x, y).map_err(|_| de::Error::custom("Invalid g1 curve point"))?;

		Ok(G1(affine_g1.into()))
	}
}

impl<'de> Deserialize<'de> for G1 {
	fn deserialize<D>(deserializer: D) -> Result<G1, D::Error>
	where
		D: Deserializer<'de>,
	{
		deserializer.deserialize_seq(G1Visitor)
	}
}

#[derive(Clone)]
pub struct G2(bn::G2);

impl Into<bn::G2> for G2 {
	fn into(self) -> bn::G2 {
		self.0
	}
}

struct G2Visitor;

impl<'de> Visitor<'de> for G2Visitor {
	type Value = G2;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		formatter.write_str("a sequence of 4 hex strings")
	}

	fn visit_seq<A>(self, mut value: A) -> Result<Self::Value, A::Error>
	where
		A: de::SeqAccess<'de>,
	{
		let x_a = pop_fq(&mut value)?;
		let x_b = pop_fq(&mut value)?;

		let y_a = pop_fq(&mut value)?;
		let y_b = pop_fq(&mut value)?;

		let x = Fq2::new(x_b, x_a);
		let y = Fq2::new(y_b, y_a);

		let affine_g2 = AffineG2::new(x, y).map_err(|_| de::Error::custom("Invalid g2 curve point"))?;

		Ok(G2(affine_g2.into()))
	}
}

impl<'de> Deserialize<'de> for G2 {
	fn deserialize<D>(deserializer: D) -> Result<G2, D::Error>
	where
		D: Deserializer<'de>,
	{
		deserializer.deserialize_seq(G2Visitor)
	}
}

#[derive(Clone, Deserialize)]
pub struct VerifyingKey {
	#[serde(rename = "alphaA")]
	pub a: G2,
	#[serde(rename = "alphaB")]
	pub b: G1,
	#[serde(rename = "alphaC")]
	pub c: G2,
	#[serde(rename = "zeta")]
	pub z: G2,
	#[serde(rename = "gamma")]
	pub gamma: G2,
	#[serde(rename = "gammaBeta1")]
	pub gamma_beta_1: G1,
	#[serde(rename = "gammaBeta2")]
	pub gamma_beta_2: G2,
	#[serde(rename = "ic")]
	pub ic: Vec<G1>,
}

pub fn decode(json: &[u8]) -> Result<VerifyingKey, serde_json::Error> {
	serde_json::from_slice(json)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn g1() {
		let g1 = serde_json::from_str::<G1>(r#"[
			"0x0aee46a7ea6e80a3675026dfa84019deee2a2dedb1bbe11d7fe124cb3efb4b5a",
			"0x044747b6e9176e13ede3a4dfd0d33ccca6321b9acd23bf3683a60adc0366ebaf"
		]"#);

		assert!(g1.is_ok());
	}

	#[test]
	fn g1_messed() {
		let g1 = serde_json::from_str::<G1>(r#"[
			"0x044747b6e9176e13ede3a4dfd0d33ccca6321b9acd23bf3683a60adc0366ebaf",
			"0x0aee46a7ea6e80a3675026dfa84019deee2a2dedb1bbe11d7fe124cb3efb4b5a"
		]"#);

		assert!(!g1.is_ok());
	}

	#[test]
	fn g2() {
		let g2 = serde_json::from_str::<G2>(r#"[
			"0x1f39e4e4afc4bc74790a4a028aff2c3d2538731fb755edefd8cb48d6ea589b5e",
			"0x283f150794b6736f670d6a1033f9b46c6f5204f50813eb85c8dc4b59db1c5d39",
			"0x140d97ee4d2b36d99bc49974d18ecca3e7ad51011956051b464d9e27d46cc25e",
			"0x0764bb98575bd466d32db7b15f582b2d5c452b36aa394b789366e5e3ca5aabd4"
		]"#);

		assert!(g2.is_ok());
	}

	#[test]
	fn g2_messed() {
		let g2 = serde_json::from_str::<G2>(r#"[
			"0x283f150794b6736f670d6a1033f9b46c6f5204f50813eb85c8dc4b59db1c5d39",
			"0x1f39e4e4afc4bc74790a4a028aff2c3d2538731fb755edefd8cb48d6ea589b5e",
			"0x0764bb98575bd466d32db7b15f582b2d5c452b36aa394b789366e5e3ca5aabd4",
			"0x140d97ee4d2b36d99bc49974d18ecca3e7ad51011956051b464d9e27d46cc25e"
		]"#);

		assert!(!g2.is_ok());

		let g2 = serde_json::from_str::<G2>(r#"[
			"0x283f150794b6736f670d6a1033f9b46c6f5204f50813eb85c8dc4b59db1c5d39",
			"0x0764bb98575bd466d32db7b15f582b2d5c452b36aa394b789366e5e3ca5aabd4",
			"0x1f39e4e4afc4bc74790a4a028aff2c3d2538731fb755edefd8cb48d6ea589b5e",
			"0x140d97ee4d2b36d99bc49974d18ecca3e7ad51011956051b464d9e27d46cc25e"
		]"#);

		assert!(!g2.is_ok());
	}

	#[test]
	fn key() {
		let key_json = r#"

{
	"alphaA": [
		"0x209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7",
		"0x04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678",
		"0x2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d",
		"0x120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550"
	],
	"alphaB": [
		"0x2eca0c7238bf16e83e7a1e6c5d49540685ff51380f309842a98561558019fc02",
		"0x03d3260361bb8451de5ff5ecd17f010ff22f5c31cdf184e9020b06fa5997db84"
	],
	"alphaC": [
		"0x2e89718ad33c8bed92e210e81d1853435399a271913a6520736a4729cf0d51eb",
		"0x01a9e2ffa2e92599b68e44de5bcf354fa2642bd4f26b259daa6f7ce3ed57aeb3",
		"0x14a9a87b789a58af499b314e13c3d65bede56c07ea2d418d6874857b70763713",
		"0x178fb49a2d6cd347dc58973ff49613a20757d0fcc22079f9abd10c3baee24590"
	],
	"zeta": [
		"0x217cee0a9ad79a4493b5253e2e4e3a39fc2df38419f230d341f60cb064a0ac29",
		"0x0a3d76f140db8418ba512272381446eb73958670f00cf46f1d9e64cba057b53c",
		"0x26f64a8ec70387a13e41430ed3ee4a7db2059cc5fc13c067194bcc0cb49a9855",
		"0x2fd72bd9edb657346127da132e5b82ab908f5816c826acb499e22f2412d1a2d7"
	],
	"gamma": [
		"0x25f83c8b6ab9de74e7da488ef02645c5a16a6652c3c71a15dc37fe3a5dcb7cb1",
		"0x22acdedd6308e3bb230d226d16a105295f523a8a02bfc5e8bd2da135ac4c245d",
		"0x065bbad92e7c4e31bf3757f1fe7362a63fbfee50e7dc68da116e67d600d9bf68",
		"0x06d302580dc0661002994e7cd3a7f224e7ddc27802777486bf80f40e4ca3cfdb"
	],
	"gammaBeta1": [
		"0x15794ab061441e51d01e94640b7e3084a07e02c78cf3103c542bc5b298669f21",
		"0x14db745c6780e9df549864cec19c2daf4531f6ec0c89cc1c7436cc4d8d300c6d"
	],
	"gammaBeta2": [
		"0x1f39e4e4afc4bc74790a4a028aff2c3d2538731fb755edefd8cb48d6ea589b5e",
		"0x283f150794b6736f670d6a1033f9b46c6f5204f50813eb85c8dc4b59db1c5d39",
		"0x140d97ee4d2b36d99bc49974d18ecca3e7ad51011956051b464d9e27d46cc25e",
		"0x0764bb98575bd466d32db7b15f582b2d5c452b36aa394b789366e5e3ca5aabd4"
	],
	"ic": [
		[
			"0x0aee46a7ea6e80a3675026dfa84019deee2a2dedb1bbe11d7fe124cb3efb4b5a",
			"0x044747b6e9176e13ede3a4dfd0d33ccca6321b9acd23bf3683a60adc0366ebaf"
		],
		[
			"0x1e39e9f0f91fa7ff8047ffd90de08785777fe61c0e3434e728fce4cf35047ddc",
			"0x2e0b64d75ebfa86d7f8f8e08abbe2e7ae6e0a1c0b34d028f19fa56e9450527cb"
		],
		[
			"0x1c36e713d4d54e3a9644dffca1fc524be4868f66572516025a61ca542539d43f",
			"0x042dcc4525b82dfb242b09cb21909d5c22643dcdbe98c4d082cc2877e96b24db"
		],
		[
			"0x17d5d09b4146424bff7e6fb01487c477bbfcd0cdbbc92d5d6457aae0b6717cc5",
			"0x02b5636903efbf46db9235bbe74045d21c138897fda32e079040db1a16c1a7a1"
		],
		[
			"0x0f103f14a584d4203c27c26155b2c955f8dfa816980b24ba824e1972d6486a5d",
			"0x0c4165133b9f5be17c804203af781bcf168da7386620479f9b885ecbcd27b17b"
		],
		[
			"0x232063b584fb76c8d07995bee3a38fa7565405f3549c6a918ddaa90ab971e7f8",
			"0x2ac9b135a81d96425c92d02296322ad56ffb16299633233e4880f95aafa7fda7"
		],
		[
			"0x09b54f111d3b2d1b2fe1ae9669b3db3d7bf93b70f00647e65c849275de6dc7fe",
			"0x18b2e77c63a3e400d6d1f1fbc6e1a1167bbca603d34d03edea231eb0ab7b14b4"
		],
		[
			"0x0c54b42137b67cc268cbb53ac62b00ecead23984092b494a88befe58445a244a",
			"0x18e3723d37fae9262d58b548a0575f59d9c3266db7afb4d5739555837f6b8b3e"
		],
		[
			"0x0a6de0e2240aa253f46ce0da883b61976e3588146e01c9d8976548c145fe6e4a",
			"0x04fbaa3a4aed4bb77f30ebb07a3ec1c7d77a7f2edd75636babfeff97b1ea686e"
		],
		[
			"0x111e2e2a5f8828f80ddad08f9f74db56dac1cc16c1cb278036f79a84cf7a116f",
			"0x1d7d62e192b219b9808faa906c5ced871788f6339e8d91b83ac1343e20a16b30"
		]

	]
}

		"#;

		let _key = serde_json::from_str::<VerifyingKey>(key_json).unwrap();

	}
}