use hex::FromHex;
use bn::{self, Group, Fq, AffineG1};

use std::fmt;

use serde::de::{self, Visitor, Deserialize, Deserializer};

#[derive(Clone)]
pub struct G1(bn::G1);

struct G1Visitor;

fn pop_fq<'de, A: de::SeqAccess<'de>>(value: &mut A) -> Result<Fq, A::Error> {
    let x: Vec<u8> = value
        .next_element::<String>()?
        .ok_or(de::Error::custom("Should be 2 elements"))?
        .from_hex()
        .map_err(|e| de::Error::custom(format!("Invalid hex: {}", e)))?;

    Fq::from_slice(&x[..]).map_err(|e| de::Error::custom(format!("Invald fr: {:?}", e)))
}

impl<'de> Visitor<'de> for G1Visitor {
    type Value = G1;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a sequence of 2 strings")
    }

    fn visit_seq<A>(self, mut value: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let x = pop_fq(&mut value)?;
        let y = pop_fq(&mut value)?;
        let affine_g1 = AffineG1::new(x, y).map_err(|e| de::Error::custom("Invalid curve point"))?;

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

#[cfg(test)]
mod tests {

    extern crate serde_json;
    use serde;
    use super::*;

    #[test]
    fn g1() {
        let g1: G1 = serde_json::from_str(r#"[
            "0aee46a7ea6e80a3675026dfa84019deee2a2dedb1bbe11d7fe124cb3efb4b5a",
            "044747b6e9176e13ede3a4dfd0d33ccca6321b9acd23bf3683a60adc0366ebaf"
        ]"#).unwrap();

    }

}