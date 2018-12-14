use hex::FromHex;
use bn::{self, Group, Fq, AffineG1, Fq2, AffineG2};

use std::fmt;

use serde::de::{self, Visitor, Deserialize, Deserializer};

#[derive(Clone)]
pub struct G1(bn::G1);

struct G1Visitor;

fn clean_0x(s: &str) -> &str {
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
}