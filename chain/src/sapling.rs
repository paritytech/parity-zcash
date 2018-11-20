use std::fmt;
use hex::ToHex;

#[derive(Clone)]
pub struct Sapling {
	pub amount: i64,
	pub spends: Vec<SaplingSpendDescription>,
	pub outputs: Vec<SaplingOutputDescription>,
	pub binding_sig: [u8; 64],
}

#[derive(Clone, Serializable, Deserializable)]
pub struct SaplingSpendDescription {
	pub cv: [u8; 32],
	pub anchor: [u8; 32],
	pub nullifier: [u8; 32],
	pub rk: [u8; 32],
	pub zkproof: [u8; 192],
	pub spend_auth_sig: [u8; 64],
}

#[derive(Clone, Serializable, Deserializable)]
pub struct SaplingOutputDescription {
	pub cv: [u8; 32],
	pub cm: [u8; 32],
	pub ephemeral_key: [u8; 32],
	pub enc_cipher_text: [u8; 580],
	pub out_cipher_text: [u8; 80],
	pub zkproof: [u8; 192],
}

impl Default for Sapling {
	fn default() -> Self {
		Sapling {
			amount: Default::default(),
			spends: Default::default(),
			outputs: Default::default(),
			binding_sig: [0; 64],
		}
	}
}

impl fmt::Debug for Sapling {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("Sapling")
			.field("amount", &self.amount)
			.field("spends", &self.spends)
			.field("outputs", &self.outputs)
			.field("binding_sig", &self.binding_sig.to_hex::<String>())
			.finish()
	}
}

impl PartialEq<Sapling> for Sapling {
	fn eq(&self, other: &Sapling) -> bool {
		self.amount == other.amount
			&& self.spends == other.spends
			&& self.outputs == other.outputs
			&& self.binding_sig.as_ref() == other.binding_sig.as_ref()
	}
}

impl Default for SaplingSpendDescription {
	fn default() -> Self {
		SaplingSpendDescription {
			cv: Default::default(),
			anchor: Default::default(),
			nullifier: Default::default(),
			rk: Default::default(),
			zkproof: [0; 192],
			spend_auth_sig: [0; 64],
		}
	}
}

impl fmt::Debug for SaplingSpendDescription {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("SaplingSpendDescription")
			.field("cv", &self.cv.to_hex::<String>())
			.field("anchor", &self.anchor.to_hex::<String>())
			.field("nullifier", &self.nullifier.to_hex::<String>())
			.field("rk", &self.rk.to_hex::<String>())
			.field("zkproof", &self.zkproof.to_hex::<String>())
			.field("spend_auth_sig", &self.spend_auth_sig.to_hex::<String>())
			.finish()
	}
}

impl PartialEq<SaplingSpendDescription> for SaplingSpendDescription {
	fn eq(&self, other: &SaplingSpendDescription) -> bool {
		self.cv == other.cv
			&& self.anchor == other.anchor
			&& self.nullifier == other.nullifier
			&& self.rk == other.rk
			&& self.zkproof.as_ref() == other.zkproof.as_ref()
			&& self.spend_auth_sig.as_ref() == other.spend_auth_sig.as_ref()
	}
}

impl Default for SaplingOutputDescription {
	fn default() -> Self {
		SaplingOutputDescription {
			cv: Default::default(),
			cm: Default::default(),
			ephemeral_key: Default::default(),
			enc_cipher_text: [0; 580],
			out_cipher_text: [0; 80],
			zkproof: [0; 192],
		}
	}
}

impl fmt::Debug for SaplingOutputDescription {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("SaplingSpendDescription")
			.field("cv", &self.cv.to_hex::<String>())
			.field("cm", &self.cm.to_hex::<String>())
			.field("ephemeral_key", &self.ephemeral_key.to_hex::<String>())
			.field("enc_cipher_text", &self.enc_cipher_text.to_hex::<String>())
			.field("out_cipher_text", &self.out_cipher_text.to_hex::<String>())
			.field("zkproof", &self.zkproof.to_hex::<String>())
			.finish()
	}
}

impl PartialEq<SaplingOutputDescription> for SaplingOutputDescription {
	fn eq(&self, other: &SaplingOutputDescription) -> bool {
		self.cv == other.cv
			&& self.cm == other.cm
			&& self.ephemeral_key == other.ephemeral_key
			&& self.enc_cipher_text.as_ref() == other.enc_cipher_text.as_ref()
			&& self.out_cipher_text.as_ref() == other.out_cipher_text.as_ref()
			&& self.zkproof.as_ref() == other.zkproof.as_ref()
	}
}
