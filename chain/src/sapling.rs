use std::fmt;
use hex::ToHex;

/// 
#[derive(Clone)]
pub struct Sapling {
	/// The net value of Spend transfers minus Output transfers in a transaction is
	/// called the balancing_value.
	/// A positive balancing_value takes value from the Sapling value pool and adds
	/// it to the transparent value pool.
	/// A negative balancing value does the reverse.
	pub balancing_value: i64,
	/// A Spend transfer spends a note. Its Spend description includes a Pedersen value
	/// commitment to the value of the note. It is associated with an instance of a Spend
	/// statement for which it provides a zk-SNARK proof.
	pub spends: Vec<SaplingSpendDescription>,
	/// An Output transfer creates a note. Its Output description includes a Pedersen value
	/// commitment to the note value. It is associated with an instance of an Output statement
	/// for which it provides a zk-SNARK proof.
	pub outputs: Vec<SaplingOutputDescription>,
	/// Consistency of balancing_value with the value commitments in Spend descriptions
	/// and Output descriptions is enforced by the binding_sig.
	/// This signature has a dual role in Sapling:
	/// 1) to prove that the total value spent by Spend transfers, minus that produced by
	///    Output transfers, is consistent with the v balance field of the transaction;
	/// 2) To prove that the signer knew the randomness used for the spend and output value
	///    commitments, in order to prevent Output descriptions from being replayed by an
	///    adversary in a different transaction. (A Spend description already cannot be
	///    replayed due to its spend authorization signature.)
	pub binding_sig: [u8; 64],
}

/// Single Spend transfer description.
#[derive(Clone, Serializable, Deserializable)]
pub struct SaplingSpendDescription {
	/// Value commitment to the value of the input note.
	pub value_commitment: [u8; 32],
	/// An anchor for the output treestate of a previous block.
	pub anchor: [u8; 32],
	/// The nullifier for the input note.
	pub nullifier: [u8; 32],
	/// Randomized public key that should be used to verify spend_auth_sig.
	pub randomized_key: [u8; 32],
	/// Zero-knowledge proof with primary input
	///   (value_commitment, anchor, nullifier, randomized_key)
	/// for the spend statement.
	pub zkproof: [u8; 192],
	/// Spend authorization signature. Is used to prove knowledge of the spending key
	/// authorizing spending of an input note.
	pub spend_auth_sig: [u8; 64],
}

/// Single Output transfer description.
#[derive(Clone, Serializable, Deserializable)]
pub struct SaplingOutputDescription {
	/// Value commitment to the value of the output note.
	pub value_commitment: [u8; 32],
	/// The note commitment for the output note.
	pub note_commitment: [u8; 32],
	/// Key agreement public key, used to derive the key for encryption of the transmitted
	/// note ciphertext.
	pub ephemeral_key: [u8; 32],
	/// Ciphertext component for the encrypted output note.
	pub enc_cipher_text: [u8; 580],
	/// Ciphertext component that allows the holder of a full viewing key to recover the recipient
	/// diversified transmission key and teh ephemeral private key (and therefore the entire note
	/// plaintext).
	pub out_cipher_text: [u8; 80],
	/// Zero-knowledge proof with primary input
	///   (value_commitment, cm, ephemeral_key)
	/// for the output statement.
	pub zkproof: [u8; 192],
}

impl Default for Sapling {
	fn default() -> Self {
		Sapling {
			balancing_value: Default::default(),
			spends: Default::default(),
			outputs: Default::default(),
			binding_sig: [0; 64],
		}
	}
}

impl fmt::Debug for Sapling {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("Sapling")
			.field("balancing_value", &self.balancing_value)
			.field("spends", &self.spends)
			.field("outputs", &self.outputs)
			.field("binding_sig", &self.binding_sig.to_hex::<String>())
			.finish()
	}
}

impl PartialEq<Sapling> for Sapling {
	fn eq(&self, other: &Sapling) -> bool {
		self.balancing_value == other.balancing_value
			&& self.spends == other.spends
			&& self.outputs == other.outputs
			&& self.binding_sig.as_ref() == other.binding_sig.as_ref()
	}
}

impl Default for SaplingSpendDescription {
	fn default() -> Self {
		SaplingSpendDescription {
			value_commitment: Default::default(),
			anchor: Default::default(),
			nullifier: Default::default(),
			randomized_key: Default::default(),
			zkproof: [0; 192],
			spend_auth_sig: [0; 64],
		}
	}
}

impl fmt::Debug for SaplingSpendDescription {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("SaplingSpendDescription")
			.field("value_commitment", &self.value_commitment.to_hex::<String>())
			.field("anchor", &self.anchor.to_hex::<String>())
			.field("nullifier", &self.nullifier.to_hex::<String>())
			.field("randomized_key", &self.randomized_key.to_hex::<String>())
			.field("zkproof", &self.zkproof.to_hex::<String>())
			.field("spend_auth_sig", &self.spend_auth_sig.to_hex::<String>())
			.finish()
	}
}

impl PartialEq<SaplingSpendDescription> for SaplingSpendDescription {
	fn eq(&self, other: &SaplingSpendDescription) -> bool {
		self.value_commitment == other.value_commitment
			&& self.anchor == other.anchor
			&& self.nullifier == other.nullifier
			&& self.randomized_key == other.randomized_key
			&& self.zkproof.as_ref() == other.zkproof.as_ref()
			&& self.spend_auth_sig.as_ref() == other.spend_auth_sig.as_ref()
	}
}

impl Default for SaplingOutputDescription {
	fn default() -> Self {
		SaplingOutputDescription {
			value_commitment: Default::default(),
			note_commitment: Default::default(),
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
			.field("value_commitment", &self.value_commitment.to_hex::<String>())
			.field("note_commitment", &self.note_commitment.to_hex::<String>())
			.field("ephemeral_key", &self.ephemeral_key.to_hex::<String>())
			.field("enc_cipher_text", &self.enc_cipher_text.to_hex::<String>())
			.field("out_cipher_text", &self.out_cipher_text.to_hex::<String>())
			.field("zkproof", &self.zkproof.to_hex::<String>())
			.finish()
	}
}

impl PartialEq<SaplingOutputDescription> for SaplingOutputDescription {
	fn eq(&self, other: &SaplingOutputDescription) -> bool {
		self.value_commitment == other.value_commitment
			&& self.note_commitment == other.note_commitment
			&& self.ephemeral_key == other.ephemeral_key
			&& self.enc_cipher_text.as_ref() == other.enc_cipher_text.as_ref()
			&& self.out_cipher_text.as_ref() == other.out_cipher_text.as_ref()
			&& self.zkproof.as_ref() == other.zkproof.as_ref()
	}
}
