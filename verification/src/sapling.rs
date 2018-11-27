use std::io::Error as IoError;
use chain::{Sapling, SaplingSpendDescription, SaplingOutputDescription};
use pairing::{bls12_381::{Bls12, Fr, FrRepr}, PrimeField, PrimeFieldRepr, PrimeFieldDecodingError};
use bellman::{SynthesisError, groth16::{verify_proof, PreparedVerifyingKey, Proof,}};

use sapling_crypto::{circuit::multipack, redjubjub::{self, Signature}};
use sapling_crypto::jubjub::{edwards,fs::FsRepr, FixedGenerators, JubjubBls12, JubjubParams, Unknown};

type Point = edwards::Point<Bls12, Unknown>;

lazy_static! {
	static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
	static ref SAPLING_SPEND_VK: Option<PreparedVerifyingKey<Bls12>> = None;
	static ref SAPLING_OUTPUT_VK: Option<PreparedVerifyingKey<Bls12>> = None;
}

/// Errors that could occur during sapling verification.
pub enum Error {
	/// Spend description verification error.
	Spend(usize, SpendError),
	/// Output description verification error.
	Output(usize, OutputError),
	/// Invalid balance value.
	InvalidBalanceValue,
	/// Error deserializing/verifying binding_sig.
	BindingSig(SignatureError),
}

/// Errors that can occur during spend description verification.
pub enum SpendError {
	/// Error deserializing value commitment.
	ValueCommitment(PointError),
	/// Error deserializing anchor.
	Anchor(PrimeFieldDecodingError),
	/// Error deserializing randomized key.
	RandomizedKey(PublicKeyError),
	/// Error deserializing/verifying spend_auth_sig.
	SpendAuthSig(SignatureError),
	/// Error deserializing/verifying zk-proof.
	Proof(ProofError),
}

/// Errors that can occur during output description verification.
pub enum OutputError {
	/// Error deserializing value commitment.
	ValueCommitment(PointError),
	/// Error deserializing note commitment.
	NoteCommitment(PrimeFieldDecodingError),
	/// Error deserializing ephemeral key.
	EphemeralKey(PointError),
	/// Error deserializing/verifying zk-proof.
	Proof(ProofError),
}

/// Errors that can occur during point deserialization.
pub enum PointError {
	/// The point is invalid.
	Invalid(IoError),
	/// The point MUST NOT be small order.
	SmallOrder,
}

/// Errors that can occur during public key deserialization.
pub enum PublicKeyError {
	/// The public key is invalid.
	Invalid(IoError),
	/// The point corresponding to the public key MUST NOT be small order.
	SmallOrder,
}

/// Error that can occur during signature deserialization/verification.
pub enum SignatureError {
	/// The signature is invalid.
	Invalid(IoError),
	/// The signature verifciation has failed.
	Failed,
}

/// Proof verification error.
pub enum ProofError {
	/// The proof is invalid.
	Invalid(IoError),
	/// The error that could occur during circuit synthesis context.
	Synthesis(SynthesisError),
	/// The proof verification has invalid.
	Failed,
}

/// Verify sapling proofs/signatures validity.
pub fn accept_sapling(sighash: &[u8; 32], sapling: &Sapling) -> Result<(), Error> {
	// binding verification key is not encoded explicitly in transaction and must be recalculated
	let mut total = edwards::Point::zero();

	// verify each spend description
	for (idx, spend) in sapling.spends.iter().enumerate() {
		accept_spend(sighash, &mut total, spend)
			.map_err(|err| Error::Spend(idx, err))?;
	}

	// verify each output description
	for (idx, output) in sapling.outputs.iter().enumerate() {
		accept_output(&mut total, output)
			.map_err(|err| Error::Output(idx, err))?;
	}

	// check binding signature
	accept_sapling_final(sighash, total, sapling)
}

/// Verify sapling spend description.
fn accept_spend(sighash: &[u8; 32], total: &mut Point, spend: &SaplingSpendDescription) -> Result<(), SpendError> {
	// deserialize and check value commitment
	let value_commitment = require_non_small_order_point(&spend.value_commitment)
		.map_err(SpendError::ValueCommitment)?;

	// accumulate the value commitment
	*total = total.add(&value_commitment, &JUBJUB);

	// deserialize the anchor, which should be an element of Fr
	let anchor = Fr::from_repr(read_le(&spend.anchor))
		.map_err(SpendError::Anchor)?;

	// compute the signature's message for randomized key && spend_auth_sig
	let mut data_to_be_signed = [0u8; 64];
	data_to_be_signed[..32].copy_from_slice(&spend.randomized_key);
	data_to_be_signed[32..].copy_from_slice(sighash);

	// deserialize and check randomized key
	let randomized_key = redjubjub::PublicKey::<Bls12>::read(&spend.randomized_key[..], &JUBJUB)
		.map_err(|err| SpendError::RandomizedKey(PublicKeyError::Invalid(err)))?;
	if is_small_order(&randomized_key.0) {
		return Err(SpendError::RandomizedKey(PublicKeyError::SmallOrder));
	}

	// deserialize the signature
	let spend_auth_sig = Signature::read(&spend.spend_auth_sig[..])
		.map_err(|err| SpendError::SpendAuthSig(SignatureError::Invalid(err)))?;

	// verify the spend_auth_sig
	if !randomized_key.verify(&data_to_be_signed, &spend_auth_sig, FixedGenerators::SpendingKeyGenerator, &JUBJUB) {
		return Err(SpendError::SpendAuthSig(SignatureError::Failed));
	}

	// Add the nullifier through multiscalar packing
	let nullifier = multipack::bytes_to_bits_le(&spend.nullifier);
	let nullifier = multipack::compute_multipacking::<Bls12>(&nullifier);
	assert_eq!(nullifier.len(), 2);

	// construct public input for circuit
	let (randomized_key_x, randomized_key_y) = randomized_key.0.into_xy();
	let (value_commitment_x, value_commitment_y) = value_commitment.into_xy();
	let public_input = [
		randomized_key_x,
		randomized_key_y,
		value_commitment_x,
		value_commitment_y,
		anchor,
		nullifier[0],
		nullifier[1],
	];

	// deserialize the proof
	let zkproof = Proof::<Bls12>::read(&spend.zkproof[..])
		.map_err(|err| SpendError::Proof(ProofError::Invalid(err)))?;

	// check the proof
	let verification_key = SAPLING_SPEND_VK.as_ref().expect("TODO");
	let is_verification_ok = verify_proof(verification_key, &zkproof, &public_input[..])
		.map_err(|err| SpendError::Proof(ProofError::Synthesis(err)))?;
	if !is_verification_ok {
		return Err(SpendError::Proof(ProofError::Failed));
	}

	Ok(())
}

fn accept_output(total: &mut Point, output: &SaplingOutputDescription) -> Result<(), OutputError> {
	// deserialize and check value commitment
	let value_commitment = require_non_small_order_point(&output.value_commitment)
		.map_err(OutputError::ValueCommitment)?;

	// accumulate the value commitment
	*total = total.add(&value_commitment.clone().negate(), &JUBJUB);

	// deserialize the commitment, which should be an element of Fr
	let note_commitment = Fr::from_repr(read_le(&output.note_commitment))
		.map_err(OutputError::NoteCommitment)?;

	// deserialize the ephemeral key
	let ephemeral_key = require_non_small_order_point(&output.ephemeral_key)
		.map_err(OutputError::EphemeralKey)?;

	// construct public input for circuit
	let (ephemeral_key_x, ephemeral_key_y) = ephemeral_key.into_xy();
	let (value_commitment_x, value_commitment_y) = value_commitment.into_xy();
	let public_input = [
		value_commitment_x,
		value_commitment_y,
		ephemeral_key_x,
		ephemeral_key_y,
		note_commitment,
	];

	// deserialize the proof
	let zkproof = Proof::<Bls12>::read(&output.zkproof[..])
		.map_err(|err| OutputError::Proof(ProofError::Invalid(err)))?;

	// check the proof
	let verification_key = SAPLING_OUTPUT_VK.as_ref().expect("TODO");
	let is_verification_ok = verify_proof(verification_key, &zkproof, &public_input[..])
		.map_err(|err| OutputError::Proof(ProofError::Synthesis(err)))?;
	if !is_verification_ok {
		return Err(OutputError::Proof(ProofError::Failed));
	}

	Ok(())
}

fn accept_sapling_final(sighash: &[u8; 32], total: Point, sapling: &Sapling) -> Result<(), Error> {
	// obtain current bvk from the context
	let mut binding_verification_key = redjubjub::PublicKey(total);

	// compute value balance
	let mut value_balance = compute_value_balance(sapling.balancing_value)?;

	// subtract value_balance from current bvk to get final bvk
	value_balance = value_balance.negate();
	binding_verification_key.0 = binding_verification_key.0.add(&value_balance, &JUBJUB);

	// compute the signature's message for binding_verification_key/binding_sig
	let mut data_to_be_signed = [0u8; 64];
	binding_verification_key.0.write(&mut data_to_be_signed[..32]).expect("bvk is 32 bytes");
	data_to_be_signed[32..].copy_from_slice(&sighash[..]);

	// deserialize the binding signature
	let binding_sig = Signature::read(&sapling.binding_sig[..])
		.map_err(|err| Error::BindingSig(SignatureError::Invalid(err)))?;

	// check the binding signature
	let is_verification_ok = binding_verification_key
		.verify(&data_to_be_signed, &binding_sig, FixedGenerators::ValueCommitmentRandomness, &JUBJUB);
	if !is_verification_ok {
		return Err(Error::BindingSig(SignatureError::Failed));
	}

	Ok(())
}

// This function computes `value` in the exponent of the value commitment base
fn compute_value_balance(value: i64) -> Result<Point, Error> {
	// Compute the absolute value (failing if -i64::MAX is the value)
	let abs = match value.checked_abs() {
		Some(a) => a as u64,
		None => return Err(Error::InvalidBalanceValue),
	};

	// Is it negative? We'll have to negate later if so.
	let is_negative = value.is_negative();

	// Compute it in the exponent
	let mut value_balance = JUBJUB
		.generator(FixedGenerators::ValueCommitmentValue)
		.mul(FsRepr::from(abs), &JUBJUB);

	// Negate if necessary
	if is_negative {
		value_balance = value_balance.negate();
	}

	// Convert to unknown order point
	Ok(value_balance.into())
}

/// Reads an FrRepr from a [u8] of length 32.
/// This will panic (abort) if length provided is
/// not correct.
fn read_le(from: &[u8; 32]) -> FrRepr {
	let mut repr = FrRepr::default();
	repr.read_le(&from[..]).expect("length is 32 bytes");
	repr
}


/// Deserializes point from the serialized buffer, checking that it is on the curve
/// AND it MUST NOT be of small order.
fn require_non_small_order_point(point_buff: &[u8; 32]) -> Result<Point, PointError> {
	let point = Point::read(&point_buff[..], &JUBJUB).map_err(PointError::Invalid)?;
	if is_small_order(&point) {
		return Err(PointError::SmallOrder);
	}
	Ok(point)
}

/// Is this a small order point?
fn is_small_order(point: &Point) -> bool {
	point.double(&JUBJUB).double(&JUBJUB).double(&JUBJUB) == edwards::Point::zero()
}

#[cfg(test)]
mod tests {
	// TODO: detailed tests when sighash + verification keys are available
}
