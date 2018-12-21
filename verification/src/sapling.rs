use std::io::Error as IoError;
use chain::{Sapling, SaplingSpendDescription, SaplingOutputDescription};
use crypto::{
	Groth16VerifyingKey,
	pairing::{bls12_381::{Bls12, Fr, FrRepr}, PrimeField, PrimeFieldRepr, PrimeFieldDecodingError},
	bellman::{SynthesisError, groth16::{verify_proof, Proof}},
	sapling_crypto::{circuit::multipack, redjubjub::{self, Signature}},
	sapling_crypto::jubjub::{edwards,fs::FsRepr, FixedGenerators, JubjubBls12, JubjubParams, Unknown}
};

type Point = edwards::Point<Bls12, Unknown>;

lazy_static! {
	static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}

/// Errors that could occur during sapling verification.
#[derive(Debug)]
pub enum Error {
	/// Spend description verification error.
	Spend(usize, SpendError),
	/// Output description verification error.
	Output(usize, OutputError),
	/// Invalid balance value.
	InvalidBalanceValue,
	/// Error verifying binding_sig.
	BadBindingSignature,
}

/// Errors that can occur during spend description verification.
#[derive(Debug)]
pub enum SpendError {
	/// Error deserializing value commitment.
	ValueCommitment(PointError),
	/// Error deserializing anchor.
	Anchor(PrimeFieldDecodingError),
	/// Error deserializing randomized key.
	RandomizedKey(PointError),
	/// Error verifying spend_auth_sig.
	BadSpendAuthSig,
	/// Error deserializing/verifying zk-proof.
	Proof(ProofError),
}

/// Errors that can occur during output description verification.
#[derive(Debug)]
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
#[derive(Debug)]
pub enum PointError {
	/// The point is invalid.
	Invalid(IoError),
	/// The point MUST NOT be small order.
	SmallOrder,
}

/// Proof verification error.
#[derive(Debug)]
pub enum ProofError {
	/// The proof is invalid.
	Invalid(IoError),
	/// The error that could occur during circuit synthesis context.
	Synthesis(SynthesisError),
	/// The proof verification has invalid.
	Failed,
}

/// Verify sapling proofs/signatures validity.
pub fn accept_sapling(
	spend_vk: &Groth16VerifyingKey,
	output_vk: &Groth16VerifyingKey,
	sighash: &[u8; 32],
	sapling: &Sapling,
) -> Result<(), Error> {
	// binding verification key is not encoded explicitly in transaction and must be recalculated
	let mut total = edwards::Point::zero();

	// verify each spend description
	for (idx, spend) in sapling.spends.iter().enumerate() {
		accept_spend(spend_vk, sighash, &mut total, spend)
			.map_err(|err| Error::Spend(idx, err))?;
	}

	// verify each output description
	for (idx, output) in sapling.outputs.iter().enumerate() {
		accept_output(output_vk, &mut total, output)
			.map_err(|err| Error::Output(idx, err))?;
	}

	// check binding signature
	accept_sapling_final(sighash, total, sapling)
}

/// Verify sapling spend description.
fn accept_spend(
	spend_vk: &Groth16VerifyingKey,
	sighash: &[u8; 32],
	total: &mut Point,
	spend: &SaplingSpendDescription,
) -> Result<(), SpendError> {
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
		.map_err(|err| SpendError::RandomizedKey(PointError::Invalid(err)))?;
	if is_small_order(&randomized_key.0) {
		return Err(SpendError::RandomizedKey(PointError::SmallOrder));
	}

	// deserialize the signature
	let spend_auth_sig = Signature::read(&spend.spend_auth_sig[..])
		.expect("only could fail if length of passed buffer != 64; qed");

	// verify the spend_auth_sig
	if !randomized_key.verify(&data_to_be_signed, &spend_auth_sig, FixedGenerators::SpendingKeyGenerator, &JUBJUB) {
		return Err(SpendError::BadSpendAuthSig);
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
	let is_verification_ok = verify_proof(&spend_vk.0, &zkproof, &public_input[..])
		.map_err(|err| SpendError::Proof(ProofError::Synthesis(err)))?;
	if !is_verification_ok {
		return Err(SpendError::Proof(ProofError::Failed));
	}

	Ok(())
}

fn accept_output(
	output_vk: &Groth16VerifyingKey,
	total: &mut Point,
	output: &SaplingOutputDescription,
) -> Result<(), OutputError> {
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
	let is_verification_ok = verify_proof(&output_vk.0, &zkproof, &public_input[..])
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
		.expect("only could fail if length of passed buffer != 64; qed");

	// check the binding signature
	let is_verification_ok = binding_verification_key
		.verify(&data_to_be_signed, &binding_sig, FixedGenerators::ValueCommitmentRandomness, &JUBJUB);
	if !is_verification_ok {
		return Err(Error::BadBindingSignature);
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
	extern crate test_data;

	use chain::Transaction;
	use script::{TransactionInputSigner, SighashBase};
	use super::*;

	// tx: https://zcash.blockexplorer.com/tx/bd4fe81c15cfbd125f5ca6fe51fb5ac4ef340e64a36f576a6a09f7528eb2e176
	fn test_tx() -> Transaction {
		"0400008085202f8900000000000072da060010270000000000000148b1c0668fce604361fbb1b89bbd76f8fee09b51a9dc0fdfcf6c6720cd596083d970234fcc0e9a70fdfed82d32fbb9ca92c9c5c3bad5daad9ac62b5bf4255817ee5bc95a9af453bb9cc7e2c544aa29efa20011a65b624998369c849aa8f0bc83d60e7902a3cfe6eeaeb8d583a491de5982c5ded29e64cd8f8fac594a5bb4f2838e6c30876e36a18d8d935238815c8d9205a4f1f523ff76b51f614bff1064d1c5fa0a27ec0c43c8a6c2714e7234d32e9a8934a3e9c0f74f1fdac2ddf6be3b13bc933b0478cae556a2d387cc23b05e8b0bd53d9e838ad2d2cb31daccefe256087511b044dfae665f0af0fa968edeea4cbb437a8099724159471adf7946eec434cccc1129f4d1e31d7f3f8be524226c65f28897d3604c14efb64bea6a889b2705617432927229dfa382e78c0ace31cc158fbf3ec1597242955e45af1ee5cfaffd789cc80dc53d6b18d42033ec2c327170e2811fe8ec00feadeb1033eb48ab24a6dce2480ad428be57c4619466fc3181ece69b914fed30566ff853250ef19ef7370601f4c24b0125e4059eec61f63ccbe277363172f2bdee384412ea073c5aca06b94e402ba3a43e15bd9c65bbfb194c561c24a031dec43be95c59eb6b568c176b1038d5b7b057dc032488335284adebfb6607e6a995b7fa418f13c8a61b343e5df44faa1050d9d76550748d9efebe01da97ade5937afd5f007ed26e0af03f283611655e91bc6a4857f66a57a1584ff687c4baf725f4a1b32fae53a3e6e8b98bca319bb1badb704c9c1a04f401f33d813d605eef6943c2c52dbc85ab7081d1f8f69d3202aae281bf42336a949a12a7dbbd22abdd6e92996282ebd69033c22cb0539d97f83636d6a8232209a7411e8b03bef180d83e608563ea2d0becff56dc996c2049df054961bfb21b7cbef5049a7dacc18f2c977aa1b2d48291abc19c3c8ea25d2e61901048354b17ce952f6f2248cf3a0eb54c19b507b41d7281c3d227e2b142ff695d8b925a4bb942ed9492a73a17468a8332a367fd16295420bdca6c04d380271f40440709998fce3a3af3e1e505f5402e5dd464dd179cb0eede3d494a95b84d2fb2eb5abb425cf2c712af999c65259c4782a5ec97388324c67738908a5ba43b6db62a10f50cddf9b5039123437c74165921ac8cf4f13292a216baef9d00bd544106b52755986c98a462ade1149f69367e926d88eb92798c0e56cd19a1bcf264fd93293033b758da65c7901eb5b4a17ee265a3312dbc477868da0057e1b3cbf47726dead6ecfcc8e1044c6f311ff0fc83192dc2f75a89626ba33364dac747b63ff3c8337e00332c8783ba9c8dc13cdf0750d7adc3926fbe1279017d50adba35c38c5b810f73abe5d759cd7fb650f6b0a1f78dc1f62fd017090ff4de4cf54c883752ddda68083d4617ed2c38bab8da313965dd3f7b755aec23a2d9e2965d08d2134827a72ffb3bd65b1fd5410da105bfba7a74ddff0928a654aca1ee211ac9dce8019ddcbb52263ce44b2544a314355c1e8c8543f3ed3e883e7a7a8f9e3c7c11f41ab9069854fb21e9b3660a860df19d289d54b29d82522b32d187cde6261eb0a429c3994dff6f37b9ab9102281223e3cd584790a909e05ba0ea1a2d9aef8e571986e98e09312dccaf8e739d718a1edd217dc4c8a5c8a650015405b592a7c674a451d7d1686c7ea6d93e74a8fe4ade12b679ac780457f08a79bfbf96dcf7eefe9a39b99f1ae39d2c5f86aadf156b7d5ce4b2733f307cfe1e1ff6de0ff2006d9cba535b0c40dfb7a98399cdff8e681fc38c7b9aa94ee5eb89432e28d94ee27f238776ba964a87caf58eddbb64771e64de094305a8eb848d2d9ad6373903687d22170f48f1ae8d714514034ee2733857af4747312bb006e6ce3918ede8c730bacc7821b81c1b93bb50b219e79e8e0d74531ed18c1145632d9847d38783b49141ac5353aaa7d125fb2934e681467e16b28090978e74e0b".into()
	}

	fn compute_sighash(tx: Transaction) -> [u8; 32] {
		let signer: TransactionInputSigner = tx.into();
		signer.signature_hash(&mut None, None, 0, &From::from(vec![]), SighashBase::All.into(), 0x76b809bb).into()
	}

	fn run_accept_sapling(tx: Transaction) -> Result<(), Error> {
		let spend_vk = crypto::load_sapling_spend_verifying_key().unwrap();
		let output_vk = crypto::load_sapling_output_verifying_key().unwrap();

		let sighash = compute_sighash(tx.clone());
		let sapling = tx.sapling.unwrap();

		accept_sapling(&spend_vk, &output_vk, &sighash, &sapling)
	}

	fn swap_xy(point: [u8; 32]) -> [u8; 32] {
		let mut new_point = [0; 32];
		new_point[..16].copy_from_slice(&point[16..]);
		new_point[16..].copy_from_slice(&point[..16]);
		new_point
	}

	fn small_order_point() -> [u8; 32] {
		[0; 32]
	}

	fn not_in_field_number() -> [u8; 32] {
		[0xFF; 32]
	}

	fn bad_signature() -> [u8; 64] {
		[0; 64]
	}

	fn bad_proof() -> [u8; 192] {
		[0; 192]
	}

	fn bad_verifying_key() -> Groth16VerifyingKey {
		use crypto::pairing::{CurveAffine, bls12_381::{G1Affine, G2Affine}};
		use crypto::bellman::groth16::{VerifyingKey, prepare_verifying_key};

		Groth16VerifyingKey(prepare_verifying_key(&VerifyingKey {
			alpha_g1: G1Affine::zero(),
			beta_g1: G1Affine::zero(),
			beta_g2: G2Affine::zero(),
			gamma_g2: G2Affine::zero(),
			delta_g1: G1Affine::zero(),
			delta_g2: G2Affine::zero(),
			ic: vec![],
		}))
	}

	#[test]
	fn accept_sapling_works() {
		run_accept_sapling(test_tx()).unwrap();
	}

	#[test]
	fn accept_spend_fails() {
		let spend_vk = crypto::load_sapling_spend_verifying_key().unwrap();
		let sighash = compute_sighash(test_tx());
		let sapling = test_tx().sapling.unwrap();
		let mut total = edwards::Point::zero();

		// when value commitment isn't an on-curve point
		let mut spend = sapling.spends[0].clone();
		spend.value_commitment = swap_xy(spend.value_commitment);
		assert_matches!(
			accept_spend(&spend_vk, &sighash, &mut total, &spend),
			Err(SpendError::ValueCommitment(PointError::Invalid(_)))
		);

		// when value commitment is a small order point
		let mut spend = sapling.spends[0].clone();
		spend.value_commitment = small_order_point();
		assert_matches!(
			accept_spend(&spend_vk, &sighash, &mut total, &spend),
			Err(SpendError::ValueCommitment(PointError::SmallOrder))
		);

		// when anchor is not in field
		let mut spend = sapling.spends[0].clone();
		spend.anchor = not_in_field_number();
		assert_matches!(
			accept_spend(&spend_vk, &sighash, &mut total, &spend),
			Err(SpendError::Anchor(_))
		);

		// when randomized key isn't represented by an on-curve point
		let mut spend = sapling.spends[0].clone();
		spend.randomized_key = swap_xy(spend.randomized_key);
		assert_matches!(
			accept_spend(&spend_vk, &sighash, &mut total, &spend),
			Err(SpendError::RandomizedKey(PointError::Invalid(_)))
		);

		// when randomized key is represented by a small order point
		let mut spend = sapling.spends[0].clone();
		spend.randomized_key = small_order_point();
		assert_matches!(
			accept_spend(&spend_vk, &sighash, &mut total, &spend),
			Err(SpendError::RandomizedKey(PointError::SmallOrder))
		);

		// when spend auth signature verification fails
		let mut spend = sapling.spends[0].clone();
		spend.spend_auth_sig = bad_signature();
		assert_matches!(
			accept_spend(&spend_vk, &sighash, &mut total, &spend),
			Err(SpendError::BadSpendAuthSig)
		);

		// when proof is failed to deserialize
		let mut spend = sapling.spends[0].clone();
		spend.zkproof = bad_proof();
		assert_matches!(
			accept_spend(&spend_vk, &sighash, &mut total, &spend),
			Err(SpendError::Proof(ProofError::Invalid(_)))
		);

		// when proof isn't compatible with verifying key
		assert_matches!(
			accept_spend(&bad_verifying_key(), &sighash, &mut total, &sapling.spends[0]),
			Err(SpendError::Proof(ProofError::Synthesis(_)))
		);

		// when proof verification has failed
		let mut spend = sapling.spends[0].clone();
		spend.nullifier = [0; 32];
		assert_matches!(
			accept_spend(&spend_vk, &sighash, &mut total, &spend),
			Err(SpendError::Proof(ProofError::Failed))
		);
	}

	#[test]
	fn accept_output_fails() {
		let output_vk = crypto::load_sapling_output_verifying_key().unwrap();
		let sapling = test_tx().sapling.unwrap();
		let mut total = edwards::Point::zero();

		// when value commitment isn't an on-curve point
		let mut output = sapling.outputs[0].clone();
		output.value_commitment = swap_xy(sapling.spends[0].value_commitment);
		assert_matches!(
			accept_output(&output_vk, &mut total, &output),
			Err(OutputError::ValueCommitment(PointError::Invalid(_)))
		);

		// when value commitment is a small order point
		let mut output = sapling.outputs[0].clone();
		output.value_commitment = small_order_point();
		assert_matches!(
			accept_output(&output_vk, &mut total, &output),
			Err(OutputError::ValueCommitment(PointError::SmallOrder))
		);

		// when note commitment is not in field
		let mut output = sapling.outputs[0].clone();
		output.note_commitment = not_in_field_number();
		assert_matches!(
			accept_output(&output_vk, &mut total, &output),
			Err(OutputError::NoteCommitment(_))
		);

		// when empeheral key isn't represented by an on-curve point
		let mut output = sapling.outputs[0].clone();
		output.ephemeral_key = swap_xy(output.ephemeral_key);
		assert_matches!(
			accept_output(&output_vk, &mut total, &output),
			Err(OutputError::EphemeralKey(PointError::Invalid(_)))
		);

		// when empeheral key is represented by a small order point
		let mut output = sapling.outputs[0].clone();
		output.ephemeral_key = small_order_point();
		assert_matches!(
			accept_output(&output_vk, &mut total, &output),
			Err(OutputError::EphemeralKey(PointError::SmallOrder))
		);

		// when proof is failed to deserialize
		let mut output = sapling.outputs[0].clone();
		output.zkproof = bad_proof();
		assert_matches!(
			accept_output(&output_vk, &mut total, &output),
			Err(OutputError::Proof(ProofError::Invalid(_)))
		);

		// when proof isn't compatible with verifying key
		assert_matches!(
			accept_output(&bad_verifying_key(), &mut total, &sapling.outputs[0]),
			Err(OutputError::Proof(ProofError::Synthesis(_)))
		);

		// when proof verification has failed
		let mut output = sapling.outputs[0].clone();
		output.note_commitment = output.value_commitment.clone();
		assert_matches!(
			accept_output(&output_vk, &mut total, &output),
			Err(OutputError::Proof(ProofError::Failed))
		);
	}

	#[test]
	fn accept_sapling_final_fails() {
		let sighash = compute_sighash(test_tx().clone());
		let sapling = test_tx().sapling.unwrap();

		// when total value is -i64::MAX
		let mut bad_sapling = sapling.clone();
		bad_sapling.balancing_value = ::std::i64::MIN;
		assert_matches!(
			accept_sapling_final(&sighash, Point::zero(), &bad_sapling),
			Err(Error::InvalidBalanceValue)
		);

		// when proof verification has failed
		assert_matches!(
			accept_sapling_final(&sighash, Point::zero(), &sapling),
			Err(Error::BadBindingSignature)
		);
	}
}
