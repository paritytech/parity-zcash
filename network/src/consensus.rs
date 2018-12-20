use {Network, Magic, Deployment, crypto};

lazy_static! {
	static ref SAPLING_SPEND_VK: crypto::Groth16VerifyingKey = crypto::load_sapling_spend_verifying_key()
		.expect("hardcoded value should load without errors");
	static ref SAPLING_OUTPUT_VK: crypto::Groth16VerifyingKey = crypto::load_sapling_output_verifying_key()
		.expect("hardcoded value should load without errors");
}

#[derive(Debug, Clone)]
/// Parameters that influence chain consensus.
pub struct ConsensusParams {
	/// Network.
	pub network: Network,
	/// Time when BIP16 becomes active.
	/// See https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
	pub bip16_time: u32,
	/// Block height at which BIP34 becomes active.
	/// See https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
	pub bip34_height: u32,
	/// Block height at which BIP65 becomes active.
	/// See https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki
	pub bip65_height: u32,
	/// Block height at which BIP65 becomes active.
	/// See https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
	pub bip66_height: u32,
	/// Version bits activation
	pub rule_change_activation_threshold: u32,
	/// Number of blocks with the same set of rules
	pub miner_confirmation_window: u32,
	/// BIP68, BIP112, BIP113 deployment
	pub csv_deployment: Option<Deployment>,

	/// Height of Overwinter activation.
	/// Details: https://zcash.readthedocs.io/en/latest/rtd_pages/nu_dev_guide.html#overwinter
	pub overwinter_height: u32,
	/// Height of Sapling activation.
	/// Details: https://zcash.readthedocs.io/en/latest/rtd_pages/nu_dev_guide.html#sapling
	pub sapling_height: u32,

	/// Interval (in blocks) to calculate average work.
	pub pow_averaging_window: u32,
	/// % of possible down adjustment of work.
	pub pow_max_adjust_down: u32,
	/// % of possible up adjustment of work.
	pub pow_max_adjust_up: u32,
	/// Optimal blocks interval (in seconds).
	pub pow_target_spacing: u32,

	/// Equihash (N, K) parameters.
	pub equihash_params: Option<(u32, u32)>,

	/// Active key for pghr13 joinsplit verification
	pub joinsplit_verification_key: crypto::Pghr13VerifyingKey,

	/// Sapling spend verification key.
	pub sapling_spend_verifying_key: &'static crypto::Groth16VerifyingKey,
	/// Sapling output verification key.
	pub sapling_output_verifying_key: &'static crypto::Groth16VerifyingKey,
}

fn mainnet_pghr_verification_key() -> crypto::Pghr13VerifyingKey {
	use crypto::{G1, G2, Group};

	// TODO: Actually use group elements from ceremony
	crypto::Pghr13VerifyingKey {
		a: G2::one(),
		b: G1::one(),
		c: G2::one(),
		z: G2::one(),
		gamma: G2::one(),
		gamma_beta_1: G1::one(),
		gamma_beta_2: G2::one(),
		ic: Vec::new(),
	}
}

fn testnet_pghr_verification_key() -> crypto::Pghr13VerifyingKey {
	use crypto::{G1, G2, Group};

	// TODO: Actually use group elements for testnet
	crypto::Pghr13VerifyingKey {
		a: G2::one(),
		b: G1::one(),
		c: G2::one(),
		z: G2::one(),
		gamma: G2::one(),
		gamma_beta_1: G1::one(),
		gamma_beta_2: G2::one(),
		ic: Vec::new(),
	}
}

fn regtest_pghr_verification_key() -> crypto::Pghr13VerifyingKey {
	use crypto::{G1, G2, Group};

	// TODO: Actually use group elements for regtests
	crypto::Pghr13VerifyingKey {
		a: G2::one(),
		b: G1::one(),
		c: G2::one(),
		z: G2::one(),
		gamma: G2::one(),
		gamma_beta_1: G1::one(),
		gamma_beta_2: G2::one(),
		ic: Vec::new(),
	}
}

fn unitest_pghr_verification_key() -> crypto::Pghr13VerifyingKey {
	use crypto::{G1, G2, Group};

	// TODO: Actually use group elements for unit tests
	crypto::Pghr13VerifyingKey {
		a: G2::one(),
		b: G1::one(),
		c: G2::one(),
		z: G2::one(),
		gamma: G2::one(),
		gamma_beta_1: G1::one(),
		gamma_beta_2: G2::one(),
		ic: Vec::new(),
	}
}

impl ConsensusParams {
	pub fn new(network: Network) -> Self {
		match network {
			Network::Mainnet | Network::Other(_) => ConsensusParams {
				network: network,
				bip16_time: 0,
				bip34_height: 1,
				bip65_height: 0,
				bip66_height: 0,
				rule_change_activation_threshold: 1916, // 95%
				miner_confirmation_window: 2016,
				csv_deployment: None,

				overwinter_height: 347500,
				sapling_height: 419200,

				pow_averaging_window: 17,
				pow_max_adjust_down: 32,
				pow_max_adjust_up: 16,
				pow_target_spacing: (2.5 * 60.0) as u32,

				equihash_params: Some((200, 9)),

				joinsplit_verification_key: mainnet_pghr_verification_key(),

				sapling_spend_verifying_key: &SAPLING_SPEND_VK,
				sapling_output_verifying_key: &SAPLING_OUTPUT_VK,
			},
			Network::Testnet => ConsensusParams {
				network: network,
				bip16_time: 0,
				bip34_height: 1,
				bip65_height: 0,
				bip66_height: 0,
				rule_change_activation_threshold: 1512, // 75%
				miner_confirmation_window: 2016,
				csv_deployment: None,

				overwinter_height: 207500,
				sapling_height: 280000,

				pow_averaging_window: 17,
				pow_max_adjust_down: 32,
				pow_max_adjust_up: 16,
				pow_target_spacing: (2.5 * 60.0) as u32,

				equihash_params: Some((200, 9)),

				joinsplit_verification_key: testnet_pghr_verification_key(),

				sapling_spend_verifying_key: &SAPLING_SPEND_VK,
				sapling_output_verifying_key: &SAPLING_OUTPUT_VK,
			},
			Network::Regtest => ConsensusParams {
				network: network,
				bip16_time: 0,
				bip34_height: 100000000,
				bip65_height: 0,
				bip66_height: 0,
				rule_change_activation_threshold: 108, // 75%
				miner_confirmation_window: 144,
				csv_deployment: None,

				overwinter_height: ::std::u32::MAX,
				sapling_height: ::std::u32::MAX,

				pow_averaging_window: 17,
				pow_max_adjust_down: 0,
				pow_max_adjust_up: 0,
				pow_target_spacing: (2.5 * 60.0) as u32,

				equihash_params: Some((200, 9)),

				joinsplit_verification_key: regtest_pghr_verification_key(),

				sapling_spend_verifying_key: &SAPLING_SPEND_VK,
				sapling_output_verifying_key: &SAPLING_OUTPUT_VK,
			},
			Network::Unitest => ConsensusParams {
				network: network,
				bip16_time: 0,
				bip34_height: 100000000,
				bip65_height: 0,
				bip66_height: 0,
				rule_change_activation_threshold: 108, // 75%
				miner_confirmation_window: 144,
				csv_deployment: None,

				overwinter_height: ::std::u32::MAX,
				sapling_height: ::std::u32::MAX,

				pow_averaging_window: 17,
				pow_max_adjust_down: 0,
				pow_max_adjust_up: 0,
				pow_target_spacing: (2.5 * 60.0) as u32,

				equihash_params: None,

				joinsplit_verification_key: unitest_pghr_verification_key(),

				sapling_spend_verifying_key: &SAPLING_SPEND_VK,
				sapling_output_verifying_key: &SAPLING_OUTPUT_VK,
			},
		}
	}

	pub fn magic(&self) -> Magic {
		self.network.magic()
	}

	pub fn averaging_window_timespan(&self) -> u32 {
		self.pow_averaging_window * self.pow_target_spacing
	}

	pub fn min_actual_timespan(&self) -> u32 {
		(self.averaging_window_timespan() * (100 - self.pow_max_adjust_up)) / 100
	}

	pub fn max_actual_timespan(&self) -> u32 {
		(self.averaging_window_timespan() * (100 + self.pow_max_adjust_down)) / 100
	}

	pub fn min_block_version(&self) -> u32 {
		4
	}

	pub fn max_block_size(&self) -> usize {
		2_000_000
	}

	pub fn max_block_sigops(&self) -> usize {
		20_000
	}

	pub fn max_transaction_value(&self) -> i64 {
		21_000_000 * 100_000_000 // No amount larger than this (in satoshi) is valid
	}

	pub fn absolute_max_transaction_size(&self) -> usize {
		2_000_000
	}

	pub fn max_transaction_size(&self, height: u32) -> usize {
		if height >= self.sapling_height {
			2_000_000
		} else {
			100_000
		}
	}

	pub fn transaction_expiry_height_threshold(&self) -> u32 {
		500_000_000
	}

	pub fn consensus_branch_id(&self, height: u32) -> u32 {
		// sapling upgrade
		if height >= self.sapling_height {
			return 0x76b809bb;
		}

		// overwinter upgrade
		if height >= self.overwinter_height {
			return 0x5ba81b19;
		}

		// sprout
		0
	}
}
