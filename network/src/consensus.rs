use {Network, Magic, Deployment};

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

	/// Interval (in blocks) to calculate average work.
	pub pow_averaging_window: u32,
	/// % of possible down adjustment of work.
	pub pow_max_adjust_down: u32,
	/// % of possible up adjustment of work.
	pub pow_max_adjust_up: u32,
	/// Optimal blocks interval (in seconds).
	pub pow_target_spacing: u32,
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

				pow_averaging_window: 17,
				pow_max_adjust_down: 32,
				pow_max_adjust_up: 16,
				pow_target_spacing: (2.5 * 60.0) as u32,
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

				pow_averaging_window: 17,
				pow_max_adjust_down: 32,
				pow_max_adjust_up: 16,
				pow_target_spacing: (2.5 * 60.0) as u32,
			},
			Network::Regtest | Network::Unitest => ConsensusParams {
				network: network,
				bip16_time: 0,
				bip34_height: 100000000,
				bip65_height: 0,
				bip66_height: 0,
				rule_change_activation_threshold: 108, // 75%
				miner_confirmation_window: 144,
				csv_deployment: None,

				pow_averaging_window: 17,
				pow_max_adjust_down: 0,
				pow_max_adjust_up: 0,
				pow_target_spacing: (2.5 * 60.0) as u32,
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

	pub fn max_block_size(&self) -> usize {
		2_000_000
	}

	pub fn max_block_sigops(&self) -> usize {
		20_000
	}

	pub fn max_transaction_size(&self) -> usize {
		100_000 // TODO: changed after sapling
	}
}
