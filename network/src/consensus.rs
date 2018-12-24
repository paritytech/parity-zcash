use keys::Address;
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

	/// 
	pub subsidy_slow_start_interval: u32,
	/// 
	pub subsidy_halving_interval: u32,
	///
	pub founders_addresses: Vec<Address>,

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

				subsidy_slow_start_interval: 20_000,
				subsidy_halving_interval: 840_000,
				founders_addresses: vec![
					"t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd".into(),
					"t3cL9AucCajm3HXDhb5jBnJK2vapVoXsop3".into(),
					"t3fqvkzrrNaMcamkQMwAyHRjfDdM2xQvDTR".into(),
					"t3TgZ9ZT2CTSK44AnUPi6qeNaHa2eC7pUyF".into(),
					"t3SpkcPQPfuRYHsP5vz3Pv86PgKo5m9KVmx".into(),
					"t3Xt4oQMRPagwbpQqkgAViQgtST4VoSWR6S".into(),
					"t3ayBkZ4w6kKXynwoHZFUSSgXRKtogTXNgb".into(),
					"t3adJBQuaa21u7NxbR8YMzp3km3TbSZ4MGB".into(),
					"t3K4aLYagSSBySdrfAGGeUd5H9z5Qvz88t2".into(),
					"t3RYnsc5nhEvKiva3ZPhfRSk7eyh1CrA6Rk".into(),
					"t3Ut4KUq2ZSMTPNE67pBU5LqYCi2q36KpXQ".into(),
					"t3ZnCNAvgu6CSyHm1vWtrx3aiN98dSAGpnD".into(),
					"t3fB9cB3eSYim64BS9xfwAHQUKLgQQroBDG".into(),
					"t3cwZfKNNj2vXMAHBQeewm6pXhKFdhk18kD".into(),
					"t3YcoujXfspWy7rbNUsGKxFEWZqNstGpeG4".into(),
					"t3bLvCLigc6rbNrUTS5NwkgyVrZcZumTRa4".into(),
					"t3VvHWa7r3oy67YtU4LZKGCWa2J6eGHvShi".into(),
					"t3eF9X6X2dSo7MCvTjfZEzwWrVzquxRLNeY".into(),
					"t3esCNwwmcyc8i9qQfyTbYhTqmYXZ9AwK3X".into(),
					"t3M4jN7hYE2e27yLsuQPPjuVek81WV3VbBj".into(),
					"t3gGWxdC67CYNoBbPjNvrrWLAWxPqZLxrVY".into(),
					"t3LTWeoxeWPbmdkUD3NWBquk4WkazhFBmvU".into(),
					"t3P5KKX97gXYFSaSjJPiruQEX84yF5z3Tjq".into(),
					"t3f3T3nCWsEpzmD35VK62JgQfFig74dV8C9".into(),
					"t3Rqonuzz7afkF7156ZA4vi4iimRSEn41hj".into(),
					"t3fJZ5jYsyxDtvNrWBeoMbvJaQCj4JJgbgX".into(),
					"t3Pnbg7XjP7FGPBUuz75H65aczphHgkpoJW".into(),
					"t3WeKQDxCijL5X7rwFem1MTL9ZwVJkUFhpF".into(),
					"t3Y9FNi26J7UtAUC4moaETLbMo8KS1Be6ME".into(),
					"t3aNRLLsL2y8xcjPheZZwFy3Pcv7CsTwBec".into(),
					"t3gQDEavk5VzAAHK8TrQu2BWDLxEiF1unBm".into(),
					"t3Rbykhx1TUFrgXrmBYrAJe2STxRKFL7G9r".into(),
					"t3aaW4aTdP7a8d1VTE1Bod2yhbeggHgMajR".into(),
					"t3YEiAa6uEjXwFL2v5ztU1fn3yKgzMQqNyo".into(),
					"t3g1yUUwt2PbmDvMDevTCPWUcbDatL2iQGP".into(),
					"t3dPWnep6YqGPuY1CecgbeZrY9iUwH8Yd4z".into(),
					"t3QRZXHDPh2hwU46iQs2776kRuuWfwFp4dV".into(),
					"t3enhACRxi1ZD7e8ePomVGKn7wp7N9fFJ3r".into(),
					"t3PkLgT71TnF112nSwBToXsD77yNbx2gJJY".into(),
					"t3LQtHUDoe7ZhhvddRv4vnaoNAhCr2f4oFN".into(),
					"t3fNcdBUbycvbCtsD2n9q3LuxG7jVPvFB8L".into(),
					"t3dKojUU2EMjs28nHV84TvkVEUDu1M1FaEx".into(),
					"t3aKH6NiWN1ofGd8c19rZiqgYpkJ3n679ME".into(),
					"t3MEXDF9Wsi63KwpPuQdD6by32Mw2bNTbEa".into(),
					"t3WDhPfik343yNmPTqtkZAoQZeqA83K7Y3f".into(),
					"t3PSn5TbMMAEw7Eu36DYctFezRzpX1hzf3M".into(),
					"t3R3Y5vnBLrEn8L6wFjPjBLnxSUQsKnmFpv".into(),
					"t3Pcm737EsVkGTbhsu2NekKtJeG92mvYyoN".into(),
				],

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

				subsidy_slow_start_interval: 20_000,
				subsidy_halving_interval: 840_000,
				founders_addresses: vec![
					"t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi".into(),
					"t2N9PH9Wk9xjqYg9iin1Ua3aekJqfAtE543".into(),
					"t2NGQjYMQhFndDHguvUw4wZdNdsssA6K7x2".into(),
					"t2ENg7hHVqqs9JwU5cgjvSbxnT2a9USNfhy".into(),
					"t2BkYdVCHzvTJJUTx4yZB8qeegD8QsPx8bo".into(),
					"t2J8q1xH1EuigJ52MfExyyjYtN3VgvshKDf".into(),
					"t2Crq9mydTm37kZokC68HzT6yez3t2FBnFj".into(),
					"t2EaMPUiQ1kthqcP5UEkF42CAFKJqXCkXC9".into(),
					"t2F9dtQc63JDDyrhnfpzvVYTJcr57MkqA12".into(),
					"t2LPirmnfYSZc481GgZBa6xUGcoovfytBnC".into(),
					"t26xfxoSw2UV9Pe5o3C8V4YybQD4SESfxtp".into(),
					"t2D3k4fNdErd66YxtvXEdft9xuLoKD7CcVo".into(),
					"t2DWYBkxKNivdmsMiivNJzutaQGqmoRjRnL".into(),
					"t2C3kFF9iQRxfc4B9zgbWo4dQLLqzqjpuGQ".into(),
					"t2MnT5tzu9HSKcppRyUNwoTp8MUueuSGNaB".into(),
					"t2AREsWdoW1F8EQYsScsjkgqobmgrkKeUkK".into(),
					"t2Vf4wKcJ3ZFtLj4jezUUKkwYR92BLHn5UT".into(),
					"t2K3fdViH6R5tRuXLphKyoYXyZhyWGghDNY".into(),
					"t2VEn3KiKyHSGyzd3nDw6ESWtaCQHwuv9WC".into(),
					"t2F8XouqdNMq6zzEvxQXHV1TjwZRHwRg8gC".into(),
					"t2BS7Mrbaef3fA4xrmkvDisFVXVrRBnZ6Qj".into(),
					"t2FuSwoLCdBVPwdZuYoHrEzxAb9qy4qjbnL".into(),
					"t2SX3U8NtrT6gz5Db1AtQCSGjrpptr8JC6h".into(),
					"t2V51gZNSoJ5kRL74bf9YTtbZuv8Fcqx2FH".into(),
					"t2FyTsLjjdm4jeVwir4xzj7FAkUidbr1b4R".into(),
					"t2EYbGLekmpqHyn8UBF6kqpahrYm7D6N1Le".into(),
					"t2NQTrStZHtJECNFT3dUBLYA9AErxPCmkka".into(),
					"t2GSWZZJzoesYxfPTWXkFn5UaxjiYxGBU2a".into(),
					"t2RpffkzyLRevGM3w9aWdqMX6bd8uuAK3vn".into(),
					"t2JzjoQqnuXtTGSN7k7yk5keURBGvYofh1d".into(),
					"t2AEefc72ieTnsXKmgK2bZNckiwvZe3oPNL".into(),
					"t2NNs3ZGZFsNj2wvmVd8BSwSfvETgiLrD8J".into(),
					"t2ECCQPVcxUCSSQopdNquguEPE14HsVfcUn".into(),
					"t2JabDUkG8TaqVKYfqDJ3rqkVdHKp6hwXvG".into(),
					"t2FGzW5Zdc8Cy98ZKmRygsVGi6oKcmYir9n".into(),
					"t2DUD8a21FtEFn42oVLp5NGbogY13uyjy9t".into(),
					"t2UjVSd3zheHPgAkuX8WQW2CiC9xHQ8EvWp".into(),
					"t2TBUAhELyHUn8i6SXYsXz5Lmy7kDzA1uT5".into(),
					"t2Tz3uCyhP6eizUWDc3bGH7XUC9GQsEyQNc".into(),
					"t2NysJSZtLwMLWEJ6MH3BsxRh6h27mNcsSy".into(),
					"t2KXJVVyyrjVxxSeazbY9ksGyft4qsXUNm9".into(),
					"t2J9YYtH31cveiLZzjaE4AcuwVho6qjTNzp".into(),
					"t2QgvW4sP9zaGpPMH1GRzy7cpydmuRfB4AZ".into(),
					"t2NDTJP9MosKpyFPHJmfjc5pGCvAU58XGa4".into(),
					"t29pHDBWq7qN4EjwSEHg8wEqYe9pkmVrtRP".into(),
					"t2Ez9KM8VJLuArcxuEkNRAkhNvidKkzXcjJ".into(),
					"t2D5y7J5fpXajLbGrMBQkFg2mFN8fo3n8cX".into(),
					"t2UV2wr1PTaUiybpkV3FdSdGxUJeZdZztyt".into(),
				],

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

				subsidy_slow_start_interval: 0,
				subsidy_halving_interval: 150,
				founders_addresses: vec![
					"t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg".into(),
				],

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

				subsidy_slow_start_interval: 0,
				subsidy_halving_interval: 150,
				founders_addresses: vec![
					"t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg".into(),
				],

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

	pub fn is_overwinter_active(&self, height: u32) -> bool {
		height >= self.overwinter_height
	}

	pub fn is_sapling_active(&self, height: u32) -> bool {
		height >= self.sapling_height
	}

	pub fn founder_address(&self, height: u32) -> Option<Address> {
		let last_founders_reward_block_height = self.subsidy_halving_interval + self.subsidy_slow_start_interval / 2 - 1;
		if height == 0 || height > last_founders_reward_block_height {
			return None;
		}

		let founders_len = self.founders_addresses.len() as u32;
		let address_change_interval = (last_founders_reward_block_height + founders_len) / founders_len;
		let address_index = height / address_change_interval;
		Some(self.founders_addresses[address_index as usize].clone())
	}

	pub fn founder_subsidy(&self, height: u32) -> u64 {
		let mut subsidy = 1250000000u64;
		if height < self.subsidy_slow_start_interval / 2 {
			subsidy /= self.subsidy_slow_start_interval as u64;
			subsidy *= height as u64;
		} else if height < self.subsidy_slow_start_interval {
			subsidy /= self.subsidy_slow_start_interval as u64;
			subsidy *= height as u64 + 1;
		} else {
			let halvings = (height - self.subsidy_slow_start_interval / 2) / self.subsidy_halving_interval;
			if halvings >= 64 {
				return 0;
			}

			subsidy >>= halvings as u64;
		}

		subsidy
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
