
pub fn mainnet_seednodes() -> Vec<&'static str> {
	vec![
		// Pieter Wuille
		"seed.bitcoin.sipa.be:8333",
		// Matt Corallo
		"dnsseed.bluematt.me:8333",
		// Luke Dashjr
		"dnsseed.bitcoin.dashjr.org:8333",
		// Christian Decker
		"seed.bitcoinstats.com:8333",
		// Jonas Schnelli
		"seed.bitcoin.jonasschnelli.ch:8333",
		// Peter Todd
		"seed.btc.petertodd.org:8333",
		//
		"seed.voskuil.org:8333",
	]
}

pub fn testnet_seednodes() -> Vec<&'static str> {
	vec![
		"testnet-seed.bitcoin.jonasschnelli.ch:18333",
		"seed.tbtc.petertodd.org:18333",
		"testnet-seed.bluematt.me:18333",
		"testnet-seed.bitcoin.schildbach.de:18333",
		"testnet-seed.voskuil.org:18333",
	]
}

pub fn bitcoin_cash_seednodes() -> Vec<&'static str> {
	vec![
		"cash-seed.bitcoin.thomaszander.se:8333",
		"seed.bitprim.org:8333",
	]
}

pub fn bitcoin_cash_testnet_seednodes() -> Vec<&'static str> {
	vec![
		"testnet-seed-abc.bitcoinforks.org:18333",
		"testnet-seed.bitprim.org:18333",
	]
}

pub fn zcash_seednodes() -> Vec<&'static str> {
	vec![
		"dnsseed.z.cash:8233",
		"dnsseed.str4d.xyz:8233",
		"dnsseed.znodes.org:8233",
	]
}
