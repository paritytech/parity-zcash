use hex::FromHex;
use hash::H256;
use ser::{deserialize};
use merkle_root::merkle_root;
use {BlockHeader, Transaction};
use super::RepresentH256;

#[derive(Debug, PartialEq, Clone, Serializable, Deserializable)]
pub struct Block {
	pub block_header: BlockHeader,
	pub transactions: Vec<Transaction>,
}

impl From<&'static str> for Block {
	fn from(s: &'static str) -> Self {
		deserialize(&s.from_hex().unwrap() as &[u8]).unwrap()
	}
}

impl RepresentH256 for Block {
	fn h256(&self) -> H256 { self.hash() }
}

impl Block {
	pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
		Block { block_header: header, transactions: transactions }
	}

	/// Returns block's merkle root.
	pub fn merkle_root(&self) -> H256 {
		let hashes = self.transactions.iter().map(Transaction::hash).collect::<Vec<H256>>();
		merkle_root(&hashes)
	}

	/// Returns block's witness merkle root.
	pub fn witness_merkle_root(&self) -> H256 {
		let hashes = match self.transactions.split_first() {
			None => vec![],
			Some((_, rest)) => {
				let mut hashes = vec![H256::from(0)];
				hashes.extend(rest.iter().map(Transaction::witness_hash));
				hashes
			},
		};
		merkle_root(&hashes)
	}

	pub fn transactions(&self) -> &[Transaction] {
		&self.transactions
	}

	pub fn header(&self) -> &BlockHeader {
		&self.block_header
	}

	pub fn hash(&self) -> H256 {
		self.block_header.hash()
	}
}

#[cfg(test)]
mod tests {
	use rustc_serialize::hex::FromHex;
	use ser::{set_default_flags, serialize_with_flags, deserialize_with_flags, SERIALIZE_ZCASH, DESERIALIZE_ZCASH};
	use hash::H256;
	use super::Block;

	// Block 80000
	// https://blockchain.info/rawblock/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6
	// https://blockchain.info/rawblock/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6?format=hex
	#[test]
	fn test_block_merkle_root_and_hash() {
		let block: Block = "01000000ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b9137190000000000190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f33a5914ce6ed5b1b01e32f570201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704e6ed5b1b014effffffff0100f2052a01000000434104b68a50eaa0287eff855189f949c1c6e5f58b37c88231373d8a59809cbae83059cc6469d65c665ccfd1cfeb75c6e8e19413bba7fbff9bc762419a76d87b16086eac000000000100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000".into();
		let merkle_root = H256::from_reversed_str("8fb300e3fdb6f30a4c67233b997f99fdd518b968b9a3fd65857bfe78b2600719");
		let hash = H256::from_reversed_str("000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6");
		assert_eq!(block.merkle_root(), merkle_root);
		assert_eq!(block.hash(), hash);
	}

	#[test]
	fn zcash_genesis_block_is_parsed() {
		set_default_flags(SERIALIZE_ZCASH);

		let origin_hash = H256::from_reversed_str("00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08");
		let origin = "040000000000000000000000000000000000000000000000000000000000000000000000db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac4000000000000000000000000000000000000000000000000000000000000000090041358ffff071f5712000000000000000000000000000000000000000000000000000000000000fd4005000a889f00854b8665cd555f4656f68179d31ccadc1b1f7fb0952726313b16941da348284d67add4686121d4e3d930160c1348d8191c25f12b267a6a9c131b5031cbf8af1f79c9d513076a216ec87ed045fa966e01214ed83ca02dc1797270a454720d3206ac7d931a0a680c5c5e099057592570ca9bdf6058343958b31901fce1a15a4f38fd347750912e14004c73dfe588b903b6c03166582eeaf30529b14072a7b3079e3a684601b9b3024054201f7440b0ee9eb1a7120ff43f713735494aa27b1f8bab60d7f398bca14f6abb2adbf29b04099121438a7974b078a11635b594e9170f1086140b4173822dd697894483e1c6b4e8b8dcd5cb12ca4903bc61e108871d4d915a9093c18ac9b02b6716ce1013ca2c1174e319c1a570215bc9ab5f7564765f7be20524dc3fdf8aa356fd94d445e05ab165ad8bb4a0db096c097618c81098f91443c719416d39837af6de85015dca0de89462b1d8386758b2cf8a99e00953b308032ae44c35e05eb71842922eb69797f68813b59caf266cb6c213569ae3280505421a7e3a0a37fdf8e2ea354fc5422816655394a9454bac542a9298f176e211020d63dee6852c40de02267e2fc9d5e1ff2ad9309506f02a1a71a0501b16d0d36f70cdfd8de78116c0c506ee0b8ddfdeb561acadf31746b5a9dd32c21930884397fb1682164cb565cc14e089d66635a32618f7eb05fe05082b8a3fae620571660a6b89886eac53dec109d7cbb6930ca698a168f301a950be152da1be2b9e07516995e20baceebecb5579d7cdbc16d09f3a50cb3c7dffe33f26686d4ff3f8946ee6475e98cf7b3cf9062b6966e838f865ff3de5fb064a37a21da7bb8dfd2501a29e184f207caaba364f36f2329a77515dcb710e29ffbf73e2bbd773fab1f9a6b005567affff605c132e4e4dd69f36bd201005458cfbd2c658701eb2a700251cefd886b1e674ae816d3f719bac64be649c172ba27a4fd55947d95d53ba4cbc73de97b8af5ed4840b659370c556e7376457f51e5ebb66018849923db82c1c9a819f173cccdb8f3324b239609a300018d0fb094adf5bd7cbb3834c69e6d0b3798065c525b20f040e965e1a161af78ff7561cd874f5f1b75aa0bc77f720589e1b810f831eac5073e6dd46d00a2793f70f7427f0f798f2f53a67e615e65d356e66fe40609a958a05edb4c175bcc383ea0530e67ddbe479a898943c6e3074c6fcc252d6014de3a3d292b03f0d88d312fe221be7be7e3c59d07fa0f2f4029e364f1f355c5d01fa53770d0cd76d82bf7e60f6903bc1beb772e6fde4a70be51d9c7e03c8d6d8dfb361a234ba47c470fe630820bbd920715621b9fbedb49fcee165ead0875e6c2b1af16f50b5d6140cc981122fcbcf7c5a4e3772b3661b628e08380abc545957e59f634705b1bbde2f0b4e055a5ec5676d859be77e20962b645e051a880fddb0180b4555789e1f9344a436a84dc5579e2553f1e5fb0a599c137be36cabbed0319831fea3fddf94ddc7971e4bcf02cdc93294a9aab3e3b13e3b058235b4f4ec06ba4ceaa49d675b4ba80716f3bc6976b1fbf9c8bf1f3e3a4dc1cd83ef9cf816667fb94f1e923ff63fef072e6a19321e4812f96cb0ffa864da50ad74deb76917a336f31dce03ed5f0303aad5e6a83634f9fcc371096f8288b8f02ddded5ff1bb9d49331e4a84dbe1543164438fde9ad71dab024779dcdde0b6602b5ae0a6265c14b94edd83b37403f4b78fcd2ed555b596402c28ee81d87a909c4e8722b30c71ecdd861b05f61f8b1231795c76adba2fdefa451b283a5d527955b9f3de1b9828e7b2e74123dd47062ddcc09b05e7fa13cb2212a6fdbc65d7e852cec463ec6fd929f5b8483cf3052113b13dac91b69f49d1b7d1aec01c4a68e41ce1570101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334ffffffff010000000000000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

		let origin = origin.from_hex().unwrap();
		let parsed: Block = deserialize_with_flags(&origin as &[u8], DESERIALIZE_ZCASH).unwrap();
		let serialized = serialize_with_flags(&parsed, SERIALIZE_ZCASH).take();
		assert_eq!(origin, serialized);

		let parsed_hash = parsed.hash();
		assert_eq!(origin_hash, parsed_hash);
	}
}
