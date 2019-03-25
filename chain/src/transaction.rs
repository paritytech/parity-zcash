//! Bitcoin transaction.
//! https://en.bitcoin.it/wiki/Protocol_documentation#tx

use std::io;
use heapsize::HeapSizeOf;
use hex::FromHex;
use bytes::Bytes;
use ser::{deserialize, serialize};
use crypto::dhash256;
use hash::H256;
use constants::{SEQUENCE_FINAL, LOCKTIME_THRESHOLD};
use join_split::{JoinSplit, deserialize_join_split, serialize_join_split};
use sapling::Sapling;
use ser::{Error, Serializable, Deserializable, Stream, Reader};

/// Original bitcoin transaction version.
pub const BTC_TX_VERSION: i32 = 1;
/// Sprout-era transaction version wit JS.
pub const SPROUT_TX_VERSION: i32 = 2;
/// Overwinter-era transaction version.
pub const OVERWINTER_TX_VERSION: i32 = 3;
/// Sapling-era transaction version.
pub const SAPLING_TX_VERSION: i32 = 4;

/// Overwinter version group id.
pub const OVERWINTER_TX_VERSION_GROUP_ID: u32 = 0x03C48270;
/// Sapling version group id.
pub const SAPLING_TX_VERSION_GROUP_ID: u32 = 0x892F2085;

#[derive(Debug, PartialEq, Eq, Clone, Default, Serializable, Deserializable, Hash)]
pub struct OutPoint {
	pub hash: H256,
	pub index: u32,
}

impl OutPoint {
	pub fn null() -> Self {
		OutPoint {
			hash: H256::default(),
			index: u32::max_value(),
		}
	}

	pub fn is_null(&self) -> bool {
		self.hash.is_zero() && self.index == u32::max_value()
	}
}

#[derive(Debug, PartialEq, Default, Clone)]
pub struct TransactionInput {
	pub previous_output: OutPoint,
	pub script_sig: Bytes,
	pub sequence: u32,
}

impl TransactionInput {
	pub fn coinbase(script_sig: Bytes) -> Self {
		TransactionInput {
			previous_output: OutPoint::null(),
			script_sig: script_sig,
			sequence: SEQUENCE_FINAL,
		}
	}

	pub fn is_final(&self) -> bool {
		self.sequence == SEQUENCE_FINAL
	}
}

impl HeapSizeOf for TransactionInput {
	fn heap_size_of_children(&self) -> usize {
		self.script_sig.heap_size_of_children()
	}
}

#[derive(Debug, PartialEq, Clone, Serializable, Deserializable)]
pub struct TransactionOutput {
	pub value: u64,
	pub script_pubkey: Bytes,
}

impl Default for TransactionOutput {
	fn default() -> Self {
		TransactionOutput {
			value: 0xffffffffffffffffu64,
			script_pubkey: Bytes::default(),
		}
	}
}

impl HeapSizeOf for TransactionOutput {
	fn heap_size_of_children(&self) -> usize {
		self.script_pubkey.heap_size_of_children()
	}
}

#[derive(Debug, PartialEq, Default, Clone)]
pub struct Transaction {
	pub overwintered: bool,
	pub version: i32,
	pub version_group_id: u32,
	pub inputs: Vec<TransactionInput>,
	pub outputs: Vec<TransactionOutput>,
	pub lock_time: u32,
	pub expiry_height: u32,
	pub join_split: Option<JoinSplit>,
	pub sapling: Option<Sapling>,
}

impl From<&'static str> for Transaction {
	fn from(s: &'static str) -> Self {
		deserialize(&s.from_hex::<Vec<u8>>().unwrap() as &[u8]).unwrap()
	}
}

impl HeapSizeOf for Transaction {
	fn heap_size_of_children(&self) -> usize {
		self.inputs.heap_size_of_children() + self.outputs.heap_size_of_children()
	}
}

impl Transaction {
	/// Returns version as it is serialized (including overwintered flag).
	pub fn serialized_version(&self) -> u32 {
		let mut version = self.version as u32;
		if self.overwintered {
			version = version | 0x80000000;
		}
		version
	}

	#[cfg(any(test, feature = "test-helpers"))]
	pub fn hash(&self) -> H256 {
		transaction_hash(self)
	}

	pub fn inputs(&self) -> &[TransactionInput] {
		&self.inputs
	}

	pub fn outputs(&self) -> &[TransactionOutput] {
		&self.outputs
	}

	pub fn is_empty(&self) -> bool {
		self.inputs.is_empty() || self.outputs.is_empty()
	}

	pub fn is_null(&self) -> bool {
		self.inputs.iter().any(|input| input.previous_output.is_null())
	}

	pub fn is_coinbase(&self) -> bool {
		self.inputs.len() == 1 && self.inputs[0].previous_output.is_null()
	}

	pub fn is_final(&self) -> bool {
		// if lock_time is 0, transaction is final
		if self.lock_time == 0 {
			return true;
		}
		// setting all sequence numbers to 0xffffffff disables the time lock, so if you want to use locktime,
		// at least one input must have a sequence number below the maximum.
		self.inputs.iter().all(TransactionInput::is_final)
	}

	pub fn is_final_in_block(&self, block_height: u32, block_time: u32) -> bool {
		if self.lock_time == 0 {
			return true;
		}

		let max_lock_time = if self.lock_time < LOCKTIME_THRESHOLD {
			block_height
		} else {
			block_time
		};

		if self.lock_time < max_lock_time {
			return true;
		}

		self.inputs.iter().all(TransactionInput::is_final)
	}

	pub fn total_spends(&self) -> u64 {
		let mut result = 0u64;
		for output in self.outputs.iter() {
			if u64::max_value() - result < output.value {
				return u64::max_value();
			}
			result += output.value;
		}
		result
	}
}

impl Serializable for TransactionInput {
	fn serialize(&self, stream: &mut Stream) {
		stream
			.append(&self.previous_output)
			.append(&self.script_sig)
			.append(&self.sequence);
	}
}

impl Deserializable for TransactionInput {
	fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error> where Self: Sized, T: io::Read {
		Ok(TransactionInput {
			previous_output: reader.read()?,
			script_sig: reader.read()?,
			sequence: reader.read()?,
		})
	}
}

impl Serializable for Transaction {
	fn serialize(&self, stream: &mut Stream) {
		stream.append(&self.serialized_version());
		if self.overwintered {
			stream.append(&self.version_group_id);
		}

		stream.append_list(&self.inputs)
			.append_list(&self.outputs)
			.append(&self.lock_time);

		if self.overwintered {
			stream.append(&self.expiry_height);
		}

		if let Some(sapling) = self.sapling.as_ref() {
			stream.append(&sapling.balancing_value)
				.append_list(&sapling.spends)
				.append_list(&sapling.outputs);
		}

		if self.version >= SPROUT_TX_VERSION {
			serialize_join_split(stream, &self.join_split);
		}

		if let Some(sapling) = self.sapling.as_ref() {
			if !sapling.spends.is_empty() || !sapling.outputs.is_empty() {
				stream.append(&sapling.binding_sig);
			}
		}
	}
}

impl Deserializable for Transaction {
	fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error> where Self: Sized, T: io::Read {
		// original bitcoin tx format:
		// version (1), inputs, outputs, lock_time
		//
		// sprout format:
		// version (2), inputs, outputs, lock_time, joint split
		//
		// overwinter format (ZIP 202):
		// overwintered, version (3), version group, inputs, outputs, lock_time, expiry height, joint split
		//
		// sapling format:
		// overwintered, version (4), version group, inputs, outputs, lock_time, expiry height, joint split

		let version: u32 = reader.read()?;
		let overwintered = (version & 0x80000000) != 0;
		let version = (version & 0x7FFFFFFF) as i32;

		let version_group_id = if overwintered {
			reader.read()?
		} else {
			0
		};

		// reject overwintered transactions of unknown versions
		let is_overwinter_tx = overwintered && version == OVERWINTER_TX_VERSION && version_group_id == OVERWINTER_TX_VERSION_GROUP_ID;
		let is_sapling_tx = overwintered && version == SAPLING_TX_VERSION && version_group_id == SAPLING_TX_VERSION_GROUP_ID;
		if overwintered && !is_overwinter_tx && !is_sapling_tx {
			return Err(Error::InvalidFormat(format!("Invalid overwinter transaction version: {}, version group: {}",
				version, version_group_id)));
		}

		let inputs: Vec<TransactionInput> = reader.read_list()?;
		let outputs = reader.read_list()?;
		let lock_time = reader.read()?;

		let expiry_height = if is_overwinter_tx || is_sapling_tx {
			reader.read()?
		} else {
			0
		};

		let mut sapling = if is_sapling_tx {
			let balancing_value = reader.read()?;
			let spends = reader.read_list()?;
			let outputs = reader.read_list()?;
			Some(Sapling {
				balancing_value,
				spends,
				outputs,
				..Default::default()
			})
		} else {
			None
		};

		let join_split = if version >= SPROUT_TX_VERSION {
			let use_groth = overwintered && version >= SAPLING_TX_VERSION;
			deserialize_join_split(reader, use_groth)?
		} else {
			None
		};

		if let Some(sapling) = sapling.as_mut() {
			if !sapling.spends.is_empty() || !sapling.outputs.is_empty() {
				sapling.binding_sig = reader.read()?;
			}
		}

		Ok(Transaction {
			overwintered,
			version,
			version_group_id,
			inputs,
			outputs,
			lock_time,
			expiry_height,
			join_split,
			sapling,
		})
	}
}

pub(crate) fn transaction_hash(transaction: &Transaction) -> H256 {
	dhash256(&serialize(transaction))
}

#[cfg(test)]
mod tests {
	use hex::ToHex;
	use hash::H256;
	use ser::{Serializable, serialize};
	use super::Transaction;

	// real transaction from Zcash block 30003
	// https://zcash.blockexplorer.com/api/rawtx/54c8acf69271dad83e9faa34284cda725caa5bea7378db92acf35becd0989463
	#[test]
	fn test_transparent_only_transaction() {
		let hex = "0100000003cfe0214a992ed056767bf963091b1cdce9a6d8585fc8bf91e7670e813bca36cfa40000006a47304402201380ad195adf528b05e6c78322434d40b0cd08f676611bf86733179c2851229102202f7ebeceffead9fe62e36126d1f15acf8c577558fff43a09aa7373c367465e7c012102ec25f8fb5efcac5b6424fd16faafdb0c24b71d7b21695dc020e1665c98da74d4feffffffeda306bdfd48c01fed953e87423ef371068bca6b4014e90da02744dda46cbbec8f0000006a47304402200a4c28685c28c7838e16100579976793f46d395f861ab103cd526a7ea69eec6602203a1410646f6cbbc336714de0dfd1d010ff3498759fe826117b87237e12e46a22012103c2a6d838e8931fe8d54c8f80b5e47a30d0ed95e7887f24c398836c57cd9a828efeffffff2dfb5bbe7cdd99757d215ad0c982274d96c560235bcec98fd5a3c30ff188df31030000006b483045022100c78051999c9a924588b09efb7320a6db2a9993132f5db2ee21864496d43386a90220494227e6b6504e92e29217cefc9fc1dea8b0ce221d678e6a0737e9aa1358081a012102a41cd4db977e834981915ef220566956cb4399305490ad4399396b1218989b55feffffff0240420f00000000001976a914c269627d8f5329930ce4259c1cc84cfa8d48f3ca88aca0d92164000000001976a9148061115677d41cd5661b86a6f9c288fbeb9d8e1f88ac28750000";

		// deserialize && check tx
		let t: Transaction = hex.into();
		assert_eq!(t.overwintered, false);
		assert_eq!(t.version, 1);
		assert_eq!(t.version_group_id, 0);
		assert_eq!(t.lock_time, 29992);
		assert_eq!(t.expiry_height, 0);
		assert_eq!(t.inputs.len(), 3);
		assert_eq!(t.outputs.len(), 2);
		let tx_input = &t.inputs[0];
		assert_eq!(tx_input.sequence, 4294967294);
		assert_eq!(tx_input.script_sig, "47304402201380ad195adf528b05e6c78322434d40b0cd08f676611bf86733179c2851229102202f7ebeceffead9fe62e36126d1f15acf8c577558fff43a09aa7373c367465e7c012102ec25f8fb5efcac5b6424fd16faafdb0c24b71d7b21695dc020e1665c98da74d4".into());
		let tx_input = &t.inputs[1];
		assert_eq!(tx_input.sequence, 4294967294);
		assert_eq!(tx_input.script_sig, "47304402200a4c28685c28c7838e16100579976793f46d395f861ab103cd526a7ea69eec6602203a1410646f6cbbc336714de0dfd1d010ff3498759fe826117b87237e12e46a22012103c2a6d838e8931fe8d54c8f80b5e47a30d0ed95e7887f24c398836c57cd9a828e".into());
		let tx_input = &t.inputs[2];
		assert_eq!(tx_input.sequence, 4294967294);
		assert_eq!(tx_input.script_sig, "483045022100c78051999c9a924588b09efb7320a6db2a9993132f5db2ee21864496d43386a90220494227e6b6504e92e29217cefc9fc1dea8b0ce221d678e6a0737e9aa1358081a012102a41cd4db977e834981915ef220566956cb4399305490ad4399396b1218989b55".into());
		let tx_output = &t.outputs[0];
		assert_eq!(tx_output.value, 1000000);
		assert_eq!(tx_output.script_pubkey, "76a914c269627d8f5329930ce4259c1cc84cfa8d48f3ca88ac".into());
		let tx_output = &t.outputs[1];
		assert_eq!(tx_output.value, 1679940000);
		assert_eq!(tx_output.script_pubkey, "76a9148061115677d41cd5661b86a6f9c288fbeb9d8e1f88ac".into());
		assert!(t.join_split.is_none());
		assert!(t.sapling.is_none());

		// serialize && check tx
		let t: String = serialize(&t).to_hex();
		assert_eq!(t, hex);
	}

	// real transaction from Zcash block 396
	// https://zcash.blockexplorer.com/api/rawtx/ec31a1b3e18533702c74a67d91c49d622717bd53d6192c5cb23b9bdf080416a5
	#[test]
	fn test_sprout_transaction() {
		let hex = "02000000010a141a3f21ed57fa8449ceac0b11909f1b5560f06b772753ca008d49675d45310000000048473044022041aaea8391c0182bf71bd974662e99534d99849b167062f7e8372c4f1a16c2d50220291b2ca6ae7616cd1f1bfddcda5ef2f53d78c2e153d3a8db571885f9adb5f05401ffffffff0000000000011070d900000000000000000000000000d7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd2597ae7c48e86173b231e84fbdcb4d8f569f28f71ebf0f9b5867f9d4c12e031a2acc0108235936d2fa2d2c968654fbea2a89fde8522ec7c227d2ff3c10bff9c1197d8a290cca91f23792df8e56aed6c142eaa322e66360b5c49132b940689fb2bc5e77f7877bba6d2c4425d9861515cbe8a5c87dfd7cf159e9d4ac9ff63c096fbcd91d2a459877b1ed40748e2f020cdc678cf576a62c63138d820aba3df4074014bb1624b703774e138c706ba394698fd33c58424bb1a8d22be0d7bc8fe58d369e89836fe673c246d8d0cb1d7e1cc94acfa5b8d76010db8d53a36a3f0e33f0ccbc0f861b5e3d0a92e1c05c6bca775ba7389f6444f0e6cbd34141953220718594664022cbbb59465c880f50d42d0d49d6422197b5f823c2b3ffdb341869b98ed2eb2fd031b271702bda61ff885788363a7cf980a134c09a24c9911dc94cbe970bd613b700b0891fe8b8b05d9d2e7e51df9d6959bdf0a3f2310164afb197a229486a0e8e3808d76c75662b568839ebac7fbf740db9d576523282e6cdd1adf8b0f9c183ae95b0301fa1146d35af869cc47c51cfd827b7efceeca3c55884f54a68e38ee7682b5d102131b9b1198ed371e7e3da9f5a8b9ad394ab5a29f67a1d9b6ca1b8449862c69a5022e5d671e6989d33c182e0a6bbbe4a9da491dbd93ca3c01490c8f74a780479c7c031fb473670cacde779713dcd8cbdad802b8d418e007335919837becf46a3b1d0e02120af9d926bed2b28ed8a2b8307b3da2a171b3ee1bc1e6196773b570407df6b43b51b52c43f834ee0854577cd3a57f8fc23b02a3845cc1f0f42410f363d862e436bf06dbc5f94eddd3b83cdf47cf0acbd7750dff5cba86ea6f1f46a5013e0dc76715d7230e44a038a527cb9033f3eeaeac661264dc6a384788a7cd8aed59589bca6205fe1bd683fa392e7a3c6cc364bba36ad75ee9babf90f7b94071953df95effc0b1c3f542913ed1eb68e15534f9ceb7777c946edf55f129df128c3f767d8d60c4aa0c5e61d00f8e495e78334e2a9feddd9302e9880cb6174d201c89a1d6bc6e83a80cbf80ab3959dcc6cdd12e3d2f6f14d226e6948954f05544941d16ed1d498532722fa39bb985c3224915dd42d70be61217fdcb4aa023251af38b5576ff9eb865a471f2cb2dbc674e401d18014e6119464768778ddcd00907f20279bdecda3880fbbb4d00bb6c5aa3e06113a2f12fcc298f34ccb6bc2c2887b0b064f3bc2e2b507d31e022e65800dd7d30f25266914646bfc07c1eafbbf1e1163c439774b47e8e844799bc8fd06db050f97f5c74ca833e81bcdcf9d864be5746f965ef41838a3535666df867ef79e07068dc7ef809fb0e08e1629bab3215fe36d0f0e0f8c6bb319f93a0f408ff4abbd88c21afaec2e7720674eaceb27efb9144f619bad6f033cbefcebfbe66cabe8286f2ff97b91f4aeef5cbd99a9b862cb904dc085d96238caaad259280ff35caa211e00324f51ff03b6a1cd159cd501faef780ef7f25a98cdcd05ef67596d58d4aea1f9f3e95aae44fd4d4ea679c5e393d4670fb35bf12d036ea731bdfad297303239251a91f9a900e06987eb8e9f5bb1fb847f5ae47e6724ddeb5a3ac01b706a02e494c5547ce338302b4906cf2c91d59a87324322763a12e13a512ace3afb897510ad9ec95aa14ca568a9962da64e5bc7fd15b3e103ab461ee7db3fc9da0a523fc403c11254cd567ca48c8dac5e5b54953e5c754e31def90fff6c56d589a5c4b9a710ccb43cd24988b2fb9336b5508aa553cfdbd1f32dfb4ff16eae066b5fb244bc9058a91898c4ae893eaf0006dae1185c7f553e6e09d12a0a2a9c181c5e4d87c8895b74b0e23a8dc87faf5d6acd5e98cb1df5585f026ae94b77db0e95c5fe22692bd2e70e8e87d07d92b98cdfcc5367e52014163a6e4511d482816259215ee7df246e493523ee51617c318e1a9825f82e73e640fbc2d25c12ce5a07875d489db6a111afdc87061047077030d32de45cd4e575c02a60c4048560bd02cf9203426f589f429b413390ace832b3ddd3dd371750d94f9c34f60a0f1b621b445525d2190a185feaab9e56a079c46236161559713d585a07e94f2316a92fffa7838f1aea39d7846638d16f9b4d1a7dc053e0ddc6620f30e3e798eba900fd25c10c5d6672c9ed7d4d2fa80c0f0137ff24933c37fcd91b19bc7cdd828f7f3f1df0e45cafca795d847e83bca8baa321006581b024306e24c4c2294c0f41b932c1e9f7602f377e8484c7eeb184fab1f747b1dff5b6e2e89f1e5c4232b5a0a41ed6a3775f8942217078b7e035747891cabd2099bfcbf6a8d4680f51265d9e7d05794514f02470e0eb003ad1222cd4fe8bcd077310c5aff274b19608c31f77453d01c9aa9c21a8d9b71de44386aee2145648f7ead471cabed297b8610bba370baa42603f21f5f4640e5bc1a0402d40394e176a0db8cedb33a9d84c48b58d3851617046511946a3700aabe8f69cdb0469ee67776480be090cad2c7adc0bf59551ef6f1ac3119e5c29ab3b82dd945dab00dc4a91d3826c4e488047a4f3ab2d57c0abe1ee7aba304784e7ad211c32c4058fca7b1db2e282132e5ccafe79fc51ab37334f03715f4ad8735b6e03f01";

		// deserialize && check tx
		let t: Transaction = hex.into();
		assert_eq!(t.overwintered, false);
		assert_eq!(t.version, 2);
		assert_eq!(t.version_group_id, 0);
		assert_eq!(t.lock_time, 0);
		assert_eq!(t.expiry_height, 0);
		assert_eq!(t.inputs.len(), 1);
		assert_eq!(t.outputs.len(), 0);
		assert!(t.join_split.is_some());
		assert!(t.sapling.is_none());

		// serialize && check tx
		let t: String = serialize(&t).to_hex();
		assert_eq!(t, hex);
	}

	// Test vector 1 from:
	// https://github.com/zcash/zips/blob/9515d73aac0aea3494f77bcd634e1e4fbd744b97/zip-0243.rst
	#[test]
	fn test_sapling_transaction_1() {
		let hex = "0400008085202f890002e7719811893e0000095200ac6551ac636565b2835a0805750200025151481cdd86b3cc4318442117623ceb0500031b3d1a027c2c40590958b7eb13d742a997738c46a458965baf276ba92f272c721fe01f7e9c8e36d6a5e29d4e30a73594bf5098421c69378af1e40f64e125946f62c2fa7b2fecbcb64b6968912a6381ce3dc166d56a1d62f5a8d7551db5fd9313e8c7203d996af7d477083756d59af80d06a745f44ab023752cb5b406ed8985e18130ab33362697b0e4e4c763ccb8f676495c222f7fba1e31defa3d5a57efc2e1e9b01a035587d5fb1a38e01d94903d3c3e0ad3360c1d3710acd20b183e31d49f25c9a138f49b1a537edcf04be34a9851a7af9db6990ed83dd64af3597c04323ea51b0052ad8084a8b9da948d320dadd64f5431e61ddf658d24ae67c22c8d1309131fc00fe7f235734276d38d47f1e191e00c7a1d48af046827591e9733a97fa6b679f3dc601d008285edcbdae69ce8fc1be4aac00ff2711ebd931de518856878f73476f21a482ec9378365c8f7393c94e2885315eb4671098b79535e790fe53e29fef2b3766697ac32b4f473f468a008e72389fc03880d780cb07fcfaabe3f1a15825b7acb4d6b57a61bc68f242b52e4fbf85cf1a09cc45b6d6bb3a391578f499486a7afd04a0d9c74c2995d96b4de37b36046a1ef6d190b916b1111c92887311a20da8aba18d1dbebbc862ded42435e92476930d069896cff30eb414f727b89e001afa2fb8dc3436d75a4a6f26572504b192232ecb9f0c02411e52596bc5e90457e745939ffedbd12863ce71a02af117d417adb3d15cc54dcb1fce467500c6b8fb86b12b56da9c382857deecc40a98d5f2935395ee4762dd21afdbb5d47fa9a6dd984d567db2857b927b7fae2db587105415d4642789d38f50b8dbcc129cab3d17d19f3355bcf73cecb8cb8a5da01307152f13936a270572670dc82d39026c6cb4cd4b0f7f5aa2a4f5a5341ec5dd715406f2fdd2afa733f5f641c8c21862a1bafce2609d9eecfa158cfb5cd79f88008e315dc7d8388e76c1782fd2795d18a763624c25fa959cc97489ce75745824b77868c53239cfbdf73caec65604037314faaceb56218c6bd30f8374ac13386793f21a9fb80ad03bc0cda4a44946c00e1b102c78f11876b7065212183199fb5979ca77d2c24c738fe5145f02602053bb4c2f6556df6ed4b4ddd3d9a69f53357d7767f4f5ccbdbc596631277f8fecd08cb056b95e3025b9792fff7f244fc716269b926d62e9596fa825c6bf21aff9e68625a192440ea06828123d97884806f15fa08da52754a1095e3ff1abd5ce4fddfccfc3a6128aef784a64610a89d1a7099216d0814d3a2d452431c32d411ac1cce82ad0229407bbc48985675e3f874a4533f1d63a84dfa3e0f460fe2f57e34fbc75423c3737f5b2a0615f5722db041a3ef66fa483afd3c2e19e59444a64add6df1d963f5dd5b5010d3d025f0287c4cf19c75f33d51ddddba5d657b43ee8da645443814cc7329f3e9b4e54c236c29af3923101756d9fa4bd0f7d2ddaacb6b0f86a2658e0a07a05ac5b950051cd24c47a88d13d659ba2a46ca1830816d09cd7646f76f716abec5de07fe9b523410806ea6f288f8736c23357c85f45791e1708029d9824d90704607f387a03e49bf9836574431345a7877efaa8a08e73081ef8d62cb780a010fa3207ee2f0408097d563da1b2146819edf88d33e7753664fb71d122a6e36998fbd467f75b780149ae8808f4e68f50c0536acddf6f1aeab016b6bc1ec144b4e59aeb77eef49d00e5fbb67101cdd41e6bc9cf641a52fca98be915f8440a410d74cb30e15914f01bc6bc2307b488d2556d7b7380ea4ffd712f6b02fe806b94569cd4059f396bf29b99d0a40e5e1711ca944f72d436a102fca4b97693da0b086fe9d2e7162470d02e0f05d4bec9512bfb3f38327296efaa74328b118c27402c70c3a90b49ad4bbc68e37c0aa7d9b3fe17799d73b841e751713a02943905aae0803fd69442eb7681ec2a05600054e92eed555028f21b6a155268a2dd6640a69301a52a38d4d9f9f957ae35af7167118141ce4c9be0a6a492fe79f1581a155fa3a2b9dafd82e650b386ad3a08cb6b83131ac300b0846354a7eef9c410e4b62c47c5426907dfc6685c5c99b7141ac626ab4761fd3f41e728e1a28f89db89ffdeca364dd2f0f0739f0534556483199c71f189341ac9b78a269164206a0ea1ce73bfb2a942e7370b247c046f8e75ef8e3f8bd821cf577491864e20e6d08fd2e32b555c92c661f19588b72a89599710a88061253ca285b6304b37da2b5294f5cb354a894322848ccbdc7c2545b7da568afac87ffa005c312241c2d57f4b45d6419f0d2e2c5af33ae243785b325cdab95404fc7aed70525cddb41872cfcc214b13232edc78609753dbff930eb0dc156612b9cb434bc4b693392deb87c530435312edcedc6a961133338d786c4a3e103f60110a16b1337129704bf4754ff6ba9fbe65951e610620f71cda8fc877625f2c5bb04cbe1228b1e886f4050afd8fe94e97d2e9e85c6bb748c0042d3249abb1342bb0eebf62058bf3de080d94611a3750915b5dc6c0b3899d41222bace760ee9c8818ded599e34c56d7372af1eb86852f2a732104bdb750739de6c2c6e0f9eb7cb17f1942bfc9f4fd6ebb6b4cdd4da2bca26fac4578e9f543405acc7d86ff59158bd0cba3aef6f4a8472d144d99f8b8d1dedaa9077d4f01d4bb27bbe31d88fbefac3dcd4797563a26b1d61fcd9a464ab21ed550fe6fa09695ba0b2f10eea6468cc6e20a66f826e3d14c5006f0563887f5e1289be1b2004caca8d3f34d6e84bf59c1e04619a7c23a996941d889e4622a9b9b1d59d5e319094318cd405ba27b7e2c084762d31453ec4549a4d97729d033460fcf89d6494f2ffd789e98082ea5ce9534b3acd60fe49e37e4f666931677319ed89f85588741b3128901a93bd78e4be0225a9e2692c77c969ed0176bdf9555948cbd5a332d045de6ba6bf4490adfe7444cd467a09075417fc0200000000000000000000000000000000062e49f008c51ad4227439c1b4476ccd8e97862dab7be1e8d399c05ef27c6e22ee273e15786e394c8f1be31682a30147963ac8da8d41d804258426a3f70289b8ad19d8de13be4eebe3bd4c8a6f55d6e0c373d456851879f5fbc282db9e134806bff71e11bc33ab75dd6ca067fb73a043b646a7cf39cab4928386786d2f24141ee120fdc34d6764eafc66880ee0204f53cc1167ed20b43a52dea3ca7cff8ef35cd8e6d7c111a68ef44bcd0c1513ad47ca61c659cc5d325b440f6b9f59aff66879bb6688fd2859362b182f207b3175961f6411a493bffd048e7d0d87d82fe6f990a2b0a25f5aa0111a6e68f37bf6f3ac2d26b84686e569d58d99c1383597fad81193c4c1b16e6a90e2d507cdfe6fbdaa86163e9cf5de3100fbca7e8da047b090db9f37952fbfee76af61668190bd52ed490e677b515d014384af07219c7c0ee7fc7bfc79f325644e4df4c0d7db08e9f0bd024943c705abff8994bfa605cfbc7ed746a7d3f7c37d9e8bdc433b7d79e08a12f738a8f0dbddfef2f2657ef3e47d1b0fd11e6a13311fb799c79c641d9da43b33e7ad012e28255398789262275f1175be8462c01491c4d842406d0ec4282c9526174a09878fe8fdde33a29604e5e5e7b2a025d6650b97dbb52befb59b1d30a57433b0a351474444099daa371046613260cf3354cfcdada663ece824ffd7e44393886a86165ddddf2b4c41773554c86995269408b11e6737a4c447586f69173446d8e48bf84cbc000a807899973eb93c5e819aad669413f8387933ad1584aa35e43f4ecd1e2d0407c0b1b89920ffdfdb9bea51ac95b557af71b89f903f5d9848f14fcbeb1837570f544d6359eb23faf38a0822da36ce426c4a2fbeffeb0a8a2e297a9d19ba15024590e3329d9fa9261f9938a4032dd34606c9cf9f3dd33e576f05cd1dd6811c6298757d77d9e810abdb226afcaa4346a6560f8932b3181fd355d5d391976183f8d99388839632d6354f666d09d3e5629ea19737388613d38a34fd0f6e50ee5a0cc9677177f50028c141378187bd2819403fc534f80076e9380cb4964d3b6b45819d3b8e9caf54f051852d671bf8c1ffde2d1510756418cb4810936aa57e6965d6fb656a760b7f19adf96c173488552193b147ee58858033dac7cd0eb204c06490bbdedf5f7571acb2ebe76acef3f2a01ee987486dfe6c3f0a5e234c127258f97a28fb5d164a8176be946b8097d0e317287f33bf9c16f9a545409ce29b1f4273725fc0df02a04ebae178b3414fb0a82d50deb09fcf4e6ee9d180ff4f56ff3bc1d3601fc2dc90d814c3256f4967d3a8d64c83fea339c51f5a8e5801fbb97835581b602465dee04b5922c2761b54245bec0c9eef2db97d22b2b3556cc969fbb13d06509765a52b3fac54b93f421bf08e18d52ddd52cc1c8ca8adfaccab7e5cc2f4573fbbf8239bb0b8aedbf8dad16282da5c9125dba1c059d0df8abf621078f02d6c4bc86d40845ac1d59710c45f07d585eb48b32fc0167ba256e73ca3b9311c62d109497957d8dbe10aa3e866b40c0baa2bc492c19ad1e6372d9622bf163fbffeaeee796a3cd9b6fbbfa4d792f34d7fd6e763cd5859dd26833d21d9bc5452bd19515dff9f4995b35bc0c1f876e6ad11f2452dc9ae85aec01fc56f8cbfda75a7727b75ebbd6bbffb43b63a3b1b671e40feb0db002974a3c3b1a788567231bf6399ff89236981149d423802d2341a3bedb9ddcbac1fe7b6435e1479c72e7089d029e7fbbaf3cf37e9b9a6b776791e4c5e6fda57e8d5f14c8c35a2d270846b9dbe005cda16af4408f3ab06a916eeeb9c9594b70424a4c1d171295b6763b22f47f80b53ccbb904bd68fd65fbd3fbdea1035e98c21a7dbc91a9b5bc7690f05ec317c97f8764eb48e911d428ec8d861b708e8298acb62155145155ae95f0a1d1501034753146e22d05f586d7f6b4fe12dad9a17f5db70b1db96b8d9a83edadc966c8a5466b61fc998c31f1070d9a5c9a6d268d304fe6b8fd3b4010348611abdcbd49fe4f85b623c7828c71382e1034ea67bc8ae97404b0c50b2a04f559e49950afcb0ef462a2ae024b0f0224dfd73684b88c7fbe92d02b68f759c4752663cd7b97a14943649305521326bde085630864629291bae25ff8822a14c4b666a9259ad0dc42a8290ac7bc7f53a16f379f758e5de750f04fd7cad47701c8597f97888bea6fa0bf2999956fbfd0ee68ec36e4688809ae231eb8bc4369f5fe1573f57e099d9c09901bf39caac48dc11956a8ae905ead86954547c448ae43d315e669c4242da565938f417bf43ce7b2b30b1cd4018388e1a910f0fc41fb0877a5925e466819d375b0a912d4fe843b76ef6f223f0f7c894f38f7ab780dfd75f669c8c06cffa0000000000000000000000000000000043eb47565a50e3b1fa45ad61ce9a1c4727b7aaa53562f523e73952bbf33d8a4104078ade3eaaa49699a69fdf1c5ac7732146ee5e1d6b6ca9b9180f964cc9d0878ae1373524d7d510e58227df6de9d30d271867640177b0f1856e28d5c8afb095ef6184fed651589022eeaea4c0ce1fa6f085092b04979489172b3ef8194a798df5724d6b05f1ae000013a08d612bca8a8c31443c10346dbf61de8475c0bbec5104b47556af3d514458e2321d146071789d2335934a680614e83562f82dfd405b54a45eb32c165448d4d5d61ca2859585369f53f1a137e9e82b67b8fdaf01bda54a317311896ae10280a032440c420a421e944d1e952b70d5826cd3b08b7db9630fe4fd5f22125de840fcc40b98038af11d55be25432597b4b65b9ec1c7a8bbfd052cbf7e1c1785314934b262d5853754f1f17771cfb7503072655753fa3f54ecc587e9f83b581916092df26e63e18994cb0db91a0bbdc7b6119b32222adf5e61d8d8ae89dae4954b54813bb33f08d562ba513fee1b09c0fcd516055419474dd7fda038a89c84ea7b9468287f0eb0c10c4b132520194d3d8d5351fc10d09c15c8cc101aa1663bbf17b84111f38bb439f07353bdea3596d15e713e1e2e7d3f1c383135b47fa7f81f46df7a902a404699ec912f5656c35b85763e4de583aecaa1dfd5d2677d9c8ffee877f63f40a5ca0d67f6e554124739f805af876aeede53aa8b0f8e5604a73c30cbd09dad963d6f8a5dcc40def40797342113ba206fae8ebe4f3bc3caf69259e462eff9ba8b3f4bfaa1300c26925a8729cd32915bfc966086f0d5560bbe32a598c22adfb48cef72ba5d4287c0cefbacfd8ce195b4963c34a94bba7a175dae4bbe3ef4863d53708915090f47a068e227433f9e49d3aa09e356d8d66d0c0121e91a3c4aa3f27fa1b63396e2b41db908fdab8b18cc7304e94e970568f9421c0dbbbaf84598d972b0534f48a5e52670436aaa776ed2482ad703430201e53443c36dcfd34a0cb6637876105e79bf3bd58ec148cb64970e3223a91f71dfcfd5a04b667fbaf3d4b3b908b9828820dfecdd753750b5f9d2216e56c615272f854464c0ca4b1e85aedd038292c4e1a57744ebba010b9ebfbb011bd6f0b78805025d27f3c17746bae116c15d9f471f0f6288a150647b2afe9df7cccf01f5cde5f04680bbfed87f6cf429fb27ad6babe791766611cf5bc20e48bef119259b9b8a0e39c3df28cb9582ea338601cdc481b32fb82adeebb3dade25d1a3df20c37e712506b5d996c49a9f0f30ddcb91fe9004e1e83294a6c9203d94e8dc2cbb449de4155032604e47997016b304fd437d8235045e255a19b743a0a9f2e336b44cae307bb3987bd3e4e777fbb34c0ab8cc3d67466c0a88dd4ccad18a07a8d1068df5b629e5718d0f6df5c957cf71bb00a5178f175caca944e635c5159f738e2402a2d21aa081e10e456afb00b9f62416c8b9c0f7228f510729e0be3f305313d77f7379dc2af24869c6c74ee4471498861d192f0ff0f508285dab6b6a36ccf7d12256cc76b95503720ac672d08268d2cf7773b6ba2a5f664847bf707f2fc10c98f2f006ec22ccb5a8c8b7c40c7c2d49a6639b9f2ce33c25c04bc461e744dfa536b00d94baddf4f4d14044c695a33881477df124f0fcf206a9fb2e65e304cdbf0c4d2390170c130ab849c2f22b5cdd3921640c8cf1976ae1010b0dfd9cb2543e45f99749cc4d61f2e8aabfe98bd905fa39951b33ea769c45ab9531c57209862ad12fd76ba4807e65417b6cd12fa8ec916f013ebb8706a96effeda06c4be24b04846392e9d1e6930eae01fa21fbd700583fb598b92c8f4eb8a61aa6235db60f2841cf3a1c6ab54c67066844711d091eb931a1bd6281aedf2a0e8fab18817202a9be06402ed9cc720c16bfe881e4df4255e87afb7fc62f38116bbe03cd8a3cb11a27d568414782f47b1a44c97c680467694bc9709d32916c97e8006cbb07ba0e4180a3738038c374c4cce8f32959afb25f303f5815c4533124acf9d18940e77522ac5dc4b9570aae8f47b7f57fd8767bea1a24ae7bed65b4afdc8f1278c30e2db98fd172730ac6bbed4f1127cd32b04a95b205526cfcb4c4e1cc955175b3e8de1f5d81b18669692350aaa1a1d797617582e54d7a5b57a683b32fb1098062dad7b0c2eb518f6862e83db25e3dbaf7aed504de932acb99d735992ce62bae9ef893ff6acc0ffcf8e3483e146b9d49dd8c7835f43a37dca0787e3ec9f6605223d5ba7ae0ab9025b73bc03f7fac36c009a56d4d95d1e81d3b3ebca7e54cc1a12d127b57c8138976e791013b015f06a624f521b6ee04ec980893c7e5e01a336203594094f82833d7445fe2d09130f63511da54832de9136b39f4599f5aa5dfbb45da60cdceab7eefde89be63f3f7c0d2324847cce1405def7c469b0e272494e5df54f568656cb9c8818d92b72b8bc34db7bb3112487e746eefe4e808bbb287d99bf07d00dabededc5e5f074ffeae0cba7da3a516c173be1c513323e119f635e8209a074b216b7023fadc2d25949c90037e71e3e550726d210a2c688342e52440635e9cc14afe10102621a9c9accb782e9e4a5fa87f0a956f5b";

		// deserialize && check tx
		let t: Transaction = hex.into();
		assert_eq!(t.overwintered, true);
		assert_eq!(t.version, 4);
		assert_eq!(t.version_group_id, 0x892F2085);
		assert_eq!(t.lock_time, 0x86dd1c48);
		assert_eq!(t.expiry_height, 0x1843ccb3);
		assert_eq!(t.inputs.len(), 0);
		assert_eq!(t.outputs.len(), 2);
		assert!(t.join_split.is_some());
		assert!(t.sapling.is_some());

		// serialize && check tx
		let t: String = serialize(&t).to_hex();
		assert_eq!(t, hex);
	}

	// tx: https://zcash.blockexplorer.com/tx/bd4fe81c15cfbd125f5ca6fe51fb5ac4ef340e64a36f576a6a09f7528eb2e176
	// rawtx is broken for this tx => parsed from rawblock
	// https://zcash.blockexplorer.com/api/rawblock/00000000007ef95f986ed8309d0ed6a1b6174c90b9c7f4d0dfc40f7147315e79
	#[test]
	fn test_sapling_transaction_2() {
		let hex = "0400008085202f8900000000000072da060010270000000000000148b1c0668fce604361fbb1b89bbd76f8fee09b51a9dc0fdfcf6c6720cd596083d970234fcc0e9a70fdfed82d32fbb9ca92c9c5c3bad5daad9ac62b5bf4255817ee5bc95a9af453bb9cc7e2c544aa29efa20011a65b624998369c849aa8f0bc83d60e7902a3cfe6eeaeb8d583a491de5982c5ded29e64cd8f8fac594a5bb4f2838e6c30876e36a18d8d935238815c8d9205a4f1f523ff76b51f614bff1064d1c5fa0a27ec0c43c8a6c2714e7234d32e9a8934a3e9c0f74f1fdac2ddf6be3b13bc933b0478cae556a2d387cc23b05e8b0bd53d9e838ad2d2cb31daccefe256087511b044dfae665f0af0fa968edeea4cbb437a8099724159471adf7946eec434cccc1129f4d1e31d7f3f8be524226c65f28897d3604c14efb64bea6a889b2705617432927229dfa382e78c0ace31cc158fbf3ec1597242955e45af1ee5cfaffd789cc80dc53d6b18d42033ec2c327170e2811fe8ec00feadeb1033eb48ab24a6dce2480ad428be57c4619466fc3181ece69b914fed30566ff853250ef19ef7370601f4c24b0125e4059eec61f63ccbe277363172f2bdee384412ea073c5aca06b94e402ba3a43e15bd9c65bbfb194c561c24a031dec43be95c59eb6b568c176b1038d5b7b057dc032488335284adebfb6607e6a995b7fa418f13c8a61b343e5df44faa1050d9d76550748d9efebe01da97ade5937afd5f007ed26e0af03f283611655e91bc6a4857f66a57a1584ff687c4baf725f4a1b32fae53a3e6e8b98bca319bb1badb704c9c1a04f401f33d813d605eef6943c2c52dbc85ab7081d1f8f69d3202aae281bf42336a949a12a7dbbd22abdd6e92996282ebd69033c22cb0539d97f83636d6a8232209a7411e8b03bef180d83e608563ea2d0becff56dc996c2049df054961bfb21b7cbef5049a7dacc18f2c977aa1b2d48291abc19c3c8ea25d2e61901048354b17ce952f6f2248cf3a0eb54c19b507b41d7281c3d227e2b142ff695d8b925a4bb942ed9492a73a17468a8332a367fd16295420bdca6c04d380271f40440709998fce3a3af3e1e505f5402e5dd464dd179cb0eede3d494a95b84d2fb2eb5abb425cf2c712af999c65259c4782a5ec97388324c67738908a5ba43b6db62a10f50cddf9b5039123437c74165921ac8cf4f13292a216baef9d00bd544106b52755986c98a462ade1149f69367e926d88eb92798c0e56cd19a1bcf264fd93293033b758da65c7901eb5b4a17ee265a3312dbc477868da0057e1b3cbf47726dead6ecfcc8e1044c6f311ff0fc83192dc2f75a89626ba33364dac747b63ff3c8337e00332c8783ba9c8dc13cdf0750d7adc3926fbe1279017d50adba35c38c5b810f73abe5d759cd7fb650f6b0a1f78dc1f62fd017090ff4de4cf54c883752ddda68083d4617ed2c38bab8da313965dd3f7b755aec23a2d9e2965d08d2134827a72ffb3bd65b1fd5410da105bfba7a74ddff0928a654aca1ee211ac9dce8019ddcbb52263ce44b2544a314355c1e8c8543f3ed3e883e7a7a8f9e3c7c11f41ab9069854fb21e9b3660a860df19d289d54b29d82522b32d187cde6261eb0a429c3994dff6f37b9ab9102281223e3cd584790a909e05ba0ea1a2d9aef8e571986e98e09312dccaf8e739d718a1edd217dc4c8a5c8a650015405b592a7c674a451d7d1686c7ea6d93e74a8fe4ade12b679ac780457f08a79bfbf96dcf7eefe9a39b99f1ae39d2c5f86aadf156b7d5ce4b2733f307cfe1e1ff6de0ff2006d9cba535b0c40dfb7a98399cdff8e681fc38c7b9aa94ee5eb89432e28d94ee27f238776ba964a87caf58eddbb64771e64de094305a8eb848d2d9ad6373903687d22170f48f1ae8d714514034ee2733857af4747312bb006e6ce3918ede8c730bacc7821b81c1b93bb50b219e79e8e0d74531ed18c1145632d9847d38783b49141ac5353aaa7d125fb2934e681467e16b28090978e74e0b";

		// deserialize && check tx
		let t: Transaction = hex.into();
		assert!(t.sapling.is_some());
		assert_eq!(t.sapling.as_ref().unwrap().spends.len(), 1);
		assert_eq!(t.sapling.as_ref().unwrap().outputs.len(), 1);
	}

	#[test]
	fn test_transaction_hash() {
		let t: Transaction = "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000".into();
		let hash = H256::from_reversed_str("5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2");
		assert_eq!(t.hash(), hash);
	}

	#[test]
	fn test_transaction_serialized_len() {
		let raw_tx: &'static str = "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000";
		let tx: Transaction = raw_tx.into();
		assert_eq!(tx.serialized_size(), raw_tx.len() / 2);
	}
}
