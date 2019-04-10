use hash::H256;
use crypto::{sha256_compress, pedersen_hash};

lazy_static! {
	static ref SPROUT_EMPTY_ROOTS: Vec<H256> = [
		H256::from("0000000000000000000000000000000000000000000000000000000000000000"),
		H256::from("da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8"),
		H256::from("dc766fab492ccf3d1e49d4f374b5235fa56506aac2224d39f943fcd49202974c"),
		H256::from("3f0a406181105968fdaee30679e3273c66b72bf9a7f5debbf3b5a0a26e359f92"),
		H256::from("26b0052694fc42fdff93e6fb5a71d38c3dd7dc5b6ad710eb048c660233137fab"),
		H256::from("0109ecc0722659ff83450b8f7b8846e67b2859f33c30d9b7acd5bf39cae54e31"),
		H256::from("3f909b8ce3d7ffd8a5b30908f605a03b0db85169558ddc1da7bbbcc9b09fd325"),
		H256::from("40460fa6bc692a06f47521a6725a547c028a6a240d8409f165e63cb54da2d23f"),
		H256::from("8c085674249b43da1b9a31a0e820e81e75f342807b03b6b9e64983217bc2b38e"),
		H256::from("a083450c1ba2a3a7be76fad9d13bc37be4bf83bd3e59fc375a36ba62dc620298"),
		H256::from("1ddddabc2caa2de9eff9e18c8c5a39406d7936e889bc16cfabb144f5c0022682"),
		H256::from("c22d8f0b5e4056e5f318ba22091cc07db5694fbeb5e87ef0d7e2c57ca352359e"),
		H256::from("89a434ae1febd7687eceea21d07f20a2512449d08ce2eee55871cdb9d46c1233"),
		H256::from("7333dbffbd11f09247a2b33a013ec4c4342029d851e22ba485d4461851370c15"),
		H256::from("5dad844ab9466b70f745137195ca221b48f346abd145fb5efc23a8b4ba508022"),
		H256::from("507e0dae81cbfbe457fd370ef1ca4201c2b6401083ddab440e4a038dc1e358c4"),
		H256::from("bdcdb3293188c9807d808267018684cfece07ac35a42c00f2c79b4003825305d"),
		H256::from("bab5800972a16c2c22530c66066d0a5867e987bed21a6d5a450b683cf1cfd709"),
		H256::from("11aa0b4ad29b13b057a31619d6500d636cd735cdd07d811ea265ec4bcbbbd058"),
		H256::from("5145b1b055c2df02b95675e3797b91de1b846d25003c0a803d08900728f2cd6a"),
		H256::from("0323f2850bf3444f4b4c5c09a6057ec7169190f45acb9e46984ab3dfcec4f06a"),
		H256::from("671546e26b1da1af754531e26d8a6a51073a57ddd72dc472efb43fcb257cffff"),
		H256::from("bb23a9bba56de57cb284b0d2b01c642cf79c9a5563f0067a21292412145bd78a"),
		H256::from("f30cc836b9f71b4e7ee3c72b1fd253268af9a27e9d7291a23d02821b21ddfd16"),
		H256::from("58a2753dade103cecbcda50b5ebfce31e12d41d5841dcc95620f7b3d50a1b9a1"),
		H256::from("925e6d474a5d8d3004f29da0dd78d30ae3824ce79dfe4934bb29ec3afaf3d521"),
		H256::from("08f279618616bcdd4eadc9c7a9062691a59b43b07e2c1e237f17bd189cd6a8fe"),
		H256::from("c92b32db42f42e2bf0a59df9055be5c669d3242df45357659b75ae2c27a76f50"),
		H256::from("c0db2a74998c50eb7ba6534f6d410efc27c4bb88acb0222c7906ea28a327b511"),
		H256::from("d7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd259"),
		H256::from("b22370106c67a17209f6130bc09f735d83aa2c04fc4fe72ea5d80b216723e7ce"),
		H256::from("9f67d5f664664c901940eee3d02dd5b3e4b92e7b42820c42fc5159e91b41172a"),
		H256::from("ac58cd1388fec290d398f1944b564449a63c815880566bd1d189f7839e3b0c8c"),
		H256::from("5698eae7c8515ed05a70339bdf7c1028e7acca13a4fa97d9538f01ac8d889ae3"),
		H256::from("2d4995770a76fb93314ca74b3524ea1db5688ad0a76183ea17204a8f024a9f3b"),
		H256::from("5e8992c1b072c16e9e28a85358fb5fb6901a81587766dadb7aa0b973ded2f264"),
		H256::from("e95db71e1f7291ba5499461bc715203e29b84bfa4283e3bb7f470a15d0e1584e"),
		H256::from("41f078bd1824c8a4b71964f394aa595084d8eb17b97a3630433af70d10e0eff6"),
		H256::from("a1913fe6b20132312f8c1f00ddd63cec7a03f5f1d7d83492fa284c0b5d6320b0"),
		H256::from("ba9440c4dbfcf55ceb605a5b8990fc11f8ef22870d8d12e130f986491eae84b3"),
		H256::from("49db2d5e22b8015cae4810d75e54014c5469862738e161ec96ec20218718828a"),
		H256::from("d4851fb8431edfbb8b1e85ada6895967c2dac87df344992a05faf1ecf836eec9"),
		H256::from("e4ab9f4470f00cd196d47c75c82e7adaf06fe17e042e3953d93bb5d56d8cd8fb"),
		H256::from("7e4320434849ecb357f1afaaba21a54400ef2d11cff83b937d87fdafa49f8199"),
		H256::from("020adc98d96cfbbcca15fc3aa03760ed286686c35b5d92c7cb64a999b394a854"),
		H256::from("3a26b29fe1acfdd6c6a151bcc3dbcb95a10ebe2f0553f80779569b67b7244e77"),
		H256::from("ec2d0986e6a0ddf43897b2d4f23bb034f538ffe00827f310dc4963f3267f0bfb"),
		H256::from("d48073f8819f81f0358e3fc35a047cc74082ae1cb7ee22fb609c01649342d0e6"),
		H256::from("ad8037601793f172441ecb00dc138d9fc5957125ecc382ec65e36f817dc799fb"),
		H256::from("ca500a5441f36f4df673d6b8ed075d36dae2c7e6481428c70a5a76b7a9bebce8"),
		H256::from("422b6ddd473231dc4d56fe913444ccd56f7c61f747ba57ca946d5fef72d840a0"),
		H256::from("ab41f4ecb7d7089615800e19fcc53b8379ed05ee35c82567095583fd90ff3035"),
		H256::from("bbf7618248354ceb1bc1fc9dbc42c426a4e2c1e0d443c5683a9256c62ecdc26f"),
		H256::from("e50ae71479fc8ec569192a13072e011afc249f471af09500ea39f75d0af856bf"),
		H256::from("e74c0b9220147db2d50a3b58d413775d16c984690be7d90f0bc43d99dba1b689"),
		H256::from("29324a0a48d11657a51ba08b004879bfcfc66a1acb7ce36dfe478d2655484b48"),
		H256::from("88952e3d0ac06cb16b665201122249659a22325e01c870f49e29da6b1757e082"),
		H256::from("cdf879f2435b95af042a3bf7b850f7819246c805285803d67ffbf4f295bed004"),
		H256::from("e005e324200b4f428c62bc3331e695c373607cd0faa9790341fa3ba1ed228bc5"),
		H256::from("354447727aa9a53dd8345b6b6c693443e56ef4aeba13c410179fc8589e7733d5"),
		H256::from("da52dda91f2829c15c0e58d29a95360b86ab30cf0cac8101832a29f38c3185f1"),
		H256::from("c7da7814e228e1144411d78b536092fe920bcdfcc36cf19d1259047b267d58b5"),
		H256::from("aba1f68b6c2b4db6cc06a7340e12313c4b4a4ea6deb17deb3e1e66cd8eacf32b"),
		H256::from("c160ae4f64ab764d864a52ad5e33126c4b5ce105a47deedd75bc70199a5247ef"),
		H256::from("eadf23fc99d514dd8ea204d223e98da988831f9b5d1940274ca520b7fb173d8a"),
		H256::from("5b8e14facac8a7c7a3bfee8bae71f2f7793d3ad5fe3383f93ab6061f2a11bb02")
	].to_vec();

	static ref SAPLING_EMPTY_ROOTS: Vec<H256> = [
		H256::from("0100000000000000000000000000000000000000000000000000000000000000"),
		H256::from("817de36ab2d57feb077634bca77819c8e0bd298c04f6fed0e6a83cc1356ca155"),
		H256::from("ffe9fc03f18b176c998806439ff0bb8ad193afdb27b2ccbc88856916dd804e34"),
		H256::from("d8283386ef2ef07ebdbb4383c12a739a953a4d6e0d6fb1139a4036d693bfbb6c"),
		H256::from("e110de65c907b9dea4ae0bd83a4b0a51bea175646a64c12b4c9f931b2cb31b49"),
		H256::from("912d82b2c2bca231f71efcf61737fbf0a08befa0416215aeef53e8bb6d23390a"),
		H256::from("8ac9cf9c391e3fd42891d27238a81a8a5c1d3a72b1bcbea8cf44a58ce7389613"),
		H256::from("d6c639ac24b46bd19341c91b13fdcab31581ddaf7f1411336a271f3d0aa52813"),
		H256::from("7b99abdc3730991cc9274727d7d82d28cb794edbc7034b4f0053ff7c4b680444"),
		H256::from("43ff5457f13b926b61df552d4e402ee6dc1463f99a535f9a713439264d5b616b"),
		H256::from("ba49b659fbd0b7334211ea6a9d9df185c757e70aa81da562fb912b84f49bce72"),
		H256::from("4777c8776a3b1e69b73a62fa701fa4f7a6282d9aee2c7a6b82e7937d7081c23c"),
		H256::from("ec677114c27206f5debc1c1ed66f95e2b1885da5b7be3d736b1de98579473048"),
		H256::from("1b77dac4d24fb7258c3c528704c59430b630718bec486421837021cf75dab651"),
		H256::from("bd74b25aacb92378a871bf27d225cfc26baca344a1ea35fdd94510f3d157082c"),
		H256::from("d6acdedf95f608e09fa53fb43dcd0990475726c5131210c9e5caeab97f0e642f"),
		H256::from("1ea6675f9551eeb9dfaaa9247bc9858270d3d3a4c5afa7177a984d5ed1be2451"),
		H256::from("6edb16d01907b759977d7650dad7e3ec049af1a3d875380b697c862c9ec5d51c"),
		H256::from("cd1c8dbf6e3acc7a80439bc4962cf25b9dce7c896f3a5bd70803fc5a0e33cf00"),
		H256::from("6aca8448d8263e547d5ff2950e2ed3839e998d31cbc6ac9fd57bc6002b159216"),
		H256::from("8d5fa43e5a10d11605ac7430ba1f5d81fb1b68d29a640405767749e841527673"),
		H256::from("08eeab0c13abd6069e6310197bf80f9c1ea6de78fd19cbae24d4a520e6cf3023"),
		H256::from("0769557bc682b1bf308646fd0b22e648e8b9e98f57e29f5af40f6edb833e2c49"),
		H256::from("4c6937d78f42685f84b43ad3b7b00f81285662f85c6a68ef11d62ad1a3ee0850"),
		H256::from("fee0e52802cb0c46b1eb4d376c62697f4759f6c8917fa352571202fd778fd712"),
		H256::from("16d6252968971a83da8521d65382e61f0176646d771c91528e3276ee45383e4a"),
		H256::from("d2e1642c9a462229289e5b0e3b7f9008e0301cbb93385ee0e21da2545073cb58"),
		H256::from("a5122c08ff9c161d9ca6fc462073396c7d7d38e8ee48cdb3bea7e2230134ed6a"),
		H256::from("28e7b841dcbc47cceb69d7cb8d94245fb7cb2ba3a7a6bc18f13f945f7dbd6e2a"),
		H256::from("e1f34b034d4a3cd28557e2907ebf990c918f64ecb50a94f01d6fda5ca5c7ef72"),
		H256::from("12935f14b676509b81eb49ef25f39269ed72309238b4c145803544b646dca62d"),
		H256::from("b2eed031d4d6a4f02a097f80b54cc1541d4163c6b6f5971f88b6e41d35c53814"),
		H256::from("fbc2f4300c01f0b7820d00e3347c8da4ee614674376cbc45359daa54f9b5493e"),
		H256::from("252e6798645f5bf114e4b4e90e96182861489840d9b4ccc4c1fb5a46997cee14"),
		H256::from("98b19042f1f7c7dd11ec25ea66b6ff74e08ce11d447ed6f1bfe87e110e331e11"),
		H256::from("d451304799572ba9f42c4dab6b07c703bd2c123ab9d60f2a60f9955854910b6a"),
		H256::from("3ecd5f27acf01bd37a33e4517867ef76474cd83fb31c9208dcef2eedcef36c72"),
		H256::from("26c37da67894a13df8aa4878d2514a4212573b73eccaab16fe4fa660e8fe2707"),
		H256::from("b545ef34485eed30d42b2c295a4a5b680de8a9d5e38345782462c04f09dc6851"),
		H256::from("77fd20b300946765a87f24bd045073729cbd7b66eb8fa140b583faa9d1425801"),
		H256::from("cbaa576b1799b58ff3a6decbba919b0b68d7c893e46fde998768e87e350a0725"),
		H256::from("45fe81b18ca30074d0120d2b1a0d10b3a050933512db8ee34e52473d4f08a267"),
		H256::from("0e60a1f0121f591e551d3ed1865b50a75d7ccff1289df7c44dd465a54317f56a"),
		H256::from("cedfb184dd92a0cbfc11e8be697b476988ed5f39369abdd90c61544988601c0d"),
		H256::from("f362686612649a313ba464437a0cad0e7e3d7e1b4b3743f90e05a2100a495f42"),
		H256::from("7deae5f3bbdeffd3f85271a08b5ec31f16f937964ae708fdff7c13e5a4f3df6b"),
		H256::from("40ccf0fc1eab6d8502bd93dc31342dfd57df5bbb5d70a1bf6b92efc61ec9a258"),
		H256::from("d78025491f1bca8507f64f25872dd02388479a1a225126e40d2fe418b98e0e2c"),
		H256::from("0db7294685c8a0725f15846ea5899ea0e986c2707bd7b412954412f26abf550a"),
		H256::from("b7e290be9555cf75548650da6d47c893aef7f8c6dd2735499495f636590dae0a"),
		H256::from("2dd2532a858c300145a65e351f91be6afeab597c41ef073f50b622d586ff5927"),
		H256::from("972f0c5c6f9aeb0e38bf8319f3a5fcdc8fd8782e4188730cd082d9babc589851"),
		H256::from("001e577b0f4390182b4ae43d329b3aa8835dae1bb79e604b7d2da0e90d060929"),
		H256::from("aa6e70a91ebc54eefce5ffd5b675daf3f1d940a8451fcb01081fa9d4f262436f"),
		H256::from("d77038bf67e631752940231251d7fe85af52dbdd6aab37c7a5ec32b65fe6de03"),
		H256::from("d227a17a7e0cf96dcedd9fc7bce43c6c1d66badd7543a887c8656c547ecfb24f"),
		H256::from("70e8a521951583e53fc0585c707eceda89b7a7d1af41d1a015d797fa76c0f569"),
		H256::from("e485a96855e872fc5090150e2cd24e10591d35166eb0eb30fcdfac93b01d281c"),
		H256::from("e4a19febdf2a86896e41f2cedcf2ae584671802e6a467e8439cab5d61843416b"),
		H256::from("e927838847806a43bd6c6088e39f65b8b3e58b2db5f7ad5643d91e0659a28a2a"),
		H256::from("0bd3a818e83f9cd2ff4f62011a510176ac32f5448e6e154515043c5926d51c6f"),
		H256::from("ce413445e03790498fe72d8e01915e7ff120ae35b3b590d21b7f74dee1830f0d"),
		H256::from("600e6f93e73d7abd4ee0a65cb1b19aa3ecc525689dbf17779658741b95c15a55"),
	].to_vec();
}

pub trait Dim {
	const HEIGHT: usize;
}

pub trait TreeHash {
	/// Get reference to empty hashes.
	fn empty() -> &'static [H256];

	/// Combine two hashes at given depth;
	fn combine(left: &H256, right: &H256, depth: usize) -> H256;
}

#[derive(Clone, Debug, PartialEq)]
pub struct H32;

impl Dim for H32 {
	const HEIGHT: usize = 32;
}

#[derive(Clone, Debug, PartialEq)]
pub struct H29;

impl Dim for H29 {
	const HEIGHT: usize = 29;
}

#[derive(Clone, Debug, PartialEq)]
pub struct SproutTreeHash;

impl TreeHash for SproutTreeHash {
	fn empty() -> &'static [H256] {
		&SPROUT_EMPTY_ROOTS
	}

	fn combine(left: &H256, right: &H256, _depth: usize) -> H256 {
		sha256_compress(&**left, &**right)
	}
}

#[derive(Clone, Debug, PartialEq)]
pub struct SaplingTreeHash;

impl TreeHash for SaplingTreeHash {
	fn empty() -> &'static [H256] {
		&SAPLING_EMPTY_ROOTS
	}

	fn combine(left: &H256, right: &H256, depth: usize) -> H256 {
		pedersen_hash(&**left, &**right, depth)
	}
}

#[derive(Clone, Debug, PartialEq)]
pub struct TreeState<D: Dim, H: TreeHash> {
	_phantom: ::std::marker::PhantomData<(D, H)>,
	left: Option<H256>,
	right: Option<H256>,
	parents: Vec<Option<H256>>,
	is_empty: bool,
}

impl<D: Dim, H: TreeHash> TreeState<D, H> {
	pub fn new() -> Self {
		TreeState {
			_phantom: ::std::marker::PhantomData,
			left: None,
			right: None,
			parents: vec![None; D::HEIGHT - 1],
			is_empty: true,
		}
	}

	pub fn append(&mut self, hash: H256) -> Result<(), &'static str> {
		if self.left.is_none() {
			self.left = Some(hash);
		} else if self.right.is_none() {
			self.right = Some(hash);
		} else {
			let former_left = ::std::mem::replace(&mut self.left, Some(hash))
				.expect("none variant is handled in the branch above; qed");
			let former_right = self.right.take()
				.expect("none variant is handled in the branch above; qed");

			let mut combined = H::combine(&former_left, &former_right, 0);
			for i in 0..D::HEIGHT-1 {
				let parent_slot = &mut self.parents[i as usize];

				match parent_slot.take() {
					None => {
						*parent_slot = Some(combined);
						return Ok(());
					},
					Some(former) => {
						combined = H::combine(&former, &combined, i + 1)
					},
				}
			}

			return Err("Appending to full tree");
		}

		self.is_empty = false;
		Ok(())
	}

	pub fn root(&self) -> H256 {
		if self.is_empty {
			return Self::empty_root();
		}

		let left = self.left.as_ref().unwrap_or(&H::empty()[0]);
		let right = self.right.as_ref().unwrap_or(&H::empty()[0]);

		let mut root = H::combine(&left, &right, 0);

		for i in 0..D::HEIGHT-1 {
			match &self.parents[i as usize] {
				&Some(ref parent) => { root = H::combine(&parent, &root, i + 1); }
				&None => { root = H::combine(&root, &H::empty()[i as usize + 1], i + 1); },
			}
		}

		root
	}

	pub fn empty_root() -> H256 {
		H::empty()[D::HEIGHT]
	}
}

pub type SproutTreeState = TreeState<H29, SproutTreeHash>;
pub type SaplingTreeState = TreeState<H32, SaplingTreeHash>;

impl<D: Dim, H: TreeHash> serialization::Serializable for TreeState<D, H> {
	fn serialize(&self, stream: &mut serialization::Stream) {
		stream.append(&self.left);
		stream.append(&self.right);
		stream.append_list(&self.parents);
	}
}

impl<D: Dim, H: TreeHash> serialization::Deserializable for TreeState<D, H> {
	fn deserialize<R: ::std::io::Read>(reader: &mut serialization::Reader<R>)
		-> Result<Self, serialization::Error>
	{
		let mut tree_state = TreeState::new();
		tree_state.left = reader.read()?;
		tree_state.right = reader.read()?;
		tree_state.parents = reader.read_list()?;

		tree_state.is_empty = tree_state.left.is_none()
			&& tree_state.right.is_none()
			&& tree_state.parents.iter().all(Option::is_none);

		Ok(tree_state)
	}
}

#[cfg(test)]
mod tests {

	use super::*;

	pub struct H4;

	impl Dim for H4 {
		const HEIGHT: usize = 4;
	}

	type TestSproutTreeState = TreeState<H4, SproutTreeHash>;
	type TestSaplingTreeState = TreeState<H4, SaplingTreeHash>;

	pub struct H1;

	impl Dim for H1 {
		const HEIGHT: usize = 1;
	}

	pub struct H2;

	impl Dim for H2 {
		const HEIGHT: usize = 2;
	}

	#[test]
	fn single_root() {
		let mut tree = TreeState::<H1, SproutTreeHash>::new();
		tree.append(SPROUT_EMPTY_ROOTS[0].clone()).unwrap();

		assert_eq!(
			tree.root(),
			H256::from("da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8")
		);
	}

	#[test]
	fn empty_29_root() {
		assert_eq!(
			SproutTreeState::new().root(),
			H256::from("d7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd259"),
		)
	}

	#[test]
	fn appended_1_29_root() {
		let mut tree = SproutTreeState::new();
		tree.append(H256::from("bab6e8992959caf0ca94847c36b4e648a7f88a9b9c6a62ea387cf1fb9badfd62"))
			.expect("failed to append to the tree");
		assert_eq!(
			tree.root(),
			H256::from("128ebe145c5d6fd81cc7734c90db0e284dd888870d4488314ef4ad70a34232aa")
		);
	}

	#[test]
	fn single_elem_in_double_tree() {
		let mut tree = TreeState::<H2, SproutTreeHash>::new();
		tree.append(SPROUT_EMPTY_ROOTS[0].clone()).unwrap();

		assert_eq!(
			tree.root(),
			H256::from("dc766fab492ccf3d1e49d4f374b5235fa56506aac2224d39f943fcd49202974c")
		);
	}

	#[test]
	fn commitment_1() {
		let mut tree = TestSproutTreeState::new();
		tree.append(H256::from_reversed_str("bab6e8992959caf0ca94847c36b4e648a7f88a9b9c6a62ea387cf1fb9badfd62"))
			.unwrap();

		assert_eq!(
			tree.root(),
			H256::from("95bf71d8e803b8601c14b5949d0f92690181154ef9d82eb3e24852266823317a")
		);
	}

	#[test]
	fn commitment_2() {
		let mut tree = TestSproutTreeState::new();
		tree.append(H256::from_reversed_str("bab6e8992959caf0ca94847c36b4e648a7f88a9b9c6a62ea387cf1fb9badfd62"))
			.unwrap();
		tree.append(H256::from_reversed_str("43c9a4b21555b832a79fc12ce27a97d4f4eca1638e7161a780db1d5ebc35eb68"))
			.unwrap();

		assert_eq!(
			tree.root(),
			H256::from("73f18d3f9cd11010aa01d4f444039e566f14ef282109df9649b2eb75e7a53ed1")
		);
	}

	#[test]
	fn glass() {
		let mut tree = TestSproutTreeState::new();
		tree.append(H256::from_reversed_str("bab6e8992959caf0ca94847c36b4e648a7f88a9b9c6a62ea387cf1fb9badfd62"))
			.unwrap();
		tree.append(H256::from_reversed_str("43c9a4b21555b832a79fc12ce27a97d4f4eca1638e7161a780db1d5ebc35eb68"))
			.unwrap();
		tree.append(H256::from_reversed_str("fb92a6142315bb3396b693222bf2d0e260b448cda74e189063cf774048456083"))
			.unwrap();

		// left should be last added hash
		assert_eq!(tree.left, Some(H256::from_reversed_str("fb92a6142315bb3396b693222bf2d0e260b448cda74e189063cf774048456083")));

		// right should be none
		assert_eq!(tree.right, None);

		// parent#0 should 1st and 2nd combined
		assert_eq!(
			tree.parents[0],
			Some(
				sha256_compress(
					&*H256::from_reversed_str("bab6e8992959caf0ca94847c36b4e648a7f88a9b9c6a62ea387cf1fb9badfd62"),
					&*H256::from_reversed_str("43c9a4b21555b832a79fc12ce27a97d4f4eca1638e7161a780db1d5ebc35eb68")
				)
			)
		);

		// parent#1 should not be set
		assert_eq!(
			tree.parents[1],
			None,
		);

		assert_eq!(
			tree.root(),
			H256::from("dcde8a273c9672bee1a894d7f7f4abb81078f52b498e095f2a87d0aec5addf25")
		);

		tree.append(H256::from_reversed_str("e44a57cd544018937680d385817be3a3e35bb5b87ceeea93d536ea95828a4992"))
			.unwrap();

		// left should be unaffeted
		assert_eq!(tree.left, Some(H256::from_reversed_str("fb92a6142315bb3396b693222bf2d0e260b448cda74e189063cf774048456083")));

		// right should be last added hash
		assert_eq!(tree.right, Some(H256::from_reversed_str("e44a57cd544018937680d385817be3a3e35bb5b87ceeea93d536ea95828a4992")));

		// *** FINAL ROUND ***
		tree.append(H256::from_reversed_str("43f48bfb9ab6f12ef91ce83e8f9190ce5dff2721784c90e08a50a67403367cff"))
			.unwrap();

		// left should be last added hash
		assert_eq!(tree.left, Some(H256::from_reversed_str("43f48bfb9ab6f12ef91ce83e8f9190ce5dff2721784c90e08a50a67403367cff")));

		// right should be none now
		assert_eq!(tree.right, None);

		// parent #0 should be None
		assert_eq!(tree.parents[0], None);

		// parent #1 should be combined what?
		assert_eq!(tree.parents[1], Some(
			sha256_compress(
				// this was parent[0]
				&*sha256_compress(
					&*H256::from_reversed_str("bab6e8992959caf0ca94847c36b4e648a7f88a9b9c6a62ea387cf1fb9badfd62"),
					&*H256::from_reversed_str("43c9a4b21555b832a79fc12ce27a97d4f4eca1638e7161a780db1d5ebc35eb68")
				),
				// this is left and right
				&*sha256_compress(
					&*H256::from_reversed_str("fb92a6142315bb3396b693222bf2d0e260b448cda74e189063cf774048456083"),
					&*H256::from_reversed_str("e44a57cd544018937680d385817be3a3e35bb5b87ceeea93d536ea95828a4992")
				),
			)
		));
	}

	lazy_static! {
		static ref TEST_COMMITMENTS: Vec<H256> = [
			H256::from_reversed_str("bab6e8992959caf0ca94847c36b4e648a7f88a9b9c6a62ea387cf1fb9badfd62"),
			H256::from_reversed_str("43c9a4b21555b832a79fc12ce27a97d4f4eca1638e7161a780db1d5ebc35eb68"),
			H256::from_reversed_str("fb92a6142315bb3396b693222bf2d0e260b448cda74e189063cf774048456083"),
			H256::from_reversed_str("e44a57cd544018937680d385817be3a3e35bb5b87ceeea93d536ea95828a4992"),
			H256::from_reversed_str("43f48bfb9ab6f12ef91ce83e8f9190ce5dff2721784c90e08a50a67403367cff"),
			H256::from_reversed_str("fce910561c3c7ebf14ed5d712e6838cdc6f1145c87eec256b7181f9df6d0c468"),
			H256::from_reversed_str("b1e7016392805b227b11e58ba629f9a6684a0b4c34306e85e47548c43ecd168b"),
			H256::from_reversed_str("2d9a49d9425449a449cc62d16febaf9c7f8b32349752ecc39191c36130b4c050"),
			H256::from_reversed_str("53969b31a862b893dde857b8b7d4f53ce0e2c21a0f70d48ba1aef3a05fddff70"),
			H256::from_reversed_str("17f8fabd440fdf9e2eafd75a3407e8bbde048d2d2232cd803d5763004af61ed8"),
			H256::from_reversed_str("9b7805cb5e8ef337c13c73cab58ee719bf33a4a80ecc161bfe714269eca4928b"),
			H256::from_reversed_str("a3ebada94d4329899ae136391604799d8cea39c0c331f9aaaa4a1e73ab63e904"),
			H256::from_reversed_str("12091a20c9ebe67c2793bb71a6fdddb0ffe3ca781fcf1e192428161f186c3fbe"),
			H256::from_reversed_str("e9c65749638df548b8909c0ea1d0f79079a6bb3235c649a8806322c87f968018"),
			H256::from_reversed_str("8e8fddf0438a4263bc926fcfa6733dc201633959f294103533a2cb9328bb65c4"),
			H256::from_reversed_str("206a202bd08dd31f77afc7114b17850192b83948cff5828df0d638cbe734c884")
		].to_vec();
	}

	#[test]
	fn commitments_full() {

		let root_list = [
			H256::from("95bf71d8e803b8601c14b5949d0f92690181154ef9d82eb3e24852266823317a"),
			H256::from("73f18d3f9cd11010aa01d4f444039e566f14ef282109df9649b2eb75e7a53ed1"),
			H256::from("dcde8a273c9672bee1a894d7f7f4abb81078f52b498e095f2a87d0aec5addf25"),
			H256::from("4677d481ec6d1e97969afbc530958d1cbb4f1c047af6fdad4687cd10830e02bd"),
			H256::from("74cd9d82de30c4222a06d420b75522ae1273729c1d8419446adf1184df61dc69"),
			H256::from("2ff57f5468c6afdad30ec0fb6c2cb67289f12584e2c20c4e0065f66748697d77"),
			H256::from("27e4ce010670801911c5765a003b15f75cde31d7378bd36540f593c8a44b3011"),
			H256::from("62231ef2ec8c4da461072871ab7bc9de10253fcb40e164ddbad05b47e0b7fb69"),
			H256::from("733a4ce688fdf07efb9e9f5a4b2dafff87cfe198fbe1dff71e028ef4cdee1f1b"),
			H256::from("df39ed31924facdd69a93db07311d45fceac7a4987c091648044f37e6ecbb0d2"),
			H256::from("87795c069bdb55281c666b9cb872d13174334ce135c12823541e9536489a9107"),
			H256::from("438c80f532903b283230446514e400c329b29483db4fe9e279fdfc79e8f4347d"),
			H256::from("08afb2813eda17e94aba1ab28ec191d4af99283cd4f1c5a04c0c2bc221bc3119"),
			H256::from("a8b3ab3284f3288f7caa21bd2b69789a159ab4188b0908825b34723305c1228c"),
			H256::from("db9b289e620de7dca2ae8fdac96808752e32e7a2c6d97ce0755dcebaa03123ab"),
			H256::from("0bf622cb9f901b7532433ea2e7c1b7632f5935899b62dcf897a71551997dc8cc"),
		];

		let mut tree = TestSproutTreeState::new();

		for i in 0..TEST_COMMITMENTS.len() {
			tree.append(TEST_COMMITMENTS[i].clone()).expect(&format!("Failed to add commitment #{}", i));
			assert_eq!(&tree.root(), &root_list[i]);
		}

		// should return error because tree is full
		assert!(tree.append(H256::from("0bf622cb9f901b7532433ea2e7c1b7632f5935899b62dcf897a71551997dc8cc")).is_err());
	}

	#[test]
	fn serde() {
		let mut tree = TestSproutTreeState::new();
		for i in 0..TEST_COMMITMENTS.len() {
			tree.append(TEST_COMMITMENTS[i].clone()).expect(&format!("Failed to add commitment #{}", i));
		}

		assert!(!tree.is_empty);
		assert_eq!(tree.root(), H256::from("0bf622cb9f901b7532433ea2e7c1b7632f5935899b62dcf897a71551997dc8cc"));

		let mut stream = serialization::Stream::new();
		stream.append(&tree);

		let bytes = stream.out();

		let mut reader = serialization::Reader::new(&bytes[..]);
		let deserialized_tree: TestSproutTreeState = reader.read().expect("Failed to deserialize");

		assert!(!tree.is_empty);
		assert_eq!(deserialized_tree.root(), H256::from("0bf622cb9f901b7532433ea2e7c1b7632f5935899b62dcf897a71551997dc8cc"));
	}

	#[test]
	fn serde_empty() {
		let tree = TestSproutTreeState::new();
		let mut stream = serialization::Stream::new();
		assert!(tree.is_empty);
		stream.append(&tree);

		let bytes = stream.out();

		let mut reader = serialization::Reader::new(&bytes[..]);
		let deserialized_tree: TestSproutTreeState = reader.read().expect("Failed to deserialize");
		assert!(deserialized_tree.is_empty);
	}

	#[test]
	fn sapling_empty_root() {
		let expected_root = H256::from_reversed_str("3e49b5f954aa9d3545bc6c37744661eea48d7c34e3000d82b7f0010c30f4c2fb");
		let actual_root = SaplingTreeState::empty_root();
		assert_eq!(actual_root, expected_root);
	}

	#[test]
	fn sapling_tree_state_root() {
		// some tests from:
		// https://github.com/zcash/zcash/blob/92cd76fcba8f284694f213547293a1cfc2c0369d/src/gtest/test_merkletree.cpp#L208

		let commitments = [
			H256::from_reversed_str("556f3af94225d46b1ef652abc9005dee873b2e245eef07fd5be587e0f21023b0"),
			H256::from_reversed_str("d814b127a6c6b8f07ed03f0f6e2843ff04c9851ff824a4e5b4dad5b5f3475722"),
			H256::from_reversed_str("ec030e6d7460f91668cc842ceb78cdb54470469e78cd59cf903d3a6e1aa03e7c"),
			H256::from_reversed_str("b0a0d08406b9e3693ee4c062bd1e6816f95bf14f5a13aafa1d57942c6c1d4250"),
			H256::from_reversed_str("92fc3e7298eb327a88abcc406fbe595e45dddd9b4209803b2e0baa3a8663ecaa"),
			H256::from_reversed_str("f607dd230ada93d14f4de1d9008a5e64a59af87c2e4f64a5f9e55e0cd44867f8"),
			H256::from_reversed_str("ae0bfc1e123edcb6252251611650f3667371f781b60302385c414716c75e8abc"),
			H256::from_reversed_str("91a5e54bf9a9b57e1c163904999ad1527f1e126c685111e18193decca2dd1ada"),
			H256::from_reversed_str("c674f7836089063143fc18b673b2d92f888c63380e3680385d47bcdbd5fe273a"),
			H256::from_reversed_str("7c1dbdb260441b89a08ba411d5f8406e81abd9dc85382f307999fdf77d8fcac8"),
			H256::from_reversed_str("02372c746664e0898576972ca6d0500c7c8ec42f144622349d133b06e837faf0"),
			H256::from_reversed_str("08c6d7dd3d2e387f7b84d6769f2b6cbe308918ab81e0f7321bd0945868d7d4e6"),
			H256::from_reversed_str("a6e8c4061f2ad984d19f2c0a4436b9800e529069c0b0d3186d4683e83bb7eb8c"),
			H256::from_reversed_str("837cc2391338956026521beca5c81b541b7f2d1ead7758bf4d1588dbbcb8fa22"),
			H256::from_reversed_str("1cc467cfd2b504e156c9a38bc5c0e4f5ea6cc208054d2d0653a7e561ac3a3ef4"),
			H256::from_reversed_str("15ac4057a9a94536eca9802de65e985319e89627c9c64bc94626b712bc61363a"),
		];

		let roots = [
			H256::from("8c3daa300c9710bf24d2595536e7c80ff8d147faca726636d28e8683a0c27703"),
			H256::from("8611f17378eb55e8c3c3f0a5f002e2b0a7ca39442fc928322b8072d1079c213d"),
			H256::from("3db73b998d536be0e1c2ec124df8e0f383ae7b602968ff6a5276ca0695023c46"),
			H256::from("7ac2e6442fec5970e116dfa4f2ee606f395366cafb1fa7dfd6c3de3ce18c4363"),
			H256::from("6a8f11ab2a11c262e39ed4ea3825ae6c94739ccf94479cb69402c5722b034532"),
			H256::from("102b109d1d41f762852c2068df174db8d5313bc8195b1e72d4c3c2ed8f5b9f5b"),
			H256::from("37807232a70f2259451cfdd55fcb9db766b2c8a567bf84ccc0c19004828a061e"),
			H256::from("d5136159c424f6728de653cad86e59745aa319e2e05c577ab5820763db7d9838"),
			H256::from("f9dfc0f06bc8c70d6e74309bbdb89b13a6917992cebd48101c5441b017477b0b"),
			H256::from("a50c3af16b41f35bf127cd8cf03a083b95e65c18d1a40b60bd617c8f9c011042"),
			H256::from("3385fbc241ed176b0140d111cb17a51ebd3aab12626bdb89d636db67e360e139"),
			H256::from("e38bf6a3784f2febe4b9bec1658da6bf05438acd647932bbf35f525af127bd5b"),
			H256::from("60b63895c392a16a327b0ed5f828dcd6238cdba379c4ab41aa4c4547ecf52c27"),
			H256::from("5e9642b3149706553d2bd8744025babdc2d6a4e4efa31d30377331f21ad30258"),
			H256::from("e36e68df1af4fe4a779ed2aa1c96f09df222f507602d22b2c1bcee764617ce04"),
			H256::from("886f6518ceae948fa8d8c90d53c58fee66dd4f7fd38a40d3868bc06ed73f546a"),
		];

		let mut tree_state = TestSaplingTreeState::new();

		let expected_root = TestSaplingTreeState::empty_root();
		let actual_root = tree_state.root();
		assert_eq!(actual_root, expected_root);

		for (commitment, expected_root) in commitments.iter().zip(roots.iter()) {
			tree_state.append(*commitment).unwrap();
			let actual_root = tree_state.root();
			assert_eq!(actual_root, *expected_root);
		}
	}
}
