use hash::H256;
use crypto::sha256_compress;

lazy_static! {
	static ref EMPTY_ROOTS: Vec<H256> = [
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
}

pub trait Dim {
	const HEIGHT: usize;
}

pub struct H32;

impl Dim for H32 {
	const HEIGHT: usize = 32;
}

pub struct TreeState<D: Dim> {
	_phantom: ::std::marker::PhantomData<D>,
	left: Option<H256>,
	right: Option<H256>,
	parents: Vec<Option<H256>>,
}

impl<D: Dim> TreeState<D> {
	pub fn new() -> Self {
		TreeState {
			_phantom: ::std::marker::PhantomData,
			left: None,
			right: None,
			parents: vec![None; D::HEIGHT - 1],
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

			let mut combined = sha256_compress(&*former_left, &*former_right);
			for i in 0..D::HEIGHT-1 {
				let parent_slot = &mut self.parents[i as usize];

				match parent_slot.take() {
					None => {
						*parent_slot = Some(combined);
						return Ok(());
					},
					Some(former) => {
						combined = sha256_compress(&*former, &*combined)
					},
				}
			}

			return Err("Appending to full tree");
		}
		Ok(())
	}

	pub fn root(&self) -> H256 {
		let left = self.left.as_ref().unwrap_or(&EMPTY_ROOTS[0]);
		let right = self.right.as_ref().unwrap_or(&EMPTY_ROOTS[0]);

		let mut root = sha256_compress(&**left, &**right);

		for i in 0..D::HEIGHT-1 {
			match &self.parents[i as usize] {
				&Some(ref parent) => { root = sha256_compress(&**parent, &*root); }
				&None => { root = sha256_compress(&*root, &*EMPTY_ROOTS[i as usize + 1]); },
			}
		}

		root
	}
}

pub type RegularTreeState = TreeState<H32>;

impl<D: Dim> serialization::Serializable for TreeState<D> {
	fn serialize(&self, stream: &mut serialization::Stream) {
		stream.append(&self.left);
		stream.append(&self.right);
		stream.append_list(&self.parents);
	}
}

impl<D: Dim> serialization::Deserializable for TreeState<D> {
	fn deserialize<R: ::std::io::Read>(reader: &mut serialization::Reader<R>)
		-> Result<Self, serialization::Error>
	{
		let mut tree_state = TreeState::<D>::new();
		tree_state.left = reader.read()?;
		tree_state.right = reader.read()?;
		tree_state.parents = reader.read_list()?;

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

	type TestTreeState = TreeState<H4>;

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
		let mut tree = TreeState::<H1>::new();
		tree.append(EMPTY_ROOTS[0].clone()).unwrap();

		assert_eq!(
			tree.root(),
			H256::from("da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8")
		);
	}

	#[test]
	fn empty_32_root() {
		assert_eq!(
			RegularTreeState::new().root(),
			H256::from("ac58cd1388fec290d398f1944b564449a63c815880566bd1d189f7839e3b0c8c"),
		)
	}

	#[test]
	fn single_elem_in_double_tree() {
		let mut tree = TreeState::<H2>::new();
		tree.append(EMPTY_ROOTS[0].clone()).unwrap();

		assert_eq!(
			tree.root(),
			H256::from("dc766fab492ccf3d1e49d4f374b5235fa56506aac2224d39f943fcd49202974c")
		);
	}

	#[test]
	fn commitment_1() {
		let mut tree = TestTreeState::new();
		tree.append(H256::from_reversed_str("bab6e8992959caf0ca94847c36b4e648a7f88a9b9c6a62ea387cf1fb9badfd62"))
			.unwrap();

		assert_eq!(
			tree.root(),
			H256::from("95bf71d8e803b8601c14b5949d0f92690181154ef9d82eb3e24852266823317a")
		);
	}

	#[test]
	fn commitment_2() {
		let mut tree = TestTreeState::new();
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
		let mut tree = TestTreeState::new();
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

		let mut tree = TestTreeState::new();

		for i in 0..TEST_COMMITMENTS.len() {
			tree.append(TEST_COMMITMENTS[i].clone()).expect(&format!("Failed to add commitment #{}", i));
			assert_eq!(&tree.root(), &root_list[i]);
		}

		// should return error because tree is full
		assert!(tree.append(H256::from("0bf622cb9f901b7532433ea2e7c1b7632f5935899b62dcf897a71551997dc8cc")).is_err());
	}

	#[test]
	fn serde() {
		let mut tree = TestTreeState::new();
		for i in 0..TEST_COMMITMENTS.len() {
			tree.append(TEST_COMMITMENTS[i].clone()).expect(&format!("Failed to add commitment #{}", i));
		}

		assert_eq!(tree.root(), H256::from("0bf622cb9f901b7532433ea2e7c1b7632f5935899b62dcf897a71551997dc8cc"));

		let mut stream = serialization::Stream::new();
		stream.append(&tree);

		let bytes = stream.out();

		let mut reader = serialization::Reader::new(&bytes[..]);
		let deserialized_tree: TestTreeState = reader.read().expect("Failed to deserialize");

		assert_eq!(deserialized_tree.root(), H256::from("0bf622cb9f901b7532433ea2e7c1b7632f5935899b62dcf897a71551997dc8cc"));
	}
}