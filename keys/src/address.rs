//! `AddressHash` with network identifier and format type
//!
//! A Bitcoin address, or simply address, is an identifier of 26-35 alphanumeric characters, beginning with the number 1
//! or 3, that represents a possible destination for a bitcoin payment.
//!
//! https://en.bitcoin.it/wiki/Address

use std::fmt;
use std::str::FromStr;
use std::ops::Deref;
use base58::{ToBase58, FromBase58};
use crypto::checksum;
use network::Network;
use {DisplayLayout, Error, AddressHash};

/// There are two transparent address formats currently in use.
/// https://bitcoin.org/en/developer-reference#address-conversion
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Type {
	/// Pay to PubKey Hash
	/// Common P2PKH which begin with the number 1, eg: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.
	/// https://bitcoin.org/en/glossary/p2pkh-address
	P2PKH,
	/// Pay to Script Hash
	/// Newer P2SH type starting with the number 3, eg: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy.
	/// https://bitcoin.org/en/glossary/p2sh-address
	P2SH,
}

/// `AddressHash` with network identifier and format type
#[derive(Debug, PartialEq, Clone)]
pub struct Address {
	/// The type of the address.
	pub kind: Type,
	/// The network of the address.
	pub network: Network,
	/// Public key hash.
	pub hash: AddressHash,
}

pub struct AddressDisplayLayout([u8; 26]);

impl Deref for AddressDisplayLayout {
	type Target = [u8];

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl DisplayLayout for Address {
	type Target = AddressDisplayLayout;

	fn layout(&self) -> Self::Target {
		let mut result = [0u8; 26];

		result[..2].copy_from_slice(&match (self.network, self.kind) {
			(Network::Mainnet, Type::P2PKH) => [0x1C, 0xB8],
			(Network::Testnet, Type::P2PKH) => [0x1D, 0x25],
			(Network::Mainnet, Type::P2SH) => [0x1C, 0xBD],
			(Network::Testnet, Type::P2SH) => [0x1C, 0xBA],
		});

		result[2..22].copy_from_slice(&*self.hash);
		let cs = checksum(&result[0..22]);
		result[22..].copy_from_slice(&*cs);
		AddressDisplayLayout(result)
	}

	fn from_layout(data: &[u8]) -> Result<Self, Error> where Self: Sized {
		if data.len() != 26 {
			return Err(Error::InvalidAddress);
		}

		let cs = checksum(&data[..22]);
		if &data[22..] != &*cs {
			return Err(Error::InvalidChecksum);
		}

		let (network, kind) = match (data[0], data[1]) {
			(0x1C, 0xB8) => (Network::Mainnet, Type::P2PKH),
			(0x1C, 0xBD) => (Network::Mainnet, Type::P2SH),
			(0x1D, 0x25) => (Network::Testnet, Type::P2PKH),
			(0x1C, 0xBA) => (Network::Testnet, Type::P2SH),
			_ => return Err(Error::InvalidAddress),
		};

		let mut hash = AddressHash::default();
		hash.copy_from_slice(&data[2..22]);

		let address = Address {
			kind: kind,
			network: network,
			hash: hash,
		};

		Ok(address)
	}
}

impl fmt::Display for Address {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		self.layout().to_base58().fmt(f)
	}
}

impl FromStr for Address {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Error> where Self: Sized {
		let hex = try!(s.from_base58().map_err(|_| Error::InvalidAddress));
		Address::from_layout(&hex)
	}
}

impl From<&'static str> for Address {
	fn from(s: &'static str) -> Self {
		s.parse().unwrap()
	}
}

#[cfg(test)]
mod tests {
	use network::Network;
	use super::{Address, Type};

	#[test]
	fn test_address_to_string() {
		let address = Address {
			kind: Type::P2PKH,
			network: Network::Mainnet,
			hash: "ff197b14e502ab41f3bc8ccb48c4abac9eab35bc".into(),
		};

		assert_eq!("t1h8SqgtM3QM5e2M8EzhhT1yL2PXXtA6oqe".to_owned(), address.to_string());
	}

	#[test]
	fn test_address_from_str() {
		let address = Address {
			kind: Type::P2PKH,
			network: Network::Mainnet,
			hash: "ff197b14e502ab41f3bc8ccb48c4abac9eab35bc".into(),
		};

		assert_eq!(address, "t1h8SqgtM3QM5e2M8EzhhT1yL2PXXtA6oqe".into());
	}
}
