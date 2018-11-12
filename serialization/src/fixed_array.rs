use std::{fmt, io};
use hex::ToHex;
use primitives::hash::H256;
use {
	Serializable, Stream,
	Deserializable, Reader, Error as ReaderError
};

macro_rules! impl_fixed_array {
	($name: ident, $type: ty, $len: expr) => {

		/// A type for fixed-length array.
		#[derive(Default, Debug, Clone, PartialEq)]
		pub struct $name(pub [$type; $len]);

		impl Serializable for $name {
			fn serialize(&self, stream: &mut Stream) {
				for i in 0..$len {
					stream.append(&self.0[i]);
				}
			}

			fn serialized_size(&self) -> usize {
				$len * ::std::mem::size_of::<$type>()
			}
		}

		impl Deserializable for $name {
			fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, ReaderError> where T: io::Read {
				//let mut array = [Default::default(); $len];
				let mut array: [$type; $len] = Default::default();
				for i in 0..$len {
					array[i] = reader.read()?;
				}
				Ok($name(array))
			}
		}

	}
}

macro_rules! impl_fixed_array_u8 {
	($name: ident, $len: expr) => {

		/// A type for fixed-length array.
		#[derive(Clone)]
		pub struct $name(pub [u8; $len]);

		impl PartialEq for $name {
			fn eq(&self, other: &Self) -> bool {
				self.0.iter().zip(other.0.iter()).all(|(l, r)| l == r)
			}
		}

		impl Default for $name {
			fn default() -> Self {
				$name([0; $len])
			}
		}

		impl fmt::Debug for $name {
			fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
				self.0.to_hex::<String>().fmt(f)
			}
		}

		impl Serializable for $name {
			fn serialize(&self, stream: &mut Stream) {
				stream.append_slice(&self.0);
			}

			fn serialized_size(&self) -> usize {
				$len
			}
		}

		impl Deserializable for $name {
			fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, ReaderError> where T: io::Read {
				let mut array = [0; $len];
				reader.read_slice(&mut array)?;
				Ok($name(array))
			}
		}

	}
}

impl_fixed_array!(FixedArray_H256_2, H256, 2);
impl_fixed_array_u8!(FixedArray_u8_296, 296);
impl_fixed_array_u8!(FixedArray_u8_601, 601);
impl_fixed_array!(FixedArray_u8_601_2, FixedArray_u8_601, 2);
