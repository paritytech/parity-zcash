use std::io;
use {
	Serializable, Stream,
	Deserializable, Reader, Error
};

/// Something that can be used to initialize empty array.
pub trait DefaultItem: Copy {
	fn default() -> Self;
}

macro_rules! impl_default_item {
	($type: ty) => {
		impl DefaultItem for $type {
			fn default() -> Self {
				Default::default()
			}
		}
	}
}

macro_rules! impl_fixed_array {
	($size: expr) => {
		impl<T: DefaultItem> DefaultItem for [T; $size] {
			fn default() -> Self {
				[T::default(); $size]
			}
		}

		impl<T: Serializable> Serializable for [T; $size] {
			fn serialize(&self, stream: &mut Stream) {
				self.iter().for_each(|item| { stream.append(item); });
			}
		}

		impl<T: DefaultItem + Deserializable> Deserializable for [T; $size] {
			fn deserialize<R>(reader: &mut Reader<R>) -> Result<Self, Error> where R: io::Read {
				let mut result = [T::default(); $size];
				for i in 0..$size {
					result[i] = reader.read()?;
				}
				Ok(result)
			}
		}
	}
}

impl_default_item!(u8);

impl_fixed_array!(2);
impl_fixed_array!(32);
impl_fixed_array!(64);
impl_fixed_array!(80);
impl_fixed_array!(192);
impl_fixed_array!(296);
impl_fixed_array!(580);
impl_fixed_array!(601);
