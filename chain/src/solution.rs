use std::{fmt, io};
use hex::ToHex;
use ser::{Error, Serializable, Deserializable, Stream, Reader};

/// Equihash solution size.
pub const SOLUTION_SIZE: usize = 1344;

#[derive(Clone)]
pub struct EquihashSolution([u8; SOLUTION_SIZE]);

impl AsRef<[u8]> for EquihashSolution {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl Default for EquihashSolution {
	fn default() -> Self {
		EquihashSolution([0; SOLUTION_SIZE])
	}
}

impl PartialEq<EquihashSolution> for EquihashSolution {
	fn eq(&self, other: &EquihashSolution) -> bool {
		self.0.as_ref() == other.0.as_ref()
	}
}

impl fmt::Debug for EquihashSolution {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(&self.0.to_hex::<String>())
	}
}

impl Serializable for EquihashSolution {
	fn serialize(&self, stream: &mut Stream) {
		stream.append_list(&self.0);
	}
}

impl Deserializable for EquihashSolution {
	fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error> where Self: Sized, T: io::Read {
		let v = reader.read_list_exact(SOLUTION_SIZE)?;
		let mut sol = [0; SOLUTION_SIZE];
		sol.copy_from_slice(&v);
		Ok(EquihashSolution(sol))
	}
}
