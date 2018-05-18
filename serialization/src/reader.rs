use std::{io, marker};
use compact_integer::CompactInteger;
use flags::get_default_flags;

/// Deserialize transaction witness data.
pub const DESERIALIZE_TRANSACTION_WITNESS: u32 = 0x40000000;
/// Deserialize everything in ZCash format.
pub const DESERIALIZE_ZCASH: u32 = 0x80000000;

pub fn deserialize<R, T>(buffer: R) -> Result<T, Error> where R: io::Read, T: Deserializable {
	let mut reader = Reader::from_read(buffer);
	let result = try!(reader.read());

	if reader.is_finished() {
		Ok(result)
	} else {
		Err(Error::UnreadData)
	}
}

pub fn deserialize_with_flags<R, T>(buffer: R, flags: u32) -> Result<T, Error> where R: io::Read, T: Deserializable {
	let mut reader = Reader::from_read_with_flags(buffer, flags);
	let result = try!(reader.read());

	if reader.is_finished() {
		Ok(result)
	} else {
		Err(Error::UnreadData)
	}

}

pub fn deserialize_iterator<R, T>(buffer: R) -> ReadIterator<R, T> where R: io::Read, T: Deserializable {
	ReadIterator {
		reader: Reader::from_read(buffer),
		iter_type: marker::PhantomData,
	}
}

#[derive(Debug, PartialEq)]
pub enum Error {
	MalformedData,
	UnexpectedEnd,
	UnreadData,
}

impl From<io::Error> for Error {
	fn from(_: io::Error) -> Self {
		Error::UnexpectedEnd
	}
}

pub trait Deserializable {
	fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error> where Self: Sized, T: io::Read;
}

/// Bitcoin structures reader.
#[derive(Debug)]
pub struct Reader<T> {
	buffer: T,
	peeked: Option<u8>,
	flags: u32,
}

impl<'a> Reader<&'a [u8]> {
	/// Convenient way of creating for slice of bytes
	pub fn new(buffer: &'a [u8], flags: u32) -> Self {
		Reader {
			buffer: buffer,
			peeked: None,
			flags: flags | get_default_flags(),
		}
	}
}

impl<T> io::Read for Reader<T> where T: io::Read {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
		// most of the times, there will be nothing in peeked,
		// so to make it as efficient as possible, check it
		// only once
		match self.peeked.take() {
			None => io::Read::read(&mut self.buffer, buf),
			Some(peeked) if buf.is_empty() => {
				self.peeked = Some(peeked);
				Ok(0)
			},
			Some(peeked) => {
				buf[0] = peeked;
				io::Read::read(&mut self.buffer, &mut buf[1..]).map(|x| x + 1)
			},
		}
	}
}

impl<R> Reader<R> where R: io::Read {
	pub fn from_read(read: R) -> Self {
		Self::from_read_with_flags(read, 0)
	}

	pub fn from_read_with_flags(read: R, flags: u32) -> Self {
		Reader {
			buffer: read,
			peeked: None,
			flags: flags,
		}
	}

	/// Are transactions read from this stream with witness data?
	pub fn read_transaction_witness(&self) -> bool {
		(self.flags & DESERIALIZE_TRANSACTION_WITNESS) != 0
	}

	/// Is data read from this stream in ZCash format?
	pub fn is_zcash_reader(&self) -> bool {
		(self.flags & DESERIALIZE_ZCASH) != 0
	}

	pub fn read<T>(&mut self) -> Result<T, Error> where T: Deserializable {
		T::deserialize(self)
	}

	pub fn read_with_proxy<T, F>(&mut self, proxy: F) -> Result<T, Error> where T: Deserializable, F: FnMut(&[u8]) {
		let mut reader = Reader::from_read(Proxy::new(self, proxy));
		T::deserialize(&mut reader)
	}

	pub fn read_slice(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
		io::Read::read_exact(self, bytes).map_err(|_| Error::UnexpectedEnd)
	}

	pub fn read_list<T>(&mut self) -> Result<Vec<T>, Error> where T: Deserializable {
		let len: usize = try!(self.read::<CompactInteger>()).into();
		let mut result = Vec::with_capacity(len);

		for _ in 0..len {
			result.push(try!(self.read()));
		}

		Ok(result)
	}

	pub fn read_list_max<T>(&mut self, max: usize) -> Result<Vec<T>, Error> where T: Deserializable {
		let len: usize = try!(self.read::<CompactInteger>()).into();
		if len > max {
			return Err(Error::MalformedData);
		}

		let mut result = Vec::with_capacity(len);

		for _ in 0..len {
			result.push(try!(self.read()));
		}

		Ok(result)
	}

	#[cfg_attr(feature="cargo-clippy", allow(wrong_self_convention))]
	pub fn is_finished(&mut self) -> bool {
		if self.peeked.is_some() {
			return false;
		}

		let peek: &mut [u8] = &mut [0u8];
		match self.read_slice(peek) {
			Ok(_) => {
				self.peeked = Some(peek[0]);
				false
			},
			Err(_) => true,
		}
	}
}

/// Should be used to iterate over structures of the same type
pub struct ReadIterator<R, T> {
	reader: Reader<R>,
	iter_type: marker::PhantomData<T>,
}

impl<R, T> Iterator for ReadIterator<R, T> where R: io::Read, T: Deserializable {
	type Item = Result<T, Error>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.reader.is_finished() {
			None
		} else {
			Some(self.reader.read())
		}
	}
}

struct Proxy<F, T> {
	from: F,
	to: T,
}

impl<F, T> Proxy<F, T> {
	fn new(from: F, to: T) -> Self {
		Proxy {
			from: from,
			to: to,
		}
	}
}

impl<F, T> io::Read for Proxy<F, T> where F: io::Read, T: FnMut(&[u8]) {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
		let len = try!(io::Read::read(&mut self.from, buf));
		let to = &mut self.to;
		to(&buf[..len]);
		Ok(len)
	}
}
