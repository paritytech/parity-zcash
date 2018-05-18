extern crate byteorder;
extern crate primitives;

mod compact_integer;
mod flags;
mod impls;
mod list;
mod reader;
mod stream;

pub use primitives::{hash, bytes, compact};

// TODO: use same flags for both serialization && deserialization (they're used this way on network layer)

pub use flags::{set_default_flags, get_default_flags};
pub use compact_integer::CompactInteger;
pub use list::List;
pub use reader::{Reader, Deserializable, deserialize, deserialize_with_flags, deserialize_iterator,
	ReadIterator, Error, DESERIALIZE_ZCASH,
};
pub use stream::{
	Stream, Serializable, serialize, serialize_with_flags, serialize_list, serialized_list_size,
	serialized_list_size_with_flags, SERIALIZE_TRANSACTION_WITNESS, SERIALIZE_ZCASH,
};


static mut GLOBAL_SERIALIZATION_FLAGS: u32 = SERIALIZE_ZCASH;

