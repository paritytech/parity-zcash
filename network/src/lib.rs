#[macro_use]
extern crate lazy_static;

extern crate chain;
extern crate primitives;
extern crate serialization;
extern crate bitcrypto as crypto;
extern crate keys;
extern crate rustc_hex as hex;

mod consensus;
mod deployments;
mod network;

pub use primitives::{hash, compact};

pub use consensus::ConsensusParams;
pub use deployments::Deployment;
pub use network::{Magic, Network};
