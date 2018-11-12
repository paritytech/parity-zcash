#[macro_use]
extern crate lazy_static;

extern crate chain;
extern crate primitives;
extern crate serialization;
extern crate rustc_hex as hex;

mod consensus;
mod deployments;
mod network;

pub use primitives::{hash, compact};

pub use consensus::{ConsensusParams, ConsensusFork, BitcoinCashConsensusParams, ZCashConsensusParams, TransactionOrdering};
pub use deployments::Deployment;
pub use network::{Magic, Network};
