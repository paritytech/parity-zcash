use primitives::compact::Compact;
use chain::IndexedBlockHeader;
use equihash::verify_block_equihash_solution;
use network::ConsensusParams;
use work::is_valid_proof_of_work;
use error::Error;
use constants::BLOCK_MAX_FUTURE;

pub struct HeaderVerifier<'a> {
	pub version: HeaderVersion<'a>,
	pub equihash: HeaderEquihashSolution<'a>,
	pub proof_of_work: HeaderProofOfWork<'a>,
	pub timestamp: HeaderTimestamp<'a>,
}

impl<'a> HeaderVerifier<'a> {
	pub fn new(header: &'a IndexedBlockHeader, consensus: &'a ConsensusParams, current_time: u32) -> Self {
		HeaderVerifier {
			version: HeaderVersion::new(header, consensus),
			proof_of_work: HeaderProofOfWork::new(header, consensus),
			equihash: HeaderEquihashSolution::new(header, consensus),
			timestamp: HeaderTimestamp::new(header, current_time, BLOCK_MAX_FUTURE as u32),
		}
	}

	pub fn check(&self) -> Result<(), Error> {
		self.version.check()?;
		self.equihash.check()?;
		self.proof_of_work.check()?;
		self.timestamp.check()?;
		Ok(())
	}
}

pub struct HeaderProofOfWork<'a> {
	header: &'a IndexedBlockHeader,
	max_work_bits: Compact,
}

impl<'a> HeaderProofOfWork<'a> {
	fn new(header: &'a IndexedBlockHeader, consensus: &ConsensusParams) -> Self {
		HeaderProofOfWork {
			header: header,
			max_work_bits: consensus.network.max_bits().into(),
		}
	}

	fn check(&self) -> Result<(), Error> {
		if is_valid_proof_of_work(self.max_work_bits, self.header.raw.bits, &self.header.hash) {
			Ok(())
		} else {
			Err(Error::Pow)
		}
	}
}

pub struct HeaderTimestamp<'a> {
	header: &'a IndexedBlockHeader,
	current_time: u32,
	max_future: u32,
}

impl<'a> HeaderTimestamp<'a> {
	fn new(header: &'a IndexedBlockHeader, current_time: u32, max_future: u32) -> Self {
		HeaderTimestamp {
			header: header,
			current_time: current_time,
			max_future: max_future,
		}
	}

	fn check(&self) -> Result<(), Error> {
		if self.header.raw.time > self.current_time + self.max_future {
			Err(Error::FuturisticTimestamp)
		} else {
			Ok(())
		}
	}
}

pub struct HeaderVersion<'a> {
	header: &'a IndexedBlockHeader,
	min_version: u32,
}

impl<'a> HeaderVersion<'a> {
	fn new(header: &'a IndexedBlockHeader, consensus: &'a ConsensusParams) -> Self {
		HeaderVersion {
			header,
			min_version: consensus.min_block_version(),
		}
	}

	fn check(&self) -> Result<(), Error> {
		if self.header.raw.version < self.min_version {
			return Err(Error::InvalidVersion);
		}

		Ok(())
	}
}

pub struct HeaderEquihashSolution<'a> {
	header: &'a IndexedBlockHeader,
	equihash_params: Option<(u32, u32)>,
}

impl<'a> HeaderEquihashSolution<'a> {
	fn new(header: &'a IndexedBlockHeader, consensus: &'a ConsensusParams) -> Self {
		HeaderEquihashSolution {
			header,
			equihash_params: consensus.equihash_params,
		}
	}

	fn check(&self) -> Result<(), Error> {
		if let Some(equihash_params) = self.equihash_params {
			if !verify_block_equihash_solution(equihash_params, &self.header.raw) {
				return Err(Error::InvalidEquihashSolution);
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	extern crate test_data;

	use network::{Network, ConsensusParams};
	use error::Error;
	use super::HeaderVersion;

	#[test]
	fn header_version_works() {
		let consensus = ConsensusParams::new(Network::Mainnet);

		assert_eq!(HeaderVersion::new(&test_data::block_builder().header().version(consensus.min_block_version() - 1)
			.build().build().block_header.into(), &consensus).check(), Err(Error::InvalidVersion));
		assert_eq!(HeaderVersion::new(&test_data::block_builder().header().version(consensus.min_block_version())
			.build().build().block_header.into(), &consensus).check(), Ok(()));
		assert_eq!(HeaderVersion::new(&test_data::block_builder().header().version(consensus.min_block_version() + 1)
			.build().build().block_header.into(), &consensus).check(), Ok(()));
	}
}
