use rayon::prelude::{IntoParallelRefIterator, IndexedParallelIterator, ParallelIterator};
use chain::IndexedBlock;
use network::ConsensusParams;
use error::Error;
use verify_block::BlockVerifier;
use verify_header::HeaderVerifier;
use verify_transaction::TransactionVerifier;
use VerificationLevel;

pub struct ChainVerifier<'a> {
	pub block: BlockVerifier<'a>,
	pub header: Option<HeaderVerifier<'a>>,
	pub transactions: Vec<TransactionVerifier<'a>>,
}

impl<'a> ChainVerifier<'a> {
	pub fn new(
		block: &'a IndexedBlock,
		consensus: &'a ConsensusParams,
		current_time: u32,
		verification_level: VerificationLevel,
	) -> Self {
		trace!(target: "verification", "Block pre-verification {}", block.hash().to_reversed_str());
		ChainVerifier {
			block: BlockVerifier::new(block, consensus),
			header: if !verification_level.intersects(VerificationLevel::HINT_HEADER_PRE_VERIFIED) {
				Some(HeaderVerifier::new(&block.header, consensus, current_time))
			} else {
				None
			},
			transactions: block.transactions.iter().map(|tx| TransactionVerifier::new(tx, consensus)).collect(),
		}
	}

	pub fn check(&self) -> Result<(), Error> {
		self.block.check()?;
		if let Some(ref header) = self.header {
			header.check()?;
		}
		self.check_transactions()?;
		Ok(())
	}

	fn check_transactions(&self) -> Result<(), Error> {
		self.transactions.par_iter()
			.enumerate()
			.fold(|| Ok(()), |result, (index, tx)| result.and_then(|_| tx.check().map_err(|err| Error::Transaction(index, err))))
			.reduce(|| Ok(()), |acc, check| acc.and(check))
	}
}
