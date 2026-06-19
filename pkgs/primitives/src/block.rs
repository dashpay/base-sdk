//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash block (header + transactions).

use crate::block_header::BlockHeader;
use crate::codec_type;
use crate::prelude::*;
use crate::transaction::{Transaction, TxInvalid};

use dash_types::codec::Checkable;

use core::fmt;

/// Maximum serialized transaction size (single tx, always 1 MB).
pub const MAX_LEGACY_BLOCK_SIZE: usize = 1_000_000;

/// Post-DIP0001 maximum block size (2 MB).
pub const MAX_DIP0001_BLOCK_SIZE: usize = 2_000_000;

/// A Dash block: header followed by a vector of transactions.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Block {
  /// Block header (80 bytes).
  pub header: BlockHeader,
  /// Transactions in the block.
  pub transactions: Vec<Transaction>,
}

codec_type!(Block { header, transactions });

impl Checkable for Block {
  type Error = BlockInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.transactions.is_empty() {
      return Some(BlockInvalid::BadBlockLength { size: 0 });
    }

    if !self.transactions[0].is_coinbase() {
      return Some(BlockInvalid::MissingCoinbase);
    }
    for i in 1..self.transactions.len() {
      if self.transactions[i].is_coinbase() {
        return Some(BlockInvalid::MultipleCoinbases { index: i });
      }
    }

    for (i, tx) in self.transactions.iter().enumerate() {
      if let Some(e) = tx.check() {
        return Some(BlockInvalid::Transaction { index: i, error: e });
      }
    }

    let max_sigops = MAX_DIP0001_BLOCK_SIZE / 50;
    let mut total_sigops: usize = 0;
    for tx in &self.transactions {
      for input in &tx.inputs {
        total_sigops += dash_script::legacy_sigop_count(input.script_sig.as_bytes());
      }
      for output in &tx.outputs {
        total_sigops += dash_script::legacy_sigop_count(output.script_pubkey.as_bytes());
      }
    }
    if total_sigops > max_sigops {
      return Some(BlockInvalid::TooManySigops {
        count: total_sigops,
        limit: max_sigops,
      });
    }

    None
  }
}

impl fmt::Display for Block {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Block {{ txs: {} }}", self.transactions.len())
  }
}

/// Block validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BlockInvalid {
  /// `bad-blk-length`
  BadBlockLength { size: usize },
  /// `bad-cb-missing`
  MissingCoinbase,
  /// `bad-cb-multiple`
  MultipleCoinbases { index: usize },
  /// `bad-blk-sigops`
  TooManySigops { count: usize, limit: usize },
  /// A contained transaction failed validation.
  Transaction { index: usize, error: TxInvalid },
}

impl fmt::Display for BlockInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::BadBlockLength { size } => write!(f, "bad-blk-length: {size} bytes"),
      Self::MissingCoinbase => write!(f, "bad-cb-missing"),
      Self::MultipleCoinbases { index } => write!(f, "bad-cb-multiple: tx {index}"),
      Self::TooManySigops { count, limit } => write!(f, "bad-blk-sigops: {count} > {limit}"),
      Self::Transaction { index, error } => write!(f, "tx {index}: {error}"),
    }
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::panic, clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, load_corpus_file, read_corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_block() {
    let text = load_corpus_file(env!("CARGO_MANIFEST_DIR"), "blocks");
    let items = read_corpus::<Block>(&text, "blocks", |raw, details, label| {
      check_wire(raw, details, label);
      if let Some(e) = details.check() {
        panic!("{label}: check: {e}");
      }
      let pow_hash = crate::BlockHash::from(dash_pow::hash(&raw[..80]));
      let expected = crate::BlockHash::from_hex(label).unwrap();
      assert_eq!(pow_hash, expected, "{label}: pow hash");
    });
    assert_serde_rt("blocks", &items);
  }
}
