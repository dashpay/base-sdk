//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Masternode list diff messages: getmnlistd, mnlistdiff.

use crate::codec::impl_p2p;
use crate::prelude::*;
use crate::primitives::mn_list::MnListDiffPayload;

use dash_primitives::BlockHash;
use dash_types::codec::{BaseCodec, DecodeError};

/// Requests a masternode list diff between two blocks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetMnListDiff {
  /// Base block hash (beginning of range).
  pub base_block_hash: BlockHash,
  /// Target block hash (end of range).
  pub block_hash: BlockHash,
}

impl BaseCodec for GetMnListDiff {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      base_block_hash: BlockHash::decode(data)?,
      block_hash: BlockHash::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.base_block_hash.encode(buf);
    self.block_hash.encode(buf);
  }
}

impl_p2p!(GetMnListDiff);

/// Response carrying the masternode list diff.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MnListDiff {
  /// The full diff payload.
  pub payload: MnListDiffPayload,
}

impl BaseCodec for MnListDiff {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    MnListDiffPayload::decode(data).map(|payload| Self { payload })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.payload.encode(buf);
  }
}

impl_p2p!(MnListDiff);
