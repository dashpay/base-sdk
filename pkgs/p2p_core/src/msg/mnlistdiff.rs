//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Masternode list diff messages: getmnlistd, mnlistdiff.

use crate::codec::codec_p2p;
use crate::primitives::MnListDiffPayload;

use dash_primitives::BlockHash;

/// Requests a masternode list diff between two blocks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetMnListDiff {
  /// Base block hash (beginning of range).
  pub base_block_hash: BlockHash,
  /// Target block hash (end of range).
  pub block_hash: BlockHash,
}

codec_p2p!(GetMnListDiff {
  base_block_hash,
  block_hash
});

/// Response carrying the masternode list diff.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MnListDiff {
  /// The full diff payload.
  pub payload: MnListDiffPayload,
}

codec_p2p!(MnListDiff { payload });
