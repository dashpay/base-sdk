//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold participant identifier.

use dash_num::make_hash;
use dash_types::Numeric;

make_hash! {
  /// Threshold participant identifier.
  ///
  /// Stored in the order the curve reads and shown in the order the reference
  /// implementation prints, which are opposite ends of the same 32 bytes.
  ///
  /// The id is a masternode's `proTxHash`, held there as a `uint256` whose
  /// `GetHex` reverses, so every RPC and log quotes the reverse of the bytes
  /// it stores.
  ///
  /// Those stored bytes are what the curve gets, unreversed. `Threshold`
  /// reads them through relic's `bn_read_bin`, which is big-endian, so the
  /// scalar is the stored order read as an integer.
  ///
  /// One id therefore has two spellings there and they are byte reverses.
  /// `CBLSId` wraps the same `uint256` but inherits a plain `HexStr`, so it
  /// prints the stored order; nothing a user sees does.
  ///
  /// So `as_bytes` holds the curve's order while `Display` gives the quoted
  /// order, and the scalar must be reduced from `as_bytes()`, never from
  /// `to_bendian()`, since the displayed order names a different participant.
  BlsShareId, 32
}

/// Threshold participant identifier length.
pub const BLS_ID_LEN: usize = <BlsShareId as Numeric>::LEN;
