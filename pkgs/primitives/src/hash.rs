//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Hashing utilities for Dash consensus.

use bitcoin_hashes::sha256d;
use dash_num::Hash256;

/// Computes the SHA256d hash of the input data.
///
/// This is the standard hash used for transaction identifiers and merkle tree
/// construction in Bitcoin/Dash.
pub fn double_sha256(data: &[u8]) -> Hash256 {
  Hash256::from_bytes(sha256d::Hash::hash(data).to_byte_array())
}

/// Computes the transaction hash (SHA256d of the raw serialized
/// transaction).
pub fn tx_hash(raw_tx: &[u8]) -> crate::TxHash {
  crate::TxHash::from_bytes(sha256d::Hash::hash(raw_tx).to_byte_array())
}
