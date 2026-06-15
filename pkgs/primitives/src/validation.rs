//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared validation constants.

/// Maximum serialized transaction size (single tx, always 1 MB).
#[expect(unused, reason = "consensus constant")]
pub(crate) const MAX_LEGACY_BLOCK_SIZE: usize = 1_000_000;

/// Post-DIP0001 maximum block size (2 MB).
pub(crate) const MAX_DIP0001_BLOCK_SIZE: usize = 2_000_000;

/// Maximum extra payload size in bytes.
pub(crate) const MAX_TX_EXTRA_PAYLOAD: usize = 10_000;

/// Number of version bits available for signalling.
pub(crate) const VERSIONBITS_NUM_BITS: u8 = 29;

/// Maximum coinbase script size in bytes.
pub(crate) const MAX_COINBASE_SCRIPT_SIZE: usize = 100;
