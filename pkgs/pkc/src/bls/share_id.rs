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
  BlsShareId, 32
}

/// Threshold participant identifier length.
pub const BLS_ID_LEN: usize = <BlsShareId as Numeric>::LEN;
