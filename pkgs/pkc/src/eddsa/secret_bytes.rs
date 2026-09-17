//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Ed25519 secret key byte bag.

use dash_types::make_sbytes;

/// Raw Ed25519 secret key (seed) length.
pub const EDDSA_SK_LEN: usize = 32;

make_sbytes! {
  /// Ed25519 secret key seed (32 bytes).
  EddsaSkBytes, EDDSA_SK_LEN, nocodec
}
