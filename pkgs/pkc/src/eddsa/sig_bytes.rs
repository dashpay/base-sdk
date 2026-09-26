//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Ed25519 signature byte bag.

use dash_types::make_bytes;

/// Raw Ed25519 signature length.
pub const EDDSA_SIG_LEN: usize = 64;

make_bytes! {
  /// Ed25519 signature bytes (64 bytes, unvalidated).
  EddsaSigBytes, EDDSA_SIG_LEN, fwd, nocodec
}
