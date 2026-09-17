//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Ed25519 types for the edwards25519 curve.

mod error;
mod public_bytes;
mod public_hash;

pub use error::EddsaError;
pub use public_bytes::{EddsaPkBytes, EDDSA_PK_LEN};
pub use public_hash::EddsaPkHash;

cfg_if::cfg_if! {
  if #[cfg(feature = "eddsa")] {
    mod public_ops;

    #[cfg(any(test, feature = "tests"))]
    #[expect(clippy::unwrap_used, reason = "test code")]
    #[allow(dead_code, reason = "usage dependent on build flags")]
    pub mod tests;

    pub use public_ops::EddsaPublicKey;
  }
}
