//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Ed25519 types for the edwards25519 curve.

mod error;
mod public_bytes;
mod public_hash;
mod secret_bytes;
mod sig_bytes;

pub use error::EddsaError;
pub use public_bytes::{EddsaPkBytes, EDDSA_PK_LEN};
pub use public_hash::EddsaPkHash;
pub use secret_bytes::{EddsaSkBytes, EDDSA_SK_LEN};
pub use sig_bytes::{EddsaSigBytes, EDDSA_SIG_LEN};

cfg_if::cfg_if! {
  if #[cfg(feature = "eddsa")] {
    mod public_ops;
    mod secret_ops;
    mod sig_ops;
    #[cfg(test)]
    #[expect(clippy::unwrap_used, reason = "test code")]
    #[allow(dead_code, reason = "usage dependent on build flags")]
    pub(crate) mod tests;

    pub use public_ops::EddsaPublicKey;
    pub use secret_ops::EddsaSecretKey;
    pub use sig_ops::EddsaSignature;
  }
}
