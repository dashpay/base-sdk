//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ECDSA types for the secp256k1 curve.

mod error;
mod public_bytes;
mod secret_bytes;
mod sig_bytes;

use dash_types::Unencodable;

pub use error::EcdsaError;
pub use public_bytes::EcdsaPkBytes;
pub use secret_bytes::EcdsaSkBytes;
pub use sig_bytes::EcdsaSigBytes;

/// Whether a key's public counterpart serializes in compressed (33-byte) or
/// uncompressed (65-byte) SEC1 form.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub enum Compression {
  /// The public key serializes compressed.
  Compressed,
  /// The public key serializes uncompressed.
  Uncompressed,
}

impl Compression {
  /// Whether this is the compressed form.
  pub const fn is_compressed(self) -> bool {
    matches!(self, Self::Compressed)
  }
}

impl From<bool> for Compression {
  fn from(compressed: bool) -> Self {
    if compressed {
      Self::Compressed
    } else {
      Self::Uncompressed
    }
  }
}

cfg_if::cfg_if! {
  if #[cfg(feature = "ecdsa")] {
    mod public_ops;
    mod secret_ops;
    mod sig_ops;
    mod sig_rec_ops;

    #[cfg(any(test, feature = "tests"))]
    #[expect(clippy::unwrap_used, reason = "test code")]
    #[allow(dead_code, reason = "usage dependent on build flags")]
    pub mod tests;

    pub use public_ops::EcdsaPublicKey;
    pub use secret_ops::EcdsaSecretKey;
    pub use sig_ops::{EcdsaDerSignature, EcdsaSignature};
    pub use sig_rec_ops::EcdsaRecSignature;
  }
}
