//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared types and macros for the Dash SDK.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod hex;

#[doc(hidden)]
pub mod __private {
  pub use crate::hex::{ByteTypeDecoder, ByteTypeDecoderError};
  pub use bitcoin_consensus_encoding;
}

make_bytes! {
  /// Platform node identifier for Evo masternodes.
  PlatformNodeId, 20
}

make_bytes! {
  /// Raw BLS public key bytes (48 bytes, unvalidated).
  BlsPublicKeyBytes, 48
}

make_bytes! {
  /// Raw BLS signature bytes (96 bytes, unvalidated).
  BlsSignatureBytes, 96
}
