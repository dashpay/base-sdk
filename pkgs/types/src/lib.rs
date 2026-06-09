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

mod entity;
mod hex;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod uint;

pub mod codec;
#[cfg(feature = "serde")]
pub mod serialize;

pub use entity::{BufferDecoder, VecEncoder, MAX_SER_SIZE};

#[doc(hidden)]
pub mod __private {
  pub use bitcoin_consensus_encoding;
  #[cfg(feature = "serde")]
  pub use hex_conservative;
}

make_bytes! {
  /// ADDRv1 IPv4-mapped IPv6 address (16 bytes).
  AddrV1, 16
}

make_bytes! {
  /// Raw BLS public key bytes (48 bytes, unvalidated).
  BlsPublicKeyBytes, 48
}

make_bytes! {
  /// Raw BLS signature bytes (96 bytes, unvalidated).
  BlsSignatureBytes, 96
}

make_bytes! {
  /// Raw compressed ECDSA public key bytes (33 bytes, unvalidated).
  EcdsaPublicKeyBytes, 33
}

make_bytes! {
  /// Raw compact ECDSA signature bytes (64 bytes, unvalidated).
  EcdsaSignatureBytes, 64
}

make_bytes! {
  /// 20-byte public key hash (RIPEMD-160 of SHA-256).
  KeyId, 20
}

make_bytes! {
  /// Platform node identifier for Evo masternodes.
  PlatformNodeId, 20
}
