//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Public-key cryptography for Dash.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;

#[cfg(feature = "k256")]
pub mod k256;
#[cfg(feature = "std")]
pub mod worker;

cfg_if::cfg_if! {
  if #[cfg(feature = "bls")] {
    mod common;

    pub mod bls_chia;
    pub mod bls_ietf;
  }
}

dash_types::make_bytes! {
  /// Raw BLS public key bytes (48 bytes, unvalidated).
  BlsPublicKeyBytes, 48
}

dash_types::make_bytes! {
  /// Raw BLS signature bytes (96 bytes, unvalidated).
  BlsSignatureBytes, 96
}

dash_types::make_bytes! {
  /// Raw compressed ECDSA public key bytes (33 bytes, unvalidated).
  EcdsaPublicKeyBytes, 33
}

dash_types::make_bytes! {
  /// Raw compact ECDSA signature bytes (64 bytes, unvalidated).
  EcdsaSignatureBytes, 64
}
