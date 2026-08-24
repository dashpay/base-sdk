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

#[cfg(feature = "bls")]
mod aes_cbc;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;

pub mod bls;

cfg_if::cfg_if! {
  if #[cfg(feature = "codec")] {
    pub mod ecdsa;

    #[doc(hidden)]
    pub mod __private {
      pub use crate::ecdsa::PubKeyHash as __PubKeyHash;
    }
  }
}
