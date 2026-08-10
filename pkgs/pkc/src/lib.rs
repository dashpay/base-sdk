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

pub mod bls;
pub mod ecdsa;
#[cfg(feature = "std")]
pub mod worker;

#[doc(hidden)]
pub mod __private {
  pub use crate::ecdsa::PubKeyHash as __PubKeyHash;
}

cfg_if::cfg_if! {
  if #[cfg(feature = "bls")] {
    pub mod bls_chia;
    pub mod bls_ietf;
  }
}
