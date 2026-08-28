//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared types and macros for the Dash SDK.

#![no_std]

extern crate alloc;
extern crate self as dash_types;
#[cfg(feature = "std")]
extern crate std;

#[allow(unused_macros, reason = "used by feature-gated submodules")]
#[cfg(feature = "codec")]
mod adapters;
#[cfg(feature = "codec")]
mod entity;
mod macros;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
#[cfg(feature = "codec")]
mod secret;
#[cfg(feature = "codec")]
mod uint;

#[cfg(feature = "serde")]
pub mod serialize;

pub use macros::qtypestr;

cfg_if::cfg_if! {
  if #[cfg(feature = "codec")] {
    mod compact;

    pub mod codec;
    pub mod type_id;

    pub use compact::CompactSize;
    pub use entity::{VecDecoder, VecEncoder, MAX_SER_SIZE};
    pub use secret::{ArrDecoder, ArrEncoder, ArrayBuf, MAX_ARR_SIZE};
  }
}

#[doc(hidden)]
pub mod __private {
  #[cfg(feature = "bitcoin-primitives")]
  pub use crate::adapters::bitcoin_primitives::ScriptHash as __ScriptHash;

  #[cfg(feature = "codec")]
  pub use bitcoin_consensus_encoding;
  #[cfg(feature = "serde")]
  pub use hex_conservative;
  #[cfg(feature = "serde")]
  pub use serde;
  pub use subtle;
  pub use zeroize;
}
