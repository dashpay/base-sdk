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
mod adapters;
mod entity;
mod hex;
mod macros;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod secret;
mod uint;

pub mod codec;
#[cfg(feature = "serde")]
pub mod serialize;

pub use dash_types_marker::{TypeId, Unencodable};
pub use entity::{VecDecoder, VecEncoder, MAX_SER_SIZE};
pub use secret::{ArrDecoder, ArrEncoder, ArrayBuf, MAX_ARR_SIZE};

#[doc(hidden)]
pub mod __private {
  #[cfg(feature = "bitcoin-primitives")]
  pub use crate::adapters::bitcoin_primitives::ScriptHash as __ScriptHash;

  pub use bitcoin_consensus_encoding;
  #[cfg(feature = "serde")]
  pub use hex_conservative;
}
