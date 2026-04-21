//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Blake-512 hash function.
//!
//! Blake is a Merkle-Damgard construction using a ChaCha-derived G mixing
//! function. It operates on 128-byte blocks with 16 rounds per block, producing
//! a 512-bit digest. The message length is tracked by a 128-bit counter and
//! encoded in the padding as big-endian.

pub mod consts;
pub_if_internal! { mod scalar; }
#[cfg(feature = "simd")]
pub_if_internal! { mod simd; }

cfg_if::cfg_if! {
  if #[cfg(feature = "simd")] {
    pub use simd::hash512;
  } else {
    pub use scalar::hash512;
  }
}
