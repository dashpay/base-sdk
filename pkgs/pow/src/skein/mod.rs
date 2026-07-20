//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Skein-512 hash function.

#[doc(hidden)]
pub mod consts;
#[doc(hidden)]
pub mod scalar;
#[cfg(feature = "simd")]
#[doc(hidden)]
pub mod simd;

cfg_if::cfg_if! {
  if #[cfg(feature = "simd")] {
    pub use simd::hash512;
  } else {
    pub use scalar::hash512;
  }
}
