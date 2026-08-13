//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BMW-512 (Blue Midnight Wish) hash function.

#[doc(hidden)]
pub mod consts;
#[doc(hidden)]
pub mod scalar;
#[cfg(feature = "simd")]
#[doc(hidden)]
pub mod simd;

#[cfg(not(feature = "simd"))]
pub use scalar::hash512;
#[cfg(feature = "simd")]
pub use simd::hash512;
