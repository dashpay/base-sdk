//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared helpers for ARX-style permutations.

/// Rotate a `u32` word left by `shift` bits.
#[expect(dead_code, reason = "used by cubehash consts IV generation")]
#[inline]
pub(crate) const fn rotl_u32(word: u32, shift: u32) -> u32 {
  word.rotate_left(shift)
}

/// Rotate each lane of a `Simd<u32, 4>` value left by `shift` bits.
#[cfg(feature = "simd")]
#[inline]
pub(crate) fn rotl_u32x4(words: core::simd::Simd<u32, 4>, shift: u32) -> core::simd::Simd<u32, 4> {
  if shift == 0 {
    return words;
  }
  let left = words << core::simd::Simd::splat(shift);
  let right = words >> core::simd::Simd::splat(32 - shift);
  left | right
}
