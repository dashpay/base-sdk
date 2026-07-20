//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AES round via x86_64 AES-NI instructions.
//!
//! Requires AES-NI + SSE2 (`aes` and `sse2` target features). _mm_aesenc_si128
//! performs the full AES encryption round (SubBytes + ShiftRows + MixColumns +
//! AddRoundKey) in a single instruction.

use core::arch::x86_64::{
  __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_set_epi32, _mm_setzero_si128, _mm_shuffle_epi8,
};

#[inline]
fn to_m128i(v: &[u32; 4]) -> __m128i {
  // SAFETY: _mm_set_epi32 is always safe with sse2.
  unsafe { _mm_set_epi32(v[3] as i32, v[2] as i32, v[1] as i32, v[0] as i32) }
}

#[inline]
fn from_m128i(v: __m128i) -> [u32; 4] {
  let mut out = [0u32; 4];
  // SAFETY: __m128i and [u32; 4] are both 16 bytes on LE.
  unsafe {
    core::ptr::copy_nonoverlapping(&v as *const __m128i as *const u8, out.as_mut_ptr() as *mut u8, 16);
  }
  out
}

#[inline]
#[target_feature(enable = "aes,sse2")]
unsafe fn round_impl(state: &[u32; 4], key: &[u32; 4]) -> [u32; 4] {
  let s = to_m128i(state);
  let k = to_m128i(key);
  from_m128i(_mm_aesenc_si128(s, k))
}

/// AES encryption round
#[inline]
pub(crate) fn round(state: &[u32; 4], key: &[u32; 4]) -> [u32; 4] {
  // Safety: this module is only compiled with `aes_hw` + `x86_64`.
  unsafe { round_impl(state, key) }
}

#[inline]
#[target_feature(enable = "aes,sse2")]
unsafe fn round_nk_impl(state: &[u32; 4]) -> [u32; 4] {
  let s = to_m128i(state);
  from_m128i(_mm_aesenc_si128(s, _mm_setzero_si128()))
}

/// AES round without AddRoundKey (key = 0).
#[inline]
pub(crate) fn round_nk(state: &[u32; 4]) -> [u32; 4] {
  // Safety: this module is only compiled with `aes_hw` + `x86_64`.
  unsafe { round_nk_impl(state) }
}

/// Inverse AES ShiftRows shuffle for _mm_shuffle_epi8.
#[cfg(test)]
const INV_SHIFT_ROWS: [u8; 16] = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];

/// Applies the AES S-box to all 16 bytes independently.
///
/// Uses aesenclast (SubBytes + ShiftRows + XOR key, no
/// MixColumns) with zero key, then undoes AES ShiftRows
/// via pshufb. Used by Groestl.
#[cfg(test)]
#[inline]
#[target_feature(enable = "aes,sse2,ssse3")]
unsafe fn sub_bytes_impl(state: &[u8; 16]) -> [u8; 16] {
  let s: __m128i = core::mem::transmute::<[u8; 16], __m128i>(*state);
  let zero = _mm_setzero_si128();
  let tbl: __m128i = core::mem::transmute::<[u8; 16], __m128i>(INV_SHIFT_ROWS);
  let after = _mm_aesenclast_si128(s, zero);
  core::mem::transmute::<__m128i, [u8; 16]>(_mm_shuffle_epi8(after, tbl))
}

#[cfg(test)]
#[inline]
pub(crate) fn sub_bytes(state: &[u8; 16]) -> [u8; 16] {
  // Safety: this module is only compiled with `aes_hw` + `x86_64`.
  unsafe { sub_bytes_impl(state) }
}
