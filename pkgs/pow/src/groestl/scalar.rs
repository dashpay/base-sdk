//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar Groestl-512 implementation.

use super::consts::{BLOCK, IV, ROUNDS, T0, T4};
use crate::util::memops::{extract, load_u64_le, store_u64_le};

use dash_num::Hash512;

// Byte extraction from u64 (LE convention).
#[inline]
const fn b0(x: u64) -> usize {
  (x & 0xFF) as usize
}
#[inline]
const fn b1(x: u64) -> usize {
  ((x >> 8) & 0xFF) as usize
}
#[inline]
const fn b2(x: u64) -> usize {
  ((x >> 16) & 0xFF) as usize
}
#[inline]
const fn b3(x: u64) -> usize {
  ((x >> 24) & 0xFF) as usize
}
#[inline]
const fn b4(x: u64) -> usize {
  ((x >> 32) & 0xFF) as usize
}
#[inline]
const fn b5(x: u64) -> usize {
  ((x >> 40) & 0xFF) as usize
}
#[inline]
const fn b6(x: u64) -> usize {
  ((x >> 48) & 0xFF) as usize
}
#[inline]
const fn b7(x: u64) -> usize {
  (x >> 56) as usize
}

/// RSTT: fused SubBytes + ShiftBytes + MixBytes via T-table lookup.
///
/// `idx` selects the 8 input word indices (ShiftBytes permutation). Uses T0 and
/// T4 with ROTL for T1-T3 and T5-T7.
#[inline]
const fn rstt(a: &[u64; 16], idx: [usize; 8]) -> u64 {
  T0[b0(a[idx[0]])]
    ^ T0[b1(a[idx[1]])].rotate_left(8)
    ^ T0[b2(a[idx[2]])].rotate_left(16)
    ^ T0[b3(a[idx[3]])].rotate_left(24)
    ^ T4[b4(a[idx[4]])]
    ^ T4[b5(a[idx[5]])].rotate_left(8)
    ^ T4[b6(a[idx[6]])].rotate_left(16)
    ^ T4[b7(a[idx[7]])].rotate_left(24)
}

/// P round constant (LE): XOR into byte 0 of each word.
#[inline]
const fn pc64(j: u64, r: u64) -> u64 {
  j.wrapping_add(r)
}

/// Q round constant (LE).
#[inline]
const fn qc64(j: u64, r: u64) -> u64 {
  (r << 56) ^ !(j << 56)
}

/// P permutation round.
const fn round_p(a: &mut [u64; 16], r: u64) {
  // AddRoundConstant.
  let mut j = 0;
  while j < 16 {
    a[j] ^= pc64((j as u64) * 0x10, r);
    j += 1;
  }

  // SubBytes + ShiftBytes + MixBytes.
  // P shift: (d, d+1, d+2, d+3, d+4, d+5, d+6, d+11) mod 16.
  let mut t = [0u64; 16];
  let mut d = 0;
  while d < 16 {
    #[rustfmt::skip]
    let idx = [d & 0xF, (d+1) & 0xF, (d+2) & 0xF, (d+3) & 0xF, (d+4) & 0xF, (d+5) & 0xF, (d+6) & 0xF, (d+11) & 0xF];
    t[d] = rstt(a, idx);
    d += 1;
  }
  *a = t;
}

/// Q permutation round.
const fn round_q(a: &mut [u64; 16], r: u64) {
  // AddRoundConstant.
  let mut j = 0;
  while j < 16 {
    a[j] ^= qc64((j as u64) * 0x10, r);
    j += 1;
  }

  // SubBytes + ShiftBytes + MixBytes.
  // Q shift: (d+1, d+3, d+5, d+11, d, d+2, d+4, d+6) mod 16.
  let mut t = [0u64; 16];
  let mut d = 0;
  while d < 16 {
    #[rustfmt::skip]
    let idx = [(d+1) & 0xF, (d+3) & 0xF, (d+5) & 0xF, (d+11) & 0xF, d & 0xF, (d+2) & 0xF, (d+4) & 0xF, (d+6) & 0xF];
    t[d] = rstt(a, idx);
    d += 1;
  }
  *a = t;
}

/// 14-round P permutation.
pub const fn perm_p(a: &mut [u64; 16]) {
  let mut r = 0;
  while r < ROUNDS {
    round_p(a, r as u64);
    r += 1;
  }
}

/// 14-round Q permutation.
pub const fn perm_q(a: &mut [u64; 16]) {
  let mut r = 0;
  while r < ROUNDS {
    round_q(a, r as u64);
    r += 1;
  }
}

/// Groestl-512 compression: H = H ^ P(H ^ M) ^ Q(M).
pub const fn compress(h: &mut [u64; 16], buf: &[u8]) {
  let mut g = [0u64; 16];
  let mut m = [0u64; 16];

  let mut u = 0;
  while u < 16 {
    m[u] = load_u64_le(buf, u);
    g[u] = m[u] ^ h[u];
    u += 1;
  }

  perm_p(&mut g);
  perm_q(&mut m);

  u = 0;
  while u < 16 {
    h[u] ^= g[u] ^ m[u];
    u += 1;
  }
}

/// Output transformation: H = H ^ P(H), then take H[8..15].
pub const fn output_transform(h: &mut [u64; 16]) {
  let mut x = *h;
  perm_p(&mut x);
  let mut u = 0;
  while u < 16 {
    h[u] ^= x[u];
    u += 1;
  }
}

pub const fn hash512(data: &[u8]) -> Hash512 {
  let mut h = IV;
  let mut count = 0u64;

  let mut pos = 0;
  while pos + BLOCK <= data.len() {
    compress(&mut h, &extract::<BLOCK>(data, pos));
    count = count.wrapping_add(1);
    pos += BLOCK;
  }

  let ptr = data.len() - pos;
  let mut pad = [0u8; 256];
  let mut pi = 0;
  while pi < ptr {
    pad[pi] = data[pos + pi];
    pi += 1;
  }
  pad[ptr] = 0x80;

  let pad_len;
  if ptr < 120 {
    pad_len = BLOCK;
    count = count.wrapping_add(1);
  } else {
    pad_len = 2 * BLOCK;
    count = count.wrapping_add(2);
  }

  // Encode block count as 64-bit BE at end of padding.
  let cb = count.to_be_bytes();
  let mut ci = 0;
  while ci < 8 {
    pad[pad_len - 8 + ci] = cb[ci];
    ci += 1;
  }

  // Process padding blocks.
  let mut p = 0;
  while p < pad_len {
    compress(&mut h, &extract::<BLOCK>(&pad, p));
    p += BLOCK;
  }

  // Output transform.
  output_transform(&mut h);

  // Extract H[8..15] as LE bytes.
  let mut out = [0u8; 64];
  let mut i = 0;
  while i < 8 {
    store_u64_le(&mut out, i, h[i + 8]);
    i += 1;
  }
  Hash512::from_bytes(out)
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Proves hash512 evaluates at compile time.
  const _: Hash512 = hash512(b"");
}
