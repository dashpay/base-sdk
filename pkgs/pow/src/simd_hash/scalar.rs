//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar SIMD-512 implementation.

use super::consts::{ALPHA_TAB, BLOCK, IV, PP8K, YOFF_B_F, YOFF_B_N};
use crate::util::memops::{extract, load_u32_le, store_u32_le};

use dash_num::Hash512;

// Modular reductions for Z/257Z arithmetic.
const fn reds1(x: i32) -> i32 {
  (x & 0xFF) - (x >> 8)
}
const fn reds2(x: i32) -> i32 {
  (x & 0xFFFF) + (x >> 16)
}

/// 8-point FFT butterfly.
const fn fft8(x: &[u8], xb: usize, xs: usize, d: &mut [i32; 8]) {
  let x0 = x[xb] as i32;
  let x1 = x[xb + xs] as i32;
  let x2 = x[xb + 2 * xs] as i32;
  let x3 = x[xb + 3 * xs] as i32;
  let a0 = x0 + x2;
  let a1 = x0 + (x2 << 4);
  let a2 = x0 - x2;
  let a3 = x0 - (x2 << 4);
  let b0 = x1 + x3;
  let b1 = reds1((x1 << 2) + (x3 << 6));
  let b2 = (x1 << 4) - (x3 << 4);
  let b3 = reds1((x1 << 6) + (x3 << 2));
  d[0] = a0 + b0;
  d[1] = a1 + b1;
  d[2] = a2 + b2;
  d[3] = a3 + b3;
  d[4] = a0 - b0;
  d[5] = a1 - b1;
  d[6] = a2 - b2;
  d[7] = a3 - b3;
}

/// 16-point FFT: two FFT8 combined with alpha=2.
const fn fft16(x: &[u8], xb: usize, xs: usize, q: &mut [i32], rb: usize) {
  let mut d1 = [0i32; 8];
  let mut d2 = [0i32; 8];
  fft8(x, xb, xs << 1, &mut d1);
  fft8(x, xb + xs, xs << 1, &mut d2);
  let mut i = 0;
  while i < 8 {
    q[rb + i] = d1[i] + (d2[i] << i);
    q[rb + i + 8] = d1[i] - (d2[i] << i);
    i += 1;
  }
}

/// FFT_LOOP: butterfly with alpha_tab twiddle factors.
const fn fft_loop(q: &mut [i32], rb: usize, hk: usize, a_stride: usize) {
  let m = q[rb];
  let n = q[rb + hk];
  q[rb] = m + n;
  q[rb + hk] = m - n;

  let mut u;
  let mut v = a_stride;
  // The C code uses a computed goto to start at element 1.
  // We handle element 0 above, then loop from element 1.
  {
    let m = q[rb + 1];
    let n = q[rb + 1 + hk];
    let t = reds2(n * ALPHA_TAB[v]);
    q[rb + 1] = m + t;
    q[rb + 1 + hk] = m - t;
    let m = q[rb + 2];
    let n = q[rb + 2 + hk];
    let t = reds2(n * ALPHA_TAB[v + a_stride]);
    q[rb + 2] = m + t;
    q[rb + 2 + hk] = m - t;
    let m = q[rb + 3];
    let n = q[rb + 3 + hk];
    let t = reds2(n * ALPHA_TAB[v + 2 * a_stride]);
    q[rb + 3] = m + t;
    q[rb + 3 + hk] = m - t;
  }
  u = 4;
  v = 4 * a_stride;
  while u < hk {
    let mut j = 0;
    while j < 4 {
      let m = q[rb + u + j];
      let n = q[rb + u + j + hk];
      let t = reds2(n * ALPHA_TAB[v + j * a_stride]);
      q[rb + u + j] = m + t;
      q[rb + u + j + hk] = m - t;
      j += 1;
    }
    u += 4;
    v += 4 * a_stride;
  }
}

/// 32-point FFT.
const fn fft32(x: &[u8], xb: usize, xs: usize, q: &mut [i32], rb: usize) {
  let xd = xs << 1;
  fft16(x, xb, xd, q, rb);
  fft16(x, xb + xs, xd, q, rb + 16);
  fft_loop(q, rb, 16, 8);
}

/// 64-point FFT (function call for cache friendliness).
const fn fft64(x: &[u8], xb: usize, xs: usize, q: &mut [i32], rb: usize) {
  let xd = xs << 1;
  fft32(x, xb, xd, q, rb);
  fft32(x, xb + xs, xd, q, rb + 32);
  fft_loop(q, rb, 32, 4);
}

/// 256-point FFT for SIMD-512 message expansion.
const fn fft256(x: &[u8], q: &mut [i32]) {
  fft64(x, 0, 4, q, 0);
  fft64(x, 2, 4, q, 64);
  fft_loop(q, 0, 64, 2);
  fft64(x, 1, 4, q, 128);
  fft64(x, 3, 4, q, 192);
  fft_loop(q, 128, 64, 2);
  fft_loop(q, 0, 128, 1);
}

/// Reduce FFT output to [-128, 128] range with offset table.
const fn reduce_fft(q: &mut [i32], yoff: &[u16; 256]) {
  let mut i = 0;
  while i < 256 {
    let mut tq = q[i] + yoff[i] as i32;
    tq = reds2(tq);
    tq = reds1(tq);
    tq = reds1(tq);
    q[i] = if tq <= 128 { tq } else { tq - 257 };
    i += 1;
  }
}

/// Combine two FFT values into a u32 message word.
const fn inner(l: i32, h: i32, mm: i32) -> u32 {
  ((l.wrapping_mul(mm) as u32) & 0xFFFF).wrapping_add((h.wrapping_mul(mm) as u32) << 16)
}

/// Read 64 message words from FFT output for one round.
const fn wbread(q: &[i32], wbp: &[usize], sb: usize, o1: i32, o2: i32, mm: i32, w: &mut [u32; 64]) {
  let mut u = 0;
  while u < 64 {
    let v = wbp[(u >> 3) + sb];
    let mut j = 0;
    while j < 8 {
      let li = (v as i32) + 2 * (j as i32) + o1;
      let hi = (v as i32) + 2 * (j as i32) + o2;
      w[u + j] = inner(q[li as usize], q[hi as usize], mm);
      j += 1;
    }
    u += 8;
  }
}

// IF and MAJ boolean functions.
const fn simd_if(x: u32, y: u32, z: u32) -> u32 {
  ((y ^ z) & x) ^ z
}
const fn simd_maj(x: u32, y: u32, z: u32) -> u32 {
  (x & y) | ((x | y) & z)
}

/// STEP2_BIG: 8-parallel Feistel step.
///
/// `pp8b` is XORed with lane index n to select the pre-rotated A value.
/// `use_if`: true selects IF, false selects MAJ.
const fn step2_big(state: &mut [u32; 32], w: &[u32], w_off: usize, use_if: bool, r: u32, s: u32, pp8b: usize) {
  // Pre-rotate A values.
  let mut ta = [0u32; 8];
  let mut n = 0;
  while n < 8 {
    ta[n] = state[n].rotate_left(r);
    n += 1;
  }

  // 8 parallel STEP_ELT operations.
  n = 0;
  while n < 8 {
    let a = state[n]; // A_n
    let b = state[8 + n]; // B_n
    let c = state[16 + n]; // C_n
    let d = state[24 + n]; // D_n
    let f = if use_if { simd_if(a, b, c) } else { simd_maj(a, b, c) };
    let tt = d.wrapping_add(w[w_off + n]).wrapping_add(f);
    let new_a = tt.rotate_left(s).wrapping_add(ta[pp8b ^ n]);
    state[24 + n] = c; // D_n = C_n
    state[16 + n] = b; // C_n = B_n
    state[8 + n] = ta[n]; // B_n = tA_n
    state[n] = new_a; // A_n = new value
    n += 1;
  }
}

/// One full round: 8 STEP2_BIG operations (4 IF + 4 MAJ).
const fn one_round_big(state: &mut [u32; 32], w: &[u32; 64], isp: usize, p0: u32, p1: u32, p2: u32, p3: u32) {
  step2_big(state, w, 0, true, p0, p1, PP8K[isp]);
  step2_big(state, w, 8, true, p1, p2, PP8K[isp + 1]);
  step2_big(state, w, 16, true, p2, p3, PP8K[isp + 2]);
  step2_big(state, w, 24, true, p3, p0, PP8K[isp + 3]);
  step2_big(state, w, 32, false, p0, p1, PP8K[isp + 4]);
  step2_big(state, w, 40, false, p1, p2, PP8K[isp + 5]);
  step2_big(state, w, 48, false, p2, p3, PP8K[isp + 6]);
  step2_big(state, w, 56, false, p3, p0, PP8K[isp + 7]);
}

/// SIMD-512 compression function.
pub const fn compress(h: &mut [u32; 32], buf: &[u8], last: bool) {
  let mut q = [0i32; 256];
  fft256(buf, &mut q);

  if last {
    reduce_fft(&mut q, &YOFF_B_F);
  } else {
    reduce_fft(&mut q, &YOFF_B_N);
  }

  // XOR message into state.
  let mut state = [0u32; 32];
  let mut i = 0;
  while i < 32 {
    state[i] = h[i] ^ load_u32_le(buf, i);
    i += 1;
  }

  // Word base permutation for WBREAD.
  #[rustfmt::skip]
  let wbp: [usize; 32] = [
     4 << 4,  6 << 4,  0 << 4,  2 << 4,
     7 << 4,  5 << 4,  3 << 4,  1 << 4,
    15 << 4, 11 << 4, 12 << 4,  8 << 4,
     9 << 4, 13 << 4, 10 << 4, 14 << 4,
    17 << 4, 18 << 4, 23 << 4, 20 << 4,
    22 << 4, 21 << 4, 16 << 4, 19 << 4,
    30 << 4, 24 << 4, 25 << 4, 31 << 4,
    27 << 4, 29 << 4, 28 << 4, 26 << 4,
  ];

  // 4 Feistel rounds.
  let mut w = [0u32; 64];
  wbread(&q, &wbp, 0, 0, 1, 185, &mut w);
  one_round_big(&mut state, &w, 0, 3, 23, 17, 27);
  wbread(&q, &wbp, 8, 0, 1, 185, &mut w);
  one_round_big(&mut state, &w, 1, 28, 19, 22, 7);
  wbread(&q, &wbp, 16, -256, -128, 233, &mut w);
  one_round_big(&mut state, &w, 2, 29, 9, 15, 5);
  wbread(&q, &wbp, 24, -383, -255, 233, &mut w);
  one_round_big(&mut state, &w, 3, 4, 13, 10, 25);

  // Final mixing: uses original state as message words.
  // PP8_4_=XOR 5, PP8_5_=XOR 7, PP8_6_=XOR 4, PP8_0_=XOR 1.
  step2_big(&mut state, h, 0, true, 4, 13, 5);
  step2_big(&mut state, h, 8, true, 13, 10, 7);
  step2_big(&mut state, h, 16, true, 10, 25, 4);
  step2_big(&mut state, h, 24, true, 25, 4, 1);

  *h = state;
}

/// Encode bit count for SIMD-512 (128-byte blocks).
const fn encode_count(dst: &mut [u8], low: u32, high: u32, ptr: usize) {
  let lo = low.wrapping_shl(10);
  let hi = high.wrapping_shl(10).wrapping_add(low >> 22);
  let lo = lo.wrapping_add((ptr as u32) << 3);
  let lo_b = lo.to_le_bytes();
  dst[0] = lo_b[0];
  dst[1] = lo_b[1];
  dst[2] = lo_b[2];
  dst[3] = lo_b[3];
  let hi_b = hi.to_le_bytes();
  dst[4] = hi_b[0];
  dst[5] = hi_b[1];
  dst[6] = hi_b[2];
  dst[7] = hi_b[3];
}

pub const fn hash512(data: &[u8]) -> Hash512 {
  let mut h = IV;
  let mut count_low = 0u32;
  let mut count_high = 0u32;

  let mut pos = 0;
  while pos + BLOCK <= data.len() {
    compress(&mut h, &extract::<BLOCK>(data, pos), false);
    count_low = count_low.wrapping_add(1);
    if count_low == 0 {
      count_high = count_high.wrapping_add(1);
    }
    pos += BLOCK;
  }

  // Finalize.
  let ptr = data.len() - pos;
  if ptr > 0 {
    let mut buf = [0u8; BLOCK];
    let mut ci = 0;
    while ci < ptr {
      buf[ci] = data[pos + ci];
      ci += 1;
    }
    compress(&mut h, &buf, false);
  }

  let mut buf = [0u8; BLOCK];
  encode_count(&mut buf, count_low, count_high, ptr);
  compress(&mut h, &buf, true);

  // Output: first 16 u32 words as LE.
  let mut out = [0u8; 64];
  let mut i = 0;
  while i < 16 {
    store_u32_le(&mut out, i, h[i]);
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
