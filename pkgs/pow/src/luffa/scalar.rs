//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar Luffa-512 implementation.

use super::consts::{BLOCK, IV, RC};
use crate::util::memops::extract;

use dash_num::Hash512;

/// SubCrumb: 4-input bitslice S-box at word indices.
const fn sub_crumb(w: &mut [u32; 8], i0: usize, i1: usize, i2: usize, i3: usize) {
  let (mut a0, mut a1, mut a2, mut a3) = (w[i0], w[i1], w[i2], w[i3]);
  let tmp = a0;
  a0 |= a1;
  a2 ^= a3;
  a1 = !a1;
  a0 ^= a3;
  a3 &= tmp;
  a1 ^= a3;
  a3 ^= a2;
  a2 &= a0;
  a0 = !a0;
  a2 ^= a1;
  a1 |= a3;
  let tmp = tmp ^ a1;
  a3 ^= a2;
  a2 &= a1;
  a1 ^= a0;
  a0 = tmp;
  w[i0] = a0;
  w[i1] = a1;
  w[i2] = a2;
  w[i3] = a3;
}

/// MixWord: rotation-based diffusion on a word pair.
const fn mix_word(w: &mut [u32; 8], u: usize, v: usize) {
  w[v] ^= w[u];
  w[u] = w[u].rotate_left(2) ^ w[v];
  w[v] = w[v].rotate_left(14) ^ w[u];
  w[u] = w[u].rotate_left(10) ^ w[v];
  w[v] = w[v].rotate_left(1);
}

/// M2: word rotation with feedback from word 7.
const fn m2(dst: &mut [u32; 8], src: &[u32; 8]) {
  let t = src[7];
  dst[0] = t;
  dst[1] = src[0] ^ t;
  dst[2] = src[1];
  dst[3] = src[2] ^ t;
  dst[4] = src[3] ^ t;
  dst[5] = src[4];
  dst[6] = src[5];
  dst[7] = src[6];
}

const fn m2_inplace(v: &mut [u32; 8]) {
  let c = *v;
  m2(v, &c);
}

const fn xor8(dst: &mut [u32; 8], src: &[u32; 8]) {
  let mut i = 0;
  while i < 8 {
    dst[i] ^= src[i];
    i += 1;
  }
}

/// XOR all 5 chains element-wise -> 32 bytes BE output at `base` offset.
const fn xor_chains(v: &[[u32; 8]; 5], out: &mut [u8; 64], base: usize) {
  let mut i = 0;
  while i < 8 {
    let w = v[0][i] ^ v[1][i] ^ v[2][i] ^ v[3][i] ^ v[4][i];
    let b = w.to_be_bytes();
    out[base + i * 4] = b[0];
    out[base + i * 4 + 1] = b[1];
    out[base + i * 4 + 2] = b[2];
    out[base + i * 4 + 3] = b[3];
    i += 1;
  }
}

/// MI5: message injection across 5 chains.
pub const fn mi5(v: &mut [[u32; 8]; 5], msg: &[u32; 8]) {
  // Local copies to avoid nested borrow issues.
  let [mut v0, mut v1, mut v2, mut v3, mut v4] = *v;

  let mut a = [0u32; 8];
  let mut i = 0;
  while i < 8 {
    a[i] = v0[i] ^ v1[i] ^ v2[i] ^ v3[i] ^ v4[i];
    i += 1;
  }
  m2_inplace(&mut a);
  xor8(&mut v0, &a);
  xor8(&mut v1, &a);
  xor8(&mut v2, &a);
  xor8(&mut v3, &a);
  xor8(&mut v4, &a);

  // Forward cascade.
  let mut b = [0u32; 8];
  m2(&mut b, &v0);
  xor8(&mut b, &v1);
  m2_inplace(&mut v1);
  xor8(&mut v1, &v2);
  m2_inplace(&mut v2);
  xor8(&mut v2, &v3);
  m2_inplace(&mut v3);
  xor8(&mut v3, &v4);
  m2_inplace(&mut v4);
  xor8(&mut v4, &v0);

  // Reverse cascade.
  m2(&mut v0, &b);
  xor8(&mut v0, &v4);
  m2_inplace(&mut v4);
  xor8(&mut v4, &v3);
  m2_inplace(&mut v3);
  xor8(&mut v3, &v2);
  m2_inplace(&mut v2);
  xor8(&mut v2, &v1);
  m2_inplace(&mut v1);
  xor8(&mut v1, &b);

  // Message XOR with repeated M2 doubling.
  let mut m = *msg;
  xor8(&mut v0, &m);
  m2_inplace(&mut m);
  xor8(&mut v1, &m);
  m2_inplace(&mut m);
  xor8(&mut v2, &m);
  m2_inplace(&mut m);
  xor8(&mut v3, &m);
  m2_inplace(&mut m);
  xor8(&mut v4, &m);

  *v = [v0, v1, v2, v3, v4];
}

/// TWEAK5: per-chain rotation on words 4-7.
const fn tweak5(v: &mut [[u32; 8]; 5]) {
  let mut i = 1u32;
  while i < 5 {
    let c = i as usize;
    v[c][4] = v[c][4].rotate_left(i);
    v[c][5] = v[c][5].rotate_left(i);
    v[c][6] = v[c][6].rotate_left(i);
    v[c][7] = v[c][7].rotate_left(i);
    i += 1;
  }
}

/// 8-round permutation on a single chain.
const fn permute_chain(w: &mut [u32; 8], rc0: &[u32; 8], rc4: &[u32; 8]) {
  let mut r = 0;
  while r < 8 {
    sub_crumb(w, 0, 1, 2, 3);
    sub_crumb(w, 5, 6, 7, 4);
    mix_word(w, 0, 4);
    mix_word(w, 1, 5);
    mix_word(w, 2, 6);
    mix_word(w, 3, 7);
    w[0] ^= rc0[r];
    w[4] ^= rc4[r];
    r += 1;
  }
}

/// P5: 8-round permutation on each chain independently.
pub const fn p5(v: &mut [[u32; 8]; 5]) {
  tweak5(v);
  let mut c = 0;
  while c < 5 {
    permute_chain(&mut v[c], &RC[c][0], &RC[c][1]);
    c += 1;
  }
}

const fn load_msg(buf: &[u8]) -> [u32; 8] {
  let mut out = [0u32; 8];
  let mut i = 0;
  while i < 8 {
    let o = i * 4;
    out[i] = u32::from_be_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
    i += 1;
  }
  out
}

pub const fn hash512(data: &[u8]) -> Hash512 {
  let mut v: [[u32; 8]; 5] = IV;

  let mut pos = 0;
  while pos + BLOCK <= data.len() {
    mi5(&mut v, &load_msg(&extract::<BLOCK>(data, pos)));
    p5(&mut v);
    pos += BLOCK;
  }

  let remaining = data.len() - pos;
  let mut pad = [0u8; BLOCK];
  let mut ci = 0;
  while ci < remaining {
    pad[ci] = data[pos + ci];
    ci += 1;
  }
  pad[remaining] = 0x80;

  let mut out = [0u8; 64];
  let mut i = 0;
  while i < 3 {
    mi5(&mut v, &load_msg(&pad));
    p5(&mut v);
    match i {
      0 => pad = [0u8; BLOCK],
      1 => xor_chains(&v, &mut out, 0),
      2 => xor_chains(&v, &mut out, 32),
      _ => {}
    }
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
