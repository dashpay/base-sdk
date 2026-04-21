//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar BMW-512 implementation.

use super::consts::*;
use crate::util::memops::{extract, load_u64_le, store_u64_le};

use dash_num::Hash512;

/// S-function: parameterized shift/rotate mixing.
///
/// For n < 4: `(x >> A) ^ (x << B) ^ rotl(x, C) ^ rotl(x, D)`. For n >= 4: `(x
/// >> A) ^ x`.
const fn sb(n: usize, x: u64) -> u64 {
  if n < 4 {
    (x >> SB_SHR[n]) ^ (x << SB_SHL[n]) ^ x.rotate_left(SB_RC[n]) ^ x.rotate_left(SB_RD[n])
  } else {
    (x >> SB_SHR[n]) ^ x
  }
}

/// Expansion constant: `j * 0x0555555555555555`.
const fn kb(j: usize) -> u64 {
  (j as u64).wrapping_mul(0x0555555555555555)
}

/// Add-element: `rotl(m[j], j+1) + rotl(m[j+3], j+4) - rotl(m[j+10], j+11) +
/// kb(j+16) ^ h[j+7]`.
///
/// All indices are taken mod 16 for circular access.
const fn add_elt(m: &[u64; 16], h: &[u64; 16], j: usize) -> u64 {
  let idx0 = (j) & 15;
  let idx3 = (j + 3) & 15;
  let idx10 = (j + 10) & 15;
  let r0 = m[idx0].rotate_left(idx0 as u32 + 1);
  let r3 = m[idx3].rotate_left(idx3 as u32 + 1);
  let r10 = m[idx10].rotate_left(idx10 as u32 + 1);
  r0.wrapping_add(r3).wrapping_sub(r10).wrapping_add(kb(j + 16)) ^ h[(j + 7) & 15]
}

/// Compute W[0..16] from message and state using the sign/index tables.
const fn compute_w(m: &[u64; 16], h: &[u64; 16]) -> [u64; 16] {
  let mut w = [0u64; 16];
  let mut i = 0;
  while i < 16 {
    let idx = &W_IDX[i];
    let ops = &W_OPS[i];

    let mut v = m[idx[0]] ^ h[idx[0]];
    let mut k = 1;
    while k < 5 {
      if ops[k - 1] {
        v = v.wrapping_add(m[idx[k]] ^ h[idx[k]]);
      } else {
        v = v.wrapping_sub(m[idx[k]] ^ h[idx[k]]);
      }
      k += 1;
    }
    w[i] = v;
    i += 1;
  }
  w
}

/// Shifts a u64 left or right depending on the `left` flag.
const fn directed_shift(x: u64, left: bool, amount: u32) -> u64 {
  if left {
    x << amount
  } else {
    x >> amount
  }
}

/// Compresses one 128-byte block: `h` (state) -> `dh` (output).
pub const fn compress(data: &[u8], h: &[u64; 16], dh: &mut [u64; 16]) {
  let mut m = [0u64; 16];
  let mut mi = 0;
  while mi < 16 {
    m[mi] = load_u64_le(data, mi);
    mi += 1;
  }
  let w = compute_w(&m, h);

  // Phase 1: Q[0..16] from W values + H rotation
  let mut q = [0u64; 32];
  let mut i = 0;
  while i < 16 {
    q[i] = sb(i % 5, w[i]).wrapping_add(h[(i + 1) & 15]);
    i += 1;
  }

  // Phase 2: Q[16..18] via expand1 (sb1, sb2, sb3, sb0 cycling)
  i = 16;
  while i < 18 {
    let j = i - 16;
    let mut v = 0u64;
    let mut k = 0;
    while k < 16 {
      v = v.wrapping_add(sb((k + 1) % 4, q[j + k]));
      k += 1;
    }
    q[i] = v.wrapping_add(add_elt(&m, h, j));
    i += 1;
  }

  // Phase 3: Q[18..32] via expand2 (rotation interleave)
  // q[j] + rb1(q[j+1]) + q[j+2] + rb2(q[j+3])
  //   + ... + rb7(q[j+13]) + sb4(q[j+14])
  //   + sb5(q[j+15])
  i = 18;
  while i < 32 {
    let j = i - 16;
    let mut v = q[j];
    let mut k = 0;
    while k < 7 {
      v = v.wrapping_add(q[j + 2 * k + 1].rotate_left(RB[k]));
      v = v.wrapping_add(q[j + 2 * k + 2]);
      k += 1;
    }
    // The loop adds q[j+14] as plain, but the spec requires sb4(q[j+14])
    // and sb5(q[j+15]) for the final two terms.
    v = v.wrapping_sub(q[j + 14]);
    v = v.wrapping_add(sb(4, q[j + 14]));
    v = v.wrapping_add(sb(5, q[j + 15]));
    q[i] = v.wrapping_add(add_elt(&m, h, j));
    i += 1;
  }

  // Phase 4: FOLD -- combine Q values into 16-word output
  let xl = q[16] ^ q[17] ^ q[18] ^ q[19] ^ q[20] ^ q[21] ^ q[22] ^ q[23];
  let xh = xl ^ q[24] ^ q[25] ^ q[26] ^ q[27] ^ q[28] ^ q[29] ^ q[30] ^ q[31];

  // dh[0..8]: table-driven shift/XOR pattern.
  i = 0;
  while i < 8 {
    let (xh_left, xh_amt, q_left, q_amt) = FOLD1[i];
    let term = directed_shift(xh, xh_left, xh_amt) ^ directed_shift(q[16 + i], q_left, q_amt) ^ m[i];
    dh[i] = term.wrapping_add(xl ^ q[24 + i] ^ q[i]);
    i += 1;
  }

  // dh[8..16]: rotation of earlier dh + shifted xl + Q mixing.
  i = 0;
  while i < 8 {
    let (src, rot, xl_left, xl_amt) = FOLD2[i];
    let q_idx = FOLD2_Q[i];
    dh[8 + i] = dh[src].rotate_left(rot).wrapping_add(
      (xh ^ q[24 + i] ^ m[8 + i]).wrapping_add(directed_shift(xl, xl_left, xl_amt) ^ q[q_idx] ^ q[8 + i]),
    );
    i += 1;
  }
}

/// Serializes a 16-word state as a 128-byte little-endian block.
const fn state_to_bytes(state: &[u64; 16]) -> [u8; BLOCK] {
  let mut buf = [0u8; BLOCK];
  let mut i = 0;
  while i < 16 {
    store_u64_le(&mut buf, i, state[i]);
    i += 1;
  }
  buf
}

pub const fn hash512(data: &[u8]) -> Hash512 {
  let mut h1 = IV;
  let mut h2 = [0u64; 16];
  let mut current = &mut h1;
  let mut next = &mut h2;
  let bit_count = (data.len() as u64) << 3;

  // Absorb full 128-byte blocks.
  let mut pos = 0;
  while pos + BLOCK <= data.len() {
    compress(&extract::<BLOCK>(data, pos), current, next);
    core::mem::swap(&mut current, &mut next);
    pos += BLOCK;
  }

  // Padding: 0x80 + zeros + 8-byte LE bit count at offset 120.
  let remaining = data.len() - pos;
  let mut pad = [0u8; 2 * BLOCK];
  let mut ci = 0;
  while ci < remaining {
    pad[ci] = data[pos + ci];
    ci += 1;
  }
  pad[remaining] = 0x80;

  if remaining <= 119 {
    store_u64_le(&mut pad, 15, bit_count);
    compress(&extract::<BLOCK>(&pad, 0), current, next);
    core::mem::swap(&mut current, &mut next);
  } else {
    compress(&extract::<BLOCK>(&pad, 0), current, next);
    core::mem::swap(&mut current, &mut next);
    let mut fin = [0u8; BLOCK];
    store_u64_le(&mut fin, 15, bit_count);
    compress(&fin, current, next);
    core::mem::swap(&mut current, &mut next);
  }

  // Final compression: serialize state as data, use FINAL_B as H.
  let data_buf = state_to_bytes(current);
  compress(&data_buf, &FINAL_B, next);

  // Output: last 8 words.
  let mut out = [0u8; 64];
  let mut i = 0;
  while i < 8 {
    store_u64_le(&mut out, i, next[i + 8]);
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
