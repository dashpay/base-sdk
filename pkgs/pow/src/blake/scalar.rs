//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar Blake-512 implementation.

use super::consts::{BLOCK, CB, IV, SIGMA};
use crate::util::memops::{extract, load_u64_be, store_u64_be};

/// Compresses one 128-byte block into the state.
///
/// `t0`/`t1` is the 128-bit counter AFTER the +1024 advance for this block.
pub const fn compress(h: &mut [u64; 8], block: &[u8], t0: u64, t1: u64) {
  let mut m = [0u64; 16];
  let mut mi = 0;
  while mi < 16 {
    m[mi] = load_u64_be(block, mi);
    mi += 1;
  }

  #[rustfmt::skip]
  let mut v = [
    h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
    CB[0], CB[1], CB[2], CB[3],
    t0 ^ CB[4], t0 ^ CB[5], t1 ^ CB[6], t1 ^ CB[7],
  ];

  let mut r = 0;
  while r < 16 {
    let s = &SIGMA[r];
    // G mixing function applied to 4 state words at indices (a, b, c, d)
    // using message pair m[s[i]], m[s[i+1]] and constants CB[s[i]], CB[s[i+1]].
    macro_rules! g {
      ($a:expr, $b:expr, $c:expr, $d:expr, $i:expr) => {{
        v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add(m[s[$i]] ^ CB[s[$i + 1]]);
        v[$d] = (v[$d] ^ v[$a]).rotate_right(32);
        v[$c] = v[$c].wrapping_add(v[$d]);
        v[$b] = (v[$b] ^ v[$c]).rotate_right(25);
        v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add(m[s[$i + 1]] ^ CB[s[$i]]);
        v[$d] = (v[$d] ^ v[$a]).rotate_right(16);
        v[$c] = v[$c].wrapping_add(v[$d]);
        v[$b] = (v[$b] ^ v[$c]).rotate_right(11);
      }};
    }

    // Column step
    g!(0, 4, 8, 12, 0);
    g!(1, 5, 9, 13, 2);
    g!(2, 6, 10, 14, 4);
    g!(3, 7, 11, 15, 6);

    // Diagonal step
    g!(0, 5, 10, 15, 8);
    g!(1, 6, 11, 12, 10);
    g!(2, 7, 8, 13, 12);
    g!(3, 4, 9, 14, 14);
    r += 1;
  }

  let mut i = 0;
  while i < 8 {
    h[i] ^= v[i] ^ v[i + 8];
    i += 1;
  }
}

/// Advances the 128-bit counter by 1024 (one block worth of bits).
const fn advance_counter(t0: &mut u64, t1: &mut u64) {
  *t0 = t0.wrapping_add(1024);
  if *t0 < 1024 {
    *t1 = t1.wrapping_add(1);
  }
}

pub const fn hash512(data: &[u8]) -> [u8; 64] {
  let mut h = IV;
  let mut t0: u64 = 0;
  let mut t1: u64 = 0;

  // Absorb full 128-byte blocks.
  let mut pos = 0;
  while pos + BLOCK <= data.len() {
    advance_counter(&mut t0, &mut t1);
    compress(&mut h, &extract::<BLOCK>(data, pos), t0, t1);
    pos += BLOCK;
  }

  // Padding.
  let remaining = data.len() - pos;
  let bit_len = (remaining as u64) * 8;

  // Total message length in bits (embedded in padding, computed before
  // counter adjustment).
  let tl = t0.wrapping_add(bit_len);
  let th = if bit_len > 0 && tl < t0 { t1.wrapping_add(1) } else { t1 };

  // Always advance +1024 before each compress, so the sentinel
  // wraps to the correct final value after the advance.
  if remaining == 0 {
    t0 = 0xffff_ffff_ffff_fc00;
    t1 = 0xffff_ffff_ffff_ffff;
  } else if t0 == 0 {
    t0 = 0xffff_ffff_ffff_fc00u64.wrapping_add(bit_len);
    t1 = t1.wrapping_sub(1);
  } else {
    t0 = t0.wrapping_sub(1024 - bit_len);
  }

  let mut pad = [0u8; 2 * BLOCK];
  let mut ci = 0;
  while ci < remaining {
    pad[ci] = data[pos + ci];
    ci += 1;
  }
  pad[remaining] = 0x80;

  let single_block = remaining <= 111;
  if single_block {
    pad[111] |= 0x01; // Blake-512 output-length marker
    store_u64_be(&mut pad, 14, th);
    store_u64_be(&mut pad, 15, tl);
    advance_counter(&mut t0, &mut t1);
    compress(&mut h, &extract::<BLOCK>(&pad, 0), t0, t1);
  } else {
    // First block: data remainder + 0x80 padding.
    advance_counter(&mut t0, &mut t1);
    compress(&mut h, &extract::<BLOCK>(&pad, 0), t0, t1);
    // Second block: zeros + marker + length.
    t0 = 0xffff_ffff_ffff_fc00;
    t1 = 0xffff_ffff_ffff_ffff;
    let mut fin = [0u8; BLOCK];
    fin[111] = 0x01;
    store_u64_be(&mut fin, 14, th);
    store_u64_be(&mut fin, 15, tl);
    advance_counter(&mut t0, &mut t1);
    compress(&mut h, &fin, t0, t1);
  }

  let mut out = [0u8; 64];
  let mut i = 0;
  while i < 8 {
    store_u64_be(&mut out, i, h[i]);
    i += 1;
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Proves hash512 evaluates at compile time.
  const _: [u8; 64] = hash512(b"");
}
