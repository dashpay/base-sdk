//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar JH-512 implementation.

use super::consts::{BLOCK, IV, ROUND_CONSTS};

use dash_num::Hash512;

/// E8 permutation on 16 u64 words: 42 rounds cycling W0-W6.
pub const fn e8(h: &mut [u64; 16]) {
  // Extract to locals to avoid array borrow issues.
  #[rustfmt::skip]
  let [mut h0, mut h1, mut h2, mut h3,
       mut h4, mut h5, mut h6, mut h7,
       mut h8, mut h9, mut ha, mut hb,
       mut hc, mut hd, mut he, mut hf] = *h;

  // S-box: bitslice 4-input nonlinear substitution.
  macro_rules! sb {
    ($x0:ident, $x1:ident, $x2:ident, $x3:ident, $c:expr) => {{
      $x3 = !$x3;
      $x0 ^= $c & !$x2;
      let tmp = $c ^ ($x0 & $x1);
      $x0 ^= $x2 & $x3;
      $x3 ^= !$x1 & $x2;
      $x1 ^= $x0 & $x2;
      $x2 ^= $x0 & !$x3;
      $x0 ^= $x1 | $x3;
      $x3 ^= $x1 & $x2;
      $x1 ^= tmp & $x0;
      $x2 ^= tmp;
    }};
  }

  // Linear transform.
  macro_rules! lb {
    ($x0:ident, $x1:ident, $x2:ident, $x3:ident,
     $x4:ident, $x5:ident, $x6:ident, $x7:ident) => {{
      $x4 ^= $x1;
      $x5 ^= $x2;
      $x6 ^= $x3 ^ $x0;
      $x7 ^= $x0;
      $x0 ^= $x5;
      $x1 ^= $x6;
      $x2 ^= $x7 ^ $x4;
      $x3 ^= $x4;
    }};
  }

  // W permutation: bit-group swap within u32 halves.
  macro_rules! wz {
    ($x:ident, $mask:expr, $shift:expr) => {{
      let m = ($mask as u64) | (($mask as u64) << 32);
      $x = (($x >> $shift) & m) | (($x & m) << $shift);
    }};
  }

  // One round: S-box on even+odd columns, linear transform,
  // word permutation (W0-W6) on odd-indexed halves.
  macro_rules! sl {
    ($r:expr, $ro:expr) => {{
      // State layout: 8 pairs (hNh, hNl) stored as H[2N], H[2N+1].
      // S-box columns: (H[0],H[4],H[8],H[12]), (H[1],H[5],H[9],H[13]),
      //                (H[2],H[6],H[10],H[14]), (H[3],H[7],H[11],H[15]).
      sb!(h0, h4, h8, hc, ROUND_CONSTS[$r][0]); // even hi
      sb!(h1, h5, h9, hd, ROUND_CONSTS[$r][1]); // even lo
      sb!(h2, h6, ha, he, ROUND_CONSTS[$r][2]); // odd hi
      sb!(h3, h7, hb, hf, ROUND_CONSTS[$r][3]); // odd lo
      lb!(h0, h4, h8, hc, h2, h6, ha, he); // L on hi
      lb!(h1, h5, h9, hd, h3, h7, hb, hf); // L on lo
                                           // W permutation on odd pairs: (h2,h3), (h6,h7), (ha,hb), (he,hf)
      match $ro {
        0 => {
          wz!(h2, 0x55555555u32, 1);
          wz!(h3, 0x55555555u32, 1);
          wz!(h6, 0x55555555u32, 1);
          wz!(h7, 0x55555555u32, 1);
          wz!(ha, 0x55555555u32, 1);
          wz!(hb, 0x55555555u32, 1);
          wz!(he, 0x55555555u32, 1);
          wz!(hf, 0x55555555u32, 1);
        }
        1 => {
          wz!(h2, 0x33333333u32, 2);
          wz!(h3, 0x33333333u32, 2);
          wz!(h6, 0x33333333u32, 2);
          wz!(h7, 0x33333333u32, 2);
          wz!(ha, 0x33333333u32, 2);
          wz!(hb, 0x33333333u32, 2);
          wz!(he, 0x33333333u32, 2);
          wz!(hf, 0x33333333u32, 2);
        }
        2 => {
          wz!(h2, 0x0F0F0F0Fu32, 4);
          wz!(h3, 0x0F0F0F0Fu32, 4);
          wz!(h6, 0x0F0F0F0Fu32, 4);
          wz!(h7, 0x0F0F0F0Fu32, 4);
          wz!(ha, 0x0F0F0F0Fu32, 4);
          wz!(hb, 0x0F0F0F0Fu32, 4);
          wz!(he, 0x0F0F0F0Fu32, 4);
          wz!(hf, 0x0F0F0F0Fu32, 4);
        }
        3 => {
          wz!(h2, 0x00FF00FFu32, 8);
          wz!(h3, 0x00FF00FFu32, 8);
          wz!(h6, 0x00FF00FFu32, 8);
          wz!(h7, 0x00FF00FFu32, 8);
          wz!(ha, 0x00FF00FFu32, 8);
          wz!(hb, 0x00FF00FFu32, 8);
          wz!(he, 0x00FF00FFu32, 8);
          wz!(hf, 0x00FF00FFu32, 8);
        }
        4 => {
          wz!(h2, 0x0000FFFFu32, 16);
          wz!(h3, 0x0000FFFFu32, 16);
          wz!(h6, 0x0000FFFFu32, 16);
          wz!(h7, 0x0000FFFFu32, 16);
          wz!(ha, 0x0000FFFFu32, 16);
          wz!(hb, 0x0000FFFFu32, 16);
          wz!(he, 0x0000FFFFu32, 16);
          wz!(hf, 0x0000FFFFu32, 16);
        }
        5 => {
          // Swap u32 halves within each u64
          h2 = h2.rotate_left(32);
          h3 = h3.rotate_left(32);
          h6 = h6.rotate_left(32);
          h7 = h7.rotate_left(32);
          ha = ha.rotate_left(32);
          hb = hb.rotate_left(32);
          he = he.rotate_left(32);
          hf = hf.rotate_left(32);
        }
        6 => {
          // Swap the two u64s in each pair
          ::core::mem::swap(&mut h2, &mut h3);
          ::core::mem::swap(&mut h6, &mut h7);
          ::core::mem::swap(&mut ha, &mut hb);
          ::core::mem::swap(&mut he, &mut hf);
        }
        _ => {}
      }
    }};
  }

  let mut r = 0;
  while r < 42 {
    sl!(r, 0);
    sl!(r + 1, 1);
    sl!(r + 2, 2);
    sl!(r + 3, 3);
    sl!(r + 4, 4);
    sl!(r + 5, 5);
    sl!(r + 6, 6);
    r += 7;
  }

  *h = [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, ha, hb, hc, hd, he, hf];
}

/// XOR message block into first or second half of state.
const fn xor_block(h: &mut [u64; 16], buf: &[u8], offset: usize) {
  let mut i = 0;
  while i < 8 {
    let off = i * 8;
    h[offset + i] ^= u64::from_le_bytes([
      buf[off],
      buf[off + 1],
      buf[off + 2],
      buf[off + 3],
      buf[off + 4],
      buf[off + 5],
      buf[off + 6],
      buf[off + 7],
    ]);
    i += 1;
  }
}

/// Process one 64-byte block through the JH compression.
pub const fn compress(h: &mut [u64; 16], buf: &[u8]) {
  xor_block(h, buf, 0);
  e8(h);
  xor_block(h, buf, 8);
}

/// Flattens the `[[u64; 2]; 8]` IV into a `[u64; 16]` state array.
const fn flatten_iv() -> [u64; 16] {
  let mut h = [0u64; 16];
  let mut i = 0;
  while i < 8 {
    h[2 * i] = IV[i][0];
    h[2 * i + 1] = IV[i][1];
    i += 1;
  }
  h
}

pub const fn hash512(data: &[u8]) -> Hash512 {
  let mut h = flatten_iv();
  let mut block_count: u64 = 0;
  let mut buf = [0u8; BLOCK];
  let mut ptr = 0usize;

  let mut di = 0;
  while di < data.len() {
    buf[ptr] = data[di];
    ptr += 1;
    if ptr == BLOCK {
      compress(&mut h, &buf);
      block_count += 1;
      ptr = 0;
    }
    di += 1;
  }

  // Padding flows through the same buffer to match block boundaries for messages
  // at the 64-byte boundary.
  let mut pad = [0u8; 128];
  pad[0] = 0x80;

  let nz = if ptr == 0 { 47 } else { 111 - ptr };

  let bit_lo = (block_count << 9).wrapping_add((ptr as u64) << 3);
  let bit_hi = block_count >> 55;

  let len_off = 1 + nz;
  let hi_bytes = bit_hi.to_be_bytes();
  let mut ci = 0;
  while ci < 8 {
    pad[len_off + ci] = hi_bytes[ci];
    ci += 1;
  }
  let lo_bytes = bit_lo.to_be_bytes();
  ci = 0;
  while ci < 8 {
    pad[len_off + 8 + ci] = lo_bytes[ci];
    ci += 1;
  }

  let total = nz + 17;
  let mut fed = 0;
  while fed < total {
    let space = BLOCK - ptr;
    let chunk = if space < total - fed { space } else { total - fed };
    let mut ci = 0;
    while ci < chunk {
      buf[ptr + ci] = pad[fed + ci];
      ci += 1;
    }
    ptr += chunk;
    fed += chunk;
    if ptr == BLOCK {
      compress(&mut h, &buf);
      ptr = 0;
    }
  }

  let mut out = [0u8; 64];
  let mut i = 0;
  while i < 8 {
    let b = h[i + 8].to_le_bytes();
    let base = i * 8;
    let mut j = 0;
    while j < 8 {
      out[base + j] = b[j];
      j += 1;
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
