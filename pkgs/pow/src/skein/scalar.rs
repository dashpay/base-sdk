//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar Skein-512 implementation.

use super::consts::{BLOCK, IV, NW};
use crate::util::memops::{extract, load_u64_le, store_u64_le};
use crate::util::threefish;

/// UBI chaining: processes one 64-byte block.
///
/// `etype` encodes the block type and first/final flags in bits 55..62.
pub const fn ubi(h: &mut [u64; NW], block: &[u8], bcount: u64, extra: usize, etype: u64) {
  let t0 = (bcount << 6).wrapping_add(extra as u64);
  let t1 = (bcount >> 58) | (etype << 55);

  let mut p = [0u64; NW];
  let mut i = 0;
  while i < NW {
    p[i] = load_u64_le(block, i);
    i += 1;
  }

  let plaintext = p;
  threefish::encrypt(&mut p, h, &[t0, t1]);

  // Matyas-Meyer-Oseas feedforward.
  i = 0;
  while i < NW {
    h[i] = p[i] ^ plaintext[i];
    i += 1;
  }
}

pub const fn hash512(data: &[u8]) -> [u8; 64] {
  let mut h = IV;
  let mut bcount: u64 = 0;

  // Etype encoding: (type_code << 1) | (FIRST << 7) | (FINAL << 8).
  const MSG: u64 = 48 << 1;
  const FIRST: u64 = 1 << 7;
  const FINAL: u64 = 1 << 8;
  const OUTPUT: u64 = 63 << 1;

  // Process full blocks, deferring the last one so it gets the FINAL flag.
  let mut pos = 0;
  while pos + BLOCK < data.len() {
    let first = if pos == 0 { FIRST } else { 0 };
    ubi(&mut h, &extract::<BLOCK>(data, pos), bcount, BLOCK, MSG + first);
    bcount += 1;
    pos += BLOCK;
  }

  // Final message block (may be full or partial, padded with zeros).
  let remaining = data.len() - pos;
  let mut last = [0u8; BLOCK];
  let mut j = 0;
  while j < remaining {
    last[j] = data[pos + j];
    j += 1;
  }
  let first = if bcount == 0 { FIRST } else { 0 };
  ubi(&mut h, &last, bcount, remaining, MSG + FINAL + first);

  // Output block.
  let out_block = [0u8; BLOCK];
  ubi(&mut h, &out_block, 0, 8, OUTPUT + FIRST + FINAL);

  let mut out = [0u8; 64];
  let mut i = 0;
  while i < NW {
    store_u64_le(&mut out, i, h[i]);
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
