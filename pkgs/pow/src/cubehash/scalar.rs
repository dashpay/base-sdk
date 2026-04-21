//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar CubeHash-16/32-512 implementation.

use super::consts::{round_pair, BLOCK, IV};
use crate::util::memops::{extract, load_u32_le, store_u32_le};

use dash_num::Hash512;

/// Applies 16 rounds (8 round-pairs) of the CubeHash permutation.
#[inline]
pub const fn sixteen_rounds(s: &mut [u32; 32]) {
  let mut i = 0;
  while i < 8 {
    round_pair(s);
    i += 1;
  }
}

/// Absorbs a 32-byte block into the state.
pub const fn absorb_block(state: &mut [u32; 32], block: &[u8]) {
  let mut i = 0;
  while i < BLOCK / 4 {
    state[i] ^= load_u32_le(block, i);
    i += 1;
  }
  sixteen_rounds(state);
}

pub const fn hash512(data: &[u8]) -> Hash512 {
  let mut state = IV;

  // Absorb full blocks
  let mut pos = 0;
  while pos + BLOCK <= data.len() {
    absorb_block(&mut state, &extract::<BLOCK>(data, pos));
    pos += BLOCK;
  }

  // Pad the final block: append 0x80, fill with zeros
  let mut last = [0u8; BLOCK];
  let remaining = data.len() - pos;
  let mut j = 0;
  while j < remaining {
    last[j] = data[pos + j];
    j += 1;
  }
  last[remaining] = 0x80;
  absorb_block(&mut state, &last);

  // Finalization: XOR 1 into state[31], then 10 x sixteen_rounds
  state[31] ^= 1;
  let mut i = 0;
  while i < 10 {
    sixteen_rounds(&mut state);
    i += 1;
  }

  // Extract 64 bytes (16 x u32) from state[0..16]
  let mut out = [0u8; 64];
  i = 0;
  while i < 16 {
    store_u32_le(&mut out, i, state[i]);
    i += 1;
  }
  Hash512::from_bytes(out)
}
