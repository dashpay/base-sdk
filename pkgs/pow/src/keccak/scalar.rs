//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar Keccak-f[1600] permutation and sponge.

use super::consts::{RATE, RC, ROTC};
use crate::util::memops::{extract, load_u64_le, store_u64_le};

/// Applies the Keccak-f[1600] permutation in place (24 rounds).
///
/// State is a 5x5 matrix of 64-bit lanes stored in row-major order as
/// `state[x + 5*y]`.
pub const fn keccak_f1600(a: &mut [u64; 25]) {
  let mut ri = 0;
  while ri < RC.len() {
    let rc = RC[ri];
    // theta step: column parity and diffusion
    let mut c = [0u64; 5];
    let mut x = 0;
    while x < 5 {
      c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
      x += 1;
    }
    let mut d = [0u64; 5];
    x = 0;
    while x < 5 {
      d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
      x += 1;
    }
    let mut i = 0;
    while i < 25 {
      a[i] ^= d[i % 5];
      i += 1;
    }

    // rho and pi steps (combined): rotate then move to new position
    let mut b = [0u64; 25];
    i = 0;
    while i < 25 {
      let x = i % 5;
      let y = i / 5;
      let dst = y + 5 * ((2 * x + 3 * y) % 5);
      b[dst] = a[i].rotate_left(ROTC[i]);
      i += 1;
    }

    // chi step: non-linear mixing per row
    x = 0;
    while x < 5 {
      let mut y = 0;
      while y < 5 {
        let idx = x + 5 * y;
        a[idx] = b[idx] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        y += 1;
      }
      x += 1;
    }

    // iota step: round constant injection
    a[0] ^= rc;

    ri += 1;
  }
}

/// Absorbs a full `RATE`-byte block into the sponge state.
const fn absorb_block(state: &mut [u64; 25], block: &[u8]) {
  let mut i = 0;
  while i < RATE / 8 {
    state[i] ^= load_u64_le(block, i);
    i += 1;
  }
  keccak_f1600(state);
}

pub const fn hash512(data: &[u8]) -> [u8; 64] {
  let mut state = [0u64; 25];

  // Absorb full blocks
  let mut pos = 0;
  while pos + RATE <= data.len() {
    absorb_block(&mut state, &extract::<RATE>(data, pos));
    pos += RATE;
  }

  // Pad the final block (multi-rate padding: 10*1)
  let mut last = [0u8; RATE];
  let remaining = data.len() - pos;
  let mut j = 0;
  while j < remaining {
    last[j] = data[pos + j];
    j += 1;
  }
  last[remaining] = 0x01;
  last[RATE - 1] |= 0x80;
  absorb_block(&mut state, &last);

  // Squeeze: extract 64 bytes (512 bits) from the state
  let mut out = [0u8; 64];
  let mut i = 0;
  while i < 8 {
    store_u64_le(&mut out, i, state[i]);
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
