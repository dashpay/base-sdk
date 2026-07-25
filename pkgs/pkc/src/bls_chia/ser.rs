//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy serialization format for BLS elements.
//!
//! G1 (48 bytes): sign bit at byte[0] & 0x80, no compression indicator.
//! G2 (96 bytes): legacy component order (c0||c1), sign bit at byte[0] & 0x80.

use crate::bls::blst_ffi::{G1Affine, G2Affine};
use crate::bls::BlsError;

use hex_literal::hex;

/// Serialize a G1 affine point to 48 legacy bytes.
pub(super) fn ser_g1(p: &G1Affine) -> [u8; 48] {
  let ietf = p.compress();

  if ietf[0] & 0xc0 == 0xc0 {
    return ietf; // infinity is the same in both formats
  }

  // IETF: bit 7 = compression, bit 5 = sign.
  // Legacy: bit 7 = sign, no compression indicator.
  let sign = (ietf[0] >> 5) & 1;
  let mut legacy = ietf;
  legacy[0] &= 0x1f;
  if sign == 1 {
    legacy[0] |= 0x80;
  }
  legacy
}

/// Deserialize 48 legacy bytes to a G1 affine point.
pub(super) fn deser_g1(bytes: &[u8; 48]) -> Result<G1Affine, BlsError> {
  if bytes[0] & 0xc0 == 0xc0 {
    return G1Affine::uncompress(bytes).map_err(|_| BlsError::InvalidPublicKey);
  }

  let sign = (bytes[0] >> 7) & 1;
  let mut ietf = *bytes;
  // Only bit 7 is the legacy sign flag; normalize away stray high bits
  // rather than rejecting, to stay bit-for-bit compatible on the wire.
  ietf[0] &= 0x1f;
  ietf[0] |= 0x80; // compression
  if sign == 1 {
    ietf[0] |= 0x20; // sign
  }

  G1Affine::uncompress(&ietf).map_err(|_| BlsError::InvalidPublicKey)
}

/// Serialize a G2 affine point to 96 legacy bytes.
///
/// Uses uncompressed 192-byte intermediate to sidestep sign-bit convention
/// differences between IETF and legacy formats.
///
/// blst:   `[x.c1(48), x.c0(48), y.c1(48), y.c0(48)]`
/// Legacy: `[x.c0(48), x.c1(48)]`, sign at byte\[0\] bit 7
pub(super) fn ser_g2(p: &G2Affine) -> [u8; 96] {
  let uncomp = p.serialize();

  if uncomp.iter().all(|&b| b == 0) {
    let mut out = [0u8; 96];
    out[0] = 0xc0;
    return out;
  }

  let x_c1 = &uncomp[0..48];
  let x_c0 = &uncomp[48..96];
  let y_c1 = &uncomp[96..144];

  let sign = y_c1_is_larger(y_c1);

  let mut legacy = [0u8; 96];
  legacy[..48].copy_from_slice(x_c0);
  legacy[48..96].copy_from_slice(x_c1);
  if sign {
    legacy[0] |= 0x80;
  }
  legacy
}

/// Deserialize 96 legacy bytes to a G2 affine point.
pub(super) fn deser_g2(bytes: &[u8; 96]) -> Result<G2Affine, BlsError> {
  if bytes[0] & 0xc0 == 0xc0 {
    let mut ietf = [0u8; 96];
    ietf[0] = 0xc0;
    return G2Affine::uncompress(&ietf).map_err(|_| BlsError::InvalidSignature);
  }

  let sign = (bytes[0] >> 7) & 1;

  // After swizzling, byte 48 (top of `x.c1`) sits in the IETF flag byte,
  // where blst reads flags instead of range-checking, so reject its stray
  // high bits here: the reference feeds them to relic as `x >= p`.
  if bytes[48] & 0xe0 != 0 {
    return Err(BlsError::InvalidSignature);
  }

  let mut x_c0 = [0u8; 48];
  x_c0.copy_from_slice(&bytes[..48]);
  // Clear only the sign bit: stray bits 5-6 make `x.c0 >= p`, rejected by
  // the decompression range check like any out-of-range coordinate.
  x_c0[0] &= 0x7f;
  let x_c1 = &bytes[48..96];

  let mut ietf = [0u8; 96];
  ietf[..48].copy_from_slice(x_c1);
  ietf[48..96].copy_from_slice(&x_c0);

  ietf[0] |= 0x80; // compression

  // Decompress with sign=0, then negate y if needed.
  let out = G2Affine::uncompress(&ietf).map_err(|_| BlsError::InvalidSignature)?;

  let decompressed_sign = y_c1_is_larger(&out.y().c1_bendian());
  if (sign == 1) != decompressed_sign {
    return Ok(G2Affine::from_coords(out.x(), -out.y()));
  }

  Ok(out)
}

/// y.c1 > (p-1)/2, matching the legacy sign convention.
fn y_c1_is_larger(y_c1: &[u8]) -> bool {
  const HALF_P: [u8; 48] = hex!(
    "0d0088f5 1cbff34d 258dd3db 21a5d66b"
    "b23ba5c2 79c2895f b3986950 7b587b12"
    "0f55ffff 58a9ffff dcff7fff ffffd555"
  );

  y_c1.len() >= 48 && y_c1[..48] > HALF_P[..]
}
