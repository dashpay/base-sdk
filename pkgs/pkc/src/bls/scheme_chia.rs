//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS scheme implementation.

use super::blst_ffi::{self, G1Affine, G2Affine, Point, G1};
use super::chia_h2c;
use super::error::BlsError;
use super::scheme_ops::{self, BlsScheme};
use super::schemes::BlsScChia;
use crate::prelude::*;

use blst::min_pk;
use dash_num::Hash256;
use hex_literal::hex;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// y.c1 > (p-1)/2, matching the legacy sign convention.
fn y_c1_is_larger(y_c1: &[u8]) -> bool {
  const HALF_P: [u8; 48] = hex!(
    "0d0088f5 1cbff34d 258dd3db 21a5d66b"
    "b23ba5c2 79c2895f b3986950 7b587b12"
    "0f55ffff 58a9ffff dcff7fff ffffd555"
  );

  y_c1.len() >= 48 && y_c1[..48] > HALF_P[..]
}

impl BlsScheme for BlsScChia {
  type InnerSk = blst::blst_scalar;
  type InnerPk = G1Affine;
  type InnerSig = G2Affine;
  type Msg = [u8; 32];

  /// Derive via draft-03 keygen, then range-check the scalar.
  fn generate(ikm: &[u8]) -> Result<Self::InnerSk, BlsError> {
    let sk = min_pk::SecretKey::key_gen_v3(ikm, &[]).map_err(|_| BlsError::InvalidSecretKey)?;
    let mut bytes = sk.to_bytes();
    let res = Self::sk_from_bytes(&bytes);
    bytes.zeroize();
    res
  }

  /// Interpret the bytes as a scalar and reject out-of-range values.
  fn sk_from_bytes(b: &[u8; 32]) -> Result<Self::InnerSk, BlsError> {
    let scalar = blst_ffi::scalar_from_bendian(b);
    if blst_ffi::sk_check(&scalar) {
      Ok(scalar)
    } else {
      Err(BlsError::InvalidSecretKey)
    }
  }

  /// Emit the scalar as big-endian bytes.
  fn sk_to_bytes(sk: &Self::InnerSk) -> [u8; 32] {
    blst_ffi::bendian_from_scalar(sk)
  }

  /// Multiply the G1 generator by the secret scalar.
  fn derive_pk(sk: &Self::InnerSk) -> Self::InnerPk {
    blst_ffi::sk_to_pk2_in_g1(sk)
  }

  /// Wipe the scalar limbs.
  fn zeroize_sk(sk: &mut Self::InnerSk) {
    sk.b.zeroize();
  }

  /// Decode a G1 point from the legacy 48-byte format.
  ///
  /// No prime-order subgroup check is performed on the legacy path, for
  /// backwards compatibility: checking here would reject keys the legacy
  /// format accepts.
  fn pk_from_bytes(b: &[u8; 48]) -> Result<Self::InnerPk, BlsError> {
    // Reject the all-zero encoding and the infinity marker.
    if b.iter().all(|&byte| byte == 0) || b[0] & 0xc0 == 0xc0 {
      return Err(BlsError::InvalidPublicKey);
    }

    let sign = (b[0] >> 7) & 1;
    let mut ietf = *b;
    // Only bit 7 is the legacy sign flag; normalize away stray high bits
    // rather than rejecting, to stay bit-for-bit compatible on the wire.
    ietf[0] &= 0x1f;
    ietf[0] |= 0x80; // compression
    if sign == 1 {
      ietf[0] |= 0x20; // sign
    }

    G1Affine::uncompress(&ietf).map_err(|_| BlsError::InvalidPublicKey)
  }

  /// Encode a G1 point in the legacy 48-byte format.
  fn pk_to_bytes(pk: &Self::InnerPk) -> [u8; 48] {
    let ietf = pk.compress();

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

  /// Decode a G2 point from the legacy 96-byte format.
  ///
  /// No prime-order subgroup check is performed on the legacy path, for
  /// backwards compatibility: checking here would reject signatures the
  /// legacy format accepts.
  fn sig_from_bytes(b: &[u8; 96]) -> Result<Self::InnerSig, BlsError> {
    // Reject the all-zero encoding and the infinity marker.
    if b.iter().all(|&byte| byte == 0) || b[0] & 0xc0 == 0xc0 {
      return Err(BlsError::InvalidSignature);
    }

    let sign = (b[0] >> 7) & 1;

    // After swizzling, byte 48 (top of `x.c1`) sits in the IETF flag byte,
    // where blst reads flags instead of range-checking, so reject its stray
    // high bits here: the reference feeds them to relic as `x >= p`.
    if b[48] & 0xe0 != 0 {
      return Err(BlsError::InvalidSignature);
    }

    let mut x_c0 = [0u8; 48];
    x_c0.copy_from_slice(&b[..48]);
    // Clear only the sign bit: stray bits 5-6 make `x.c0 >= p`, rejected by
    // the decompression range check like any out-of-range coordinate.
    x_c0[0] &= 0x7f;
    let x_c1 = &b[48..96];

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

  /// Encode a G2 point in the legacy 96-byte format.
  ///
  /// Uses the uncompressed 192-byte intermediate to sidestep sign-bit
  /// convention differences: blst lays out `[x.c1, x.c0, y.c1, y.c0]`,
  /// legacy `[x.c0, x.c1]` with the sign at byte\[0\] bit 7.
  fn sig_to_bytes(sig: &Self::InnerSig) -> [u8; 96] {
    let uncomp = sig.serialize();

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

  /// Hash the message to G2 and multiply by the secret scalar (no DST).
  fn sign(sk: &Self::InnerSk, msg: &Self::Msg) -> Self::InnerSig {
    let h = chia_h2c::hash_to_g2(msg);
    // blst_sign_pk_in_g1 applies IETF transformations, do manually instead.
    h.mul_scalar(&sk.b, blst_ffi::FR_BITS).to_affine()
  }

  /// Check the pairing e(sig, G1) == e(H(msg), pk).
  fn verify(sig: &Self::InnerSig, msg: &Self::Msg, pk: &Self::InnerPk) -> Result<(), BlsError> {
    let h_proj = chia_h2c::hash_to_g2(msg);
    if blst_ffi::pairings_equal_with_g1_generator(sig, &h_proj, pk) {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  /// Multiply the peer public key by the secret scalar.
  fn dh_exchange(sk: &Self::InnerSk, peer_pk: &Self::InnerPk) -> Result<Self::InnerPk, BlsError> {
    let mut sk_bytes = Self::sk_to_bytes(sk);
    let mut sk_scalar = blst_ffi::scalar_from_bendian(&sk_bytes);
    let out_aff = peer_pk.mul_scalar(&sk_scalar.b, blst_ffi::FR_BITS);
    sk_bytes.zeroize();
    sk_scalar.b.zeroize();
    Ok(out_aff)
  }

  /// Sum the public keys in G1.
  fn aggregate_pk(pks: &[&Self::InnerPk]) -> Result<Self::InnerPk, BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let mut acc = pks[0].to_projective();
    for pk in &pks[1..] {
      acc = acc + pk.to_projective();
    }
    Ok(acc.to_affine())
  }

  /// Sum the signatures in G2.
  fn aggregate_sig(sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    if sigs.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let mut acc = sigs[0].to_projective();
    for sig in &sigs[1..] {
      acc = acc + sig.to_projective();
    }
    Ok(acc.to_affine())
  }

  /// Sum the keys, then verify once against the shared message.
  fn fast_verify_aggregates(sig: &Self::InnerSig, msg: &Self::Msg, pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let agg_pk = Self::aggregate_pk(pks)?;
    Self::verify(sig, msg, &agg_pk)
  }

  /// Hash-weight each key before summing, then verify (rogue-key safe).
  fn secure_verify_aggregates(sig: &Self::InnerSig, msg: &Self::Msg, pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }

    let mut sorted: Vec<[u8; 48]> = pks.iter().map(|pk| Self::pk_to_bytes(pk)).collect();
    sorted.sort();

    let mut hasher = Sha256::new();
    for pk_bytes in &sorted {
      hasher.update(pk_bytes);
    }
    let pk_hash: [u8; 32] = hasher.finalize().into();

    let mut acc = G1::identity();

    for (i, pk_bytes) in sorted.iter().enumerate() {
      // weight = SHA256(i_as_4_bytes_be || pk_hash) mod order
      let mut weight_hasher = Sha256::new();
      let idx_bytes = (i as u32).to_be_bytes();
      weight_hasher.update(idx_bytes);
      weight_hasher.update(pk_hash);
      let weight_hash: [u8; 32] = weight_hasher.finalize().into();

      // blst_p1_mult reduces internally.
      let weight = blst_ffi::scalar_from_bendian(&weight_hash);

      let pk = Self::pk_from_bytes(pk_bytes)?;
      acc = acc + pk.to_projective().mul_scalar(&weight.b, 256);
    }

    let agg_pk = acc.to_affine();

    Self::verify(sig, msg, &agg_pk)
  }

  /// Lagrange-interpolate the share signatures in G2 at x=0.
  fn recover_sig_shares(ids: &[&Hash256], sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    if sigs.len() < 2 {
      return Err(BlsError::InsufficientShares);
    }

    // Reduce and validate ids in the scalar field, rejecting zero-reducing
    // and (post-reduction) duplicate ids.
    let reduced = scheme_ops::reduce_share_ids(ids)?;
    let points: Vec<_> = sigs.iter().map(|s| s.to_projective()).collect();

    let recovered = scheme_ops::interpolate_g2(&reduced, &points);
    Ok(recovered.to_affine())
  }

  /// Evaluate the master verification-vector polynomial in G1 at `id`.
  fn derive_pk_share(master_pks: &[&Self::InnerPk], id: &Hash256) -> Result<Self::InnerPk, BlsError> {
    // Evaluating the verification-vector polynomial needs >= 2 coefficients.
    if master_pks.len() < 2 {
      return Err(BlsError::InvalidVerificationVector);
    }
    let coeffs_g1: Vec<_> = master_pks.iter().map(|pk| pk.to_projective()).collect();

    let x = scheme_ops::reduce_id(id)?;
    let result = scheme_ops::eval_poly_g1(&coeffs_g1, &x);

    Ok(result.to_affine())
  }
}
