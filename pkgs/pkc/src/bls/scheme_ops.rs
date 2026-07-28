//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar-field arithmetic and threshold helpers.

use super::blst_ffi::{self, Fr, Point, G1, G2};
use super::error::BlsError;
use crate::prelude::*;

use dash_num::Hash256;
use zeroize::{Zeroize, Zeroizing};

/// Sum secret key scalars (mod group order).
pub(crate) fn sum_sk_scalars(key_bytes: &[[u8; 32]]) -> Zeroizing<[u8; 32]> {
  let mut acc = Fr::default();
  for bytes in key_bytes {
    let mut scalar = blst_ffi::scalar_from_bendian(bytes);
    let mut term = Fr::from(&scalar);
    acc = acc + term;
    term.zeroize();
    scalar.b.zeroize();
  }
  let mut out_scalar = blst::blst_scalar::from(&acc);
  let out_bytes = Zeroizing::new(blst_ffi::bendian_from_scalar(&out_scalar));
  out_scalar.b.zeroize();
  acc.zeroize();
  out_bytes
}

/// A generated share: participant id paired with its secret scalar bytes,
/// zeroized on drop. A custom `Debug` redacts the secret scalar.
pub(crate) struct RawShare {
  /// Participant identifier.
  pub(crate) id: Hash256,
  /// Secret scalar bytes, zeroized on drop.
  pub(crate) secret: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for RawShare {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("RawShare")
      .field("id", &self.id)
      .field("secret", &"[redacted]")
      .finish()
  }
}

/// Generate secret key shares from a polynomial with the
/// given constant term. Returns a Vec of (id, share_bytes)
/// pairs.
pub(crate) fn generate_shares(
  sk_bytes: &[u8; 32],
  threshold: usize,
  ids: &[Hash256],
  rng: &mut impl rand_core::CryptoRngCore,
) -> Result<Vec<RawShare>, ()> {
  let mut coeffs = Zeroizing::new(Vec::with_capacity(threshold));

  let mut sk_scalar = blst_ffi::scalar_from_bendian(sk_bytes);
  coeffs.push(Fr::from(&sk_scalar));
  sk_scalar.b.zeroize();

  for _ in 1..threshold {
    // Generate random 32-byte IKM from CSPRNG
    let mut ikm = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *ikm);
    let rand_sk = blst::min_pk::SecretKey::key_gen_v3(ikm.as_ref(), &[]).map_err(|_| ())?;
    let mut rand_bytes = rand_sk.to_bytes();
    let mut rand_scalar = blst_ffi::scalar_from_bendian(&rand_bytes);
    coeffs.push(Fr::from(&rand_scalar));
    rand_bytes.zeroize();
    rand_scalar.b.zeroize();
  }

  let mut shares = Vec::with_capacity(ids.len());
  for id in ids {
    let x = fr_from_hash(id);
    let mut y = poly_eval(&coeffs, &x);

    let mut y_scalar = blst::blst_scalar::from(&y);
    let y_bytes = blst_ffi::bendian_from_scalar(&y_scalar);
    y_scalar.b.zeroize();
    y.zeroize();

    // Wrap so unprocessed shares still zeroize if a later caller step fails.
    shares.push(RawShare {
      id: *id,
      secret: Zeroizing::new(y_bytes),
    });
  }

  Ok(shares)
}

/// Evaluate a polynomial at `x`. Coefficients are in ascending order:
/// `coeffs[0] + coeffs[1]*x + ...`.
pub(crate) fn poly_eval(coeffs: &[Fr], x: &Fr) -> Fr {
  // Horner's method: result = c[n-1], then for each
  // i from n-2..=0: result = result*x + c[i].
  let n = coeffs.len();
  if n == 0 {
    return Fr::default();
  }
  let mut result = coeffs[n - 1];
  for i in (0..n - 1).rev() {
    result = result * *x + coeffs[i];
  }
  result
}

/// Recover a G2 point from shares via Lagrange interpolation at x=0.
///
/// `ids` and `points` must have the same length >= 1.
/// Each id must be non-zero and unique.
pub(crate) fn interpolate_g2(ids: &[Fr], points: &[G2]) -> G2 {
  let n = ids.len();

  // Compute Lagrange coefficients at x=0:
  //   L_i = prod_{j!=i} id_j / (id_j - id_i)
  let coeffs = compute_lagrange_coeffs(ids);

  let mut result = G2::identity();
  for i in 0..n {
    // Convert Fr coefficient to scalar for point multiplication.
    let scalar = blst::blst_scalar::from(&coeffs[i]);
    result = result + points[i].mul_scalar(&scalar.b, blst_ffi::FR_BITS);
  }
  result
}

/// Lagrange coefficients at x=0 for the given evaluation points (ids).
fn compute_lagrange_coeffs(ids: &[Fr]) -> Vec<Fr> {
  let n = ids.len();
  let mut coeffs = Vec::with_capacity(n);

  for i in 0..n {
    // L_i = prod_{j!=i} ids[j] / (ids[j] - ids[i])
    let mut num = Fr::one();
    let mut den = Fr::one();

    for j in 0..n {
      if i == j {
        continue;
      }
      // num *= ids[j]
      num = num * ids[j];

      // den *= (ids[j] - ids[i])
      let diff = ids[j] - ids[i];
      den = den * diff;
    }

    coeffs.push(num * den.inverse());
  }
  coeffs
}

/// Evaluate a polynomial of G1 points at scalar `x`.
///
/// `coeffs_g1[0] + coeffs_g1[1]*x + coeffs_g1[2]*x^2 + ...`
/// Uses Horner's method.
pub(crate) fn eval_poly_g1(coeffs_g1: &[G1], x: &Fr) -> G1 {
  let n = coeffs_g1.len();
  if n == 0 {
    return G1::identity();
  }
  let x_scalar = blst::blst_scalar::from(x);
  let mut result = coeffs_g1[n - 1];
  for i in (0..n - 1).rev() {
    result = result.mul_scalar(&x_scalar.b, blst_ffi::FR_BITS) + coeffs_g1[i];
  }
  result
}

/// Convert a 32-byte participant ID to a scalar.
pub(crate) fn fr_from_hash(id: &Hash256) -> Fr {
  Fr::from(&blst_ffi::scalar_from_bendian(id.as_bytes()))
}

/// Reduce a participant id into the scalar field, rejecting zero.
///
/// An id congruent to zero mod `r` evaluates the polynomial at its
/// constant term, which leaks the master secret in share generation.
pub(crate) fn reduce_id(id: &Hash256) -> Result<Fr, BlsError> {
  let fr = fr_from_hash(id);
  if blst::blst_scalar::from(&fr).b == [0u8; 32] {
    return Err(BlsError::InvalidShareId);
  }
  Ok(fr)
}

/// Reduce participant ids into the scalar field, rejecting ids that
/// reduce to zero and duplicates after reduction.
///
/// Two distinct hashes congruent mod `r` share a scalar, producing a
/// zero Lagrange denominator that blst inverts to zero silently; a
/// raw-byte duplicate check would not catch them.
pub(crate) fn reduce_share_ids(ids: &[&Hash256]) -> Result<Vec<Fr>, BlsError> {
  let fr_ids: Vec<Fr> = ids.iter().map(|id| fr_from_hash(id)).collect();
  let mut reduced: Vec<[u8; 32]> = Vec::with_capacity(fr_ids.len());
  for fr in &fr_ids {
    let bytes = blst::blst_scalar::from(fr).b;
    if bytes == [0u8; 32] {
      return Err(BlsError::InvalidShareId);
    }
    reduced.push(bytes);
  }
  reduced.sort_unstable();
  for pair in reduced.windows(2) {
    if pair[0] == pair[1] {
      return Err(BlsError::DuplicateShareId);
    }
  }
  Ok(fr_ids)
}
