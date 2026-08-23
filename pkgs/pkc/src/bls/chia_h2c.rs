//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shallue-van de Woestijne hash-to-G2 for legacy BLS.

use super::blst_ffi::{G2Affine, Point, G2};
use super::curve_consts::{
  BLS_X_BITS, BLS_X_LE, MONT_R_MOD_P, PSI_COEFF_X_C1, PSI_COEFF_Y_C0, PSI_COEFF_Y_C1, S3, S32,
};
use super::scalar::{Fp, Fp2};

use sha2::{Digest, Sha256};

// The 'b' coefficient for BLS12-381 twist curve: y^2 = x^3 + 4(1+i).
fn curve_b() -> Fp2 {
  Fp2::new(Fp::from_u64(4), Fp::from_u64(4))
}

/// Hash a 32-byte message to a G2 point using the legacy Dash algorithm.
pub(crate) fn hash_to_g2(msg: &[u8; 32]) -> G2 {
  // Step 1: derive four field elements via SHA-256 with domain prefixes.
  let t00 = hash_to_fp(msg, b"G2_0_c0");
  let t01 = hash_to_fp(msg, b"G2_0_c1");
  let t10 = hash_to_fp(msg, b"G2_1_c0");
  let t11 = hash_to_fp(msg, b"G2_1_c1");

  // Step 2: form two Fp2 elements.
  let t0 = Fp2::new(t00, t01);
  let t1 = Fp2::new(t10, t11);

  // Step 3: apply Shallue-van de Woestijne encoding to each.
  let p0 = sw_encode(&t0);
  let p1 = sw_encode(&t1);

  // Step 4: add the two points.
  let sum = p0 + p1;

  // Step 5: clear the cofactor via Budroni-Pintore.
  mul_cof_b12(&sum)
}

/// Cofactor clearing via the Budroni-Pintore method.
///
/// Computes `(x^2-x-1)*P + psi((x-1)*P) + psi^2(2*P)` where `x` is the
/// BLS12-381 curve parameter and `psi` is the Frobenius endomorphism on the
/// twist.
fn mul_cof_b12(p: &G2) -> G2 {
  // t0 = x·P  (x is negative, so negate after multiplying by |x|)
  let t0 = -p.mul_scalar(&BLS_X_LE, BLS_X_BITS);

  // t1 = x²·P = x·t0
  let t1 = -t0.mul_scalar(&BLS_X_LE, BLS_X_BITS);

  // t2 = (x^2 - x - 1)*P = t1 - t0 - P
  let t2 = t1 + (-t0) + (-*p);

  // t2 += psi((x - 1)*P) = psi(t0 - P)
  let t2 = t2 + psi_g2(&(t0 + (-*p)));

  // t3 = psi^2(2*P)
  let dbl = p.double();
  let t3 = psi_g2(&psi_g2(&dbl));

  // result = t2 + t3
  t2 + t3
}

/// Frobenius endomorphism psi on E'(Fp2).
///
/// `psi(x, y) = (conj(x) * PSI_COEFF_X, conj(y) * PSI_COEFF_Y)` where
/// `conj(a + b*u) = a - b*u`.
fn psi(p: &G2Affine) -> G2Affine {
  // Conjugate x and y (negate the c1 component of each).
  let x = p.x().with_c1(-p.x().c1());
  let y = p.y().with_c1(-p.y().c1());

  // Multiply by the Frobenius coefficients.
  G2Affine::from_coords(x * psi_coeff_x(), y * psi_coeff_y())
}

fn psi_coeff_x() -> Fp2 {
  // PSI_COEFF_X = (0, PSI_COEFF_X_C1)
  Fp2::new(Fp::default(), Fp::from(&PSI_COEFF_X_C1))
}

fn psi_coeff_y() -> Fp2 {
  Fp2::new(Fp::from(&PSI_COEFF_Y_C0), Fp::from(&PSI_COEFF_Y_C1))
}

/// Apply the Frobenius endomorphism `psi` to a projective G2 point,
/// normalizing through affine coordinates.
fn psi_g2(p: &G2) -> G2 {
  psi(&p.to_affine()).to_projective()
}

/// Hash `msg || tag || suffix` with SHA-256 twice (suffix=0 then suffix=1),
/// concatenate to 64 bytes, reduce mod p to produce an Fp element.
fn hash_to_fp(msg: &[u8; 32], tag: &[u8; 7]) -> Fp {
  let mut input = [0u8; 40];
  input[..32].copy_from_slice(msg);
  input[32..39].copy_from_slice(tag);

  input[39] = 0;
  let h0 = Sha256::digest(input);

  input[39] = 1;
  let h1 = Sha256::digest(input);

  let mut wide = [0u8; 64];
  wide[..32].copy_from_slice(&h0);
  wide[32..].copy_from_slice(&h1);

  reduce_mod_p(&wide)
}

/// Reduce a 64-byte big-endian integer mod p to Fp.
///
/// Splits into `hi * 2^384 + lo`, computes `hi * R + lo` where
/// `R = 2^384 mod p`.
fn reduce_mod_p(wide: &[u8; 64]) -> Fp {
  let mut lo_bytes = [0u8; 48];
  lo_bytes.copy_from_slice(&wide[16..]);
  let lo_fp = Fp::from(&lo_bytes);

  let mut hi_bytes = [0u8; 48];
  hi_bytes[32..48].copy_from_slice(&wide[..16]);
  let hi_fp = Fp::from(&hi_bytes);
  let r_fp = Fp::from(&MONT_R_MOD_P);

  // result = hi * R + lo
  hi_fp * r_fp + lo_fp
}

/// Shallue-van de Woestijne encoding from Fp2 to G2 (not cofactor-cleared).
fn sw_encode(t: &Fp2) -> G2 {
  if t.is_zero() {
    return G2::default();
  }

  let b = curve_b();
  let one = Fp::from_u64(1);

  let nt = -*t;
  let parity = t.c1_bendian() > nt.c1_bendian();

  // w = t^2 + b + 1
  let mut w = t.square() + b;
  w = w.with_c0(w.c0() + one);

  if w.is_zero() {
    let mut g = G2::generator();
    if parity {
      g = -g;
    }
    return g;
  }

  let s3_fp2 = Fp2::from(Fp::from(&S3));
  let s32_fp2 = Fp2::from(Fp::from(&S32));

  // w = sqrt(-3) * t / (t^2 + b + 1)
  w = w.inverse();
  let tmp = s3_fp2 * *t;
  w = w * tmp;

  // x1 = -w*t + (sqrt(-3) - 1) / 2
  let x1 = -(w * *t) + s32_fp2;

  // x2 = -x1 - 1
  let mut x2 = -x1;
  x2 = x2.with_c0(x2.c0() - one);

  // x3 = 1/w^2 + 1
  let mut x3 = w.square().inverse();
  x3 = x3.with_c0(x3.c0() + one);

  let rhs1 = curve_rhs(&x1);
  let rhs2 = curve_rhs(&x2);

  let y1 = rhs1.sqrt();
  let y2 = rhs2.sqrt();

  let has_y1 = y1.is_some();
  let has_y2 = y2.is_some();

  let xx1: i32 = if has_y1 { 1 } else { -1 };
  let xx2: i32 = if has_y2 { 1 } else { -1 };
  let index = (((xx1 - 1) * xx2) % 3 + 3) % 3;

  // `index` selects an x whose curve RHS is a quadratic residue, so the sqrt
  // always succeeds; the zero fallback is unreachable but avoids an unwrap panic.
  let (x, mut y) = if index == 0 {
    let y = y1.unwrap_or_default();
    (x1, y)
  } else if index == 1 {
    let y = y2.unwrap_or_default();
    (x2, y)
  } else {
    let rhs = curve_rhs(&x3);
    let y = rhs.sqrt().unwrap_or_default();
    (x3, y)
  };

  let ny = -y;
  let y_parity = y.c1_bendian() > ny.c1_bendian();
  if y_parity != parity {
    y = ny;
  }

  G2Affine::from_coords(x, y).to_projective()
}

/// x^3 + b
fn curve_rhs(x: &Fp2) -> Fp2 {
  let b = curve_b();
  let x2 = x.square();
  let x3 = x2 * *x;
  x3 + b
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::prelude::*;

  use dash_dev::{arr_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct HashVector {
    msg: String,
    t00_hash: String,
    t01_hash: String,
    t10_hash: String,
    t11_hash: String,
    t00_fp: String,
    t01_fp: String,
    t10_fp: String,
    t11_fp: String,
  }

  #[test]
  fn hash_to_fp_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_hash");
    let vecs: Vec<HashVector> = corpus.vectors("chia");

    for v in &vecs {
      let msg: [u8; 32] = arr_from_hex(&v.msg);
      for (tag, hash_hex, fp_hex) in [
        (b"G2_0_c0", &v.t00_hash, &v.t00_fp),
        (b"G2_0_c1", &v.t01_hash, &v.t01_fp),
        (b"G2_1_c0", &v.t10_hash, &v.t10_fp),
        (b"G2_1_c1", &v.t11_hash, &v.t11_fp),
      ] {
        // SHA-256(msg || tag || 0) || SHA-256(msg || tag || 1).
        let mut input = [0u8; 40];
        input[..32].copy_from_slice(&msg);
        input[32..39].copy_from_slice(tag);
        input[39] = 0;
        let h0 = Sha256::digest(input);
        input[39] = 1;
        let h1 = Sha256::digest(input);
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&h0);
        concat[32..].copy_from_slice(&h1);
        assert_eq!(concat.to_lower_hex_string(), *hash_hex);

        // reduce the 64-byte hash mod p to a field element.
        let out = <[u8; 48]>::from(hash_to_fp(&msg, tag));
        assert_eq!(out.to_lower_hex_string(), *fp_hex);
      }
    }
  }
}
