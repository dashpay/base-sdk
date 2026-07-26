//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Bridging routines for unsafe blst FFI operations.

use blst::*;
use dash_types::type_cvrt;
use zeroize::Zeroize;

use core::ops::{Add, Mul, Neg, Sub};
use core::ptr::null_mut;

/// Bit-length for scalars known to be reduced mod q (< 2^255).
pub(crate) const FR_BITS: usize = 255;

/// Serialize a scalar to its 32-byte big-endian encoding.
pub(crate) fn bendian_from_scalar(scalar: &blst_scalar) -> [u8; 32] {
  let mut out = [0u8; 32];
  unsafe { blst_bendian_from_scalar(out.as_mut_ptr(), scalar) };
  out
}

/// Pairing check `e(lhs_g2, G1) == e(rhs_g2, rhs_g1)`
pub(crate) fn pairings_equal_with_g1_generator(lhs_g2: &G2Affine, rhs_g2: &G2, rhs_g1: &G1Affine) -> bool {
  let lhs_g2_aff = blst_p2_affine::from(*lhs_g2);
  let rhs_g2_aff = blst_p2_affine::from(rhs_g2.to_affine());
  let rhs_g1_aff = blst_p1_affine::from(*rhs_g1);
  let g1_generator = blst_p1_affine::from(G1Affine::generator());
  let mut lhs = blst_fp12::default();
  let mut rhs = blst_fp12::default();
  unsafe {
    blst_miller_loop(&mut lhs, &lhs_g2_aff, &g1_generator);
    blst_miller_loop(&mut rhs, &rhs_g2_aff, &rhs_g1_aff);
    blst_fp12_finalverify(&lhs, &rhs)
  }
}

/// Interpret 32 big-endian bytes as a 256-bit scalar.
pub(crate) fn scalar_from_bendian(bytes: &[u8; 32]) -> blst_scalar {
  let mut scalar = blst_scalar::default();
  unsafe { blst_scalar_from_bendian(&mut scalar, bytes.as_ptr()) };
  scalar
}

/// Whether the scalar is a valid BLS secret key, i.e. non-zero and less
/// than the group order.
pub(crate) fn sk_check(sk: &blst_scalar) -> bool {
  unsafe { blst_sk_check(sk) }
}

/// Derive the G1 public key `sk * G1_generator` for a secret-key scalar.
pub(crate) fn sk_to_pk2_in_g1(sk: &blst_scalar) -> G1Affine {
  let mut aff = blst_p1_affine::default();
  unsafe { blst_sk_to_pk2_in_g1(null_mut(), &mut aff, sk) };
  aff.into()
}

/// A scalar of the BLS12-381 scalar field, i.e. an integer reduced modulo the
/// group order `r`.
#[derive(Clone, Copy, Default)]
pub(crate) struct Fr(blst_fr);

impl Fr {
  /// Multiplicative inverse; the inverse of zero is left unspecified.
  pub(crate) fn inverse(&self) -> Self {
    let mut out = blst_fr::default();
    unsafe { blst_fr_inverse(&mut out, &self.0) };
    Self(out)
  }

  /// The multiplicative identity, one.
  pub(crate) fn one() -> Self {
    let mut out = blst_fr::default();
    let one = [1u64, 0, 0, 0];
    unsafe { blst_fr_from_uint64(&mut out, one.as_ptr()) };
    Self(out)
  }
}

impl Add for Fr {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    let mut out = blst_fr::default();
    unsafe { blst_fr_add(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Mul for Fr {
  type Output = Self;

  fn mul(self, rhs: Self) -> Self::Output {
    let mut out = blst_fr::default();
    unsafe { blst_fr_mul(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Neg for Fr {
  type Output = Self;

  fn neg(self) -> Self::Output {
    let mut out = blst_fr::default();
    unsafe { blst_fr_cneg(&mut out, &self.0, true) };
    Self(out)
  }
}

impl Sub for Fr {
  type Output = Self;

  fn sub(self, rhs: Self) -> Self::Output {
    let mut out = blst_fr::default();
    unsafe { blst_fr_sub(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Zeroize for Fr {
  fn zeroize(&mut self) {
    self.0.l.zeroize();
  }
}

type_cvrt!(From<blst_scalar> for Fr, |s| {
  let mut out = blst_fr::default();
  unsafe { blst_fr_from_scalar(&mut out, s) };
  Self(out)
});

type_cvrt!(From<Fr> for blst_scalar, |fr| {
  let mut out = blst_scalar::default();
  unsafe { blst_scalar_from_fr(&mut out, &fr.0) };
  out
});

/// An element of the BLS12-381 base field, i.e. an integer reduced
/// modulo the field prime `p`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Fp(blst_fp);

impl Fp {
  /// Construct from a `u64`, zero-extended into the low limbs.
  pub(crate) fn from_u64(v: u64) -> Self {
    let mut bytes = [0u8; 48];
    bytes[40..48].copy_from_slice(&v.to_be_bytes());
    Self::from(&bytes)
  }
}

impl Add for Fp {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp::default();
    unsafe { blst_fp_add(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Mul for Fp {
  type Output = Self;

  fn mul(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp::default();
    unsafe { blst_fp_mul(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Neg for Fp {
  type Output = Self;

  fn neg(self) -> Self::Output {
    let mut out = blst_fp::default();
    unsafe { blst_fp_cneg(&mut out, &self.0, true) };
    Self(out)
  }
}

impl Sub for Fp {
  type Output = Self;

  fn sub(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp::default();
    unsafe { blst_fp_sub(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

type_cvrt!(From<Fp> for [u8; 48], |fp| {
  let mut out = [0u8; 48];
  unsafe { blst_bendian_from_fp(out.as_mut_ptr(), &fp.0) };
  out
});

type_cvrt!(From<[u8; 48]> for Fp, |bytes| {
  let mut out = blst_fp::default();
  unsafe { blst_fp_from_bendian(&mut out, bytes.as_ptr()) };
  Self(out)
});

type_cvrt!(From<Fp> for blst_fp, |fp| fp.0);

type_cvrt!(From<blst_fp> for Fp, |raw| Self(*raw));

type_cvrt!(From<Fp> for Fp2, |fp| Self::new(*fp, Fp::default()));

/// An element of the quadratic extension field `Fp2 = Fp[u]/(u^2 + 1)`,
/// written `c0 + c1*u`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Fp2(blst_fp2);

impl Fp2 {
  /// The `c0` (real) component.
  pub(crate) fn c0(&self) -> Fp {
    Fp::from(self.0.fp[0])
  }

  /// The `c1` (coefficient of `u`) component.
  pub(crate) fn c1(&self) -> Fp {
    Fp::from(self.0.fp[1])
  }

  /// Big-endian byte encoding of the `c1` component.
  pub(crate) fn c1_bendian(&self) -> [u8; 48] {
    <[u8; 48]>::from(self.c1())
  }

  /// Multiplicative inverse; the inverse of zero is left unspecified.
  pub(crate) fn inverse(&self) -> Self {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_inverse(&mut out, &self.0) };
    Self(out)
  }

  /// Whether both components are zero.
  pub(crate) fn is_zero(&self) -> bool {
    self.0.fp[0].l == [0u64; 6] && self.0.fp[1].l == [0u64; 6]
  }

  /// Construct from the two base-field components `c0` and `c1`.
  pub(crate) fn new(c0: Fp, c1: Fp) -> Self {
    Self(blst_fp2 {
      fp: [c0.into(), c1.into()],
    })
  }

  /// A square root, or `None` when the value is not a quadratic residue.
  pub(crate) fn sqrt(&self) -> Option<Self> {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_sqrt(&mut out, &self.0) }.then_some(Self(out))
  }

  /// The square of this element.
  pub(crate) fn square(&self) -> Self {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_sqr(&mut out, &self.0) };
    Self(out)
  }

  /// Return a copy with the `c0` component replaced.
  pub(crate) fn with_c0(mut self, c0: Fp) -> Self {
    self.0.fp[0] = c0.into();
    self
  }

  /// Return a copy with the `c1` component replaced.
  pub(crate) fn with_c1(mut self, c1: Fp) -> Self {
    self.0.fp[1] = c1.into();
    self
  }
}

impl Add for Fp2 {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_add(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Mul for Fp2 {
  type Output = Self;

  fn mul(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_mul(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Neg for Fp2 {
  type Output = Self;

  fn neg(self) -> Self::Output {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_cneg(&mut out, &self.0, true) };
    Self(out)
  }
}

impl Sub for Fp2 {
  type Output = Self;

  fn sub(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_sub(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

type_cvrt!(From<Fp2> for blst_fp2, |fp2| fp2.0);

type_cvrt!(From<blst_fp2> for Fp2, |raw| Self(*raw));

/// A projective group element supporting curve addition and scalar
/// multiplication.
pub(crate) trait Point: Copy + Default + Add<Output = Self> {
  /// The group identity (point at infinity).
  fn identity() -> Self {
    Self::default()
  }

  /// Scalar multiplication by a little-endian scalar of `nbits` bits.
  fn mul_scalar(&self, scalar: &[u8], nbits: usize) -> Self;
}

/// A point of the G1 group (over `Fp`) in projective coordinates,
/// suitable for accumulation before a single conversion to affine.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct G1(blst_p1);

impl G1 {
  /// Convert to affine coordinates.
  pub(crate) fn to_affine(self) -> G1Affine {
    let mut aff = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut aff, &self.0) };
    G1Affine(aff)
  }
}

impl Add for G1 {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    let mut out = blst_p1::default();
    unsafe { blst_p1_add_or_double(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Point for G1 {
  fn mul_scalar(&self, scalar: &[u8], nbits: usize) -> Self {
    // Clamp to the bits actually backed by the slice: blst reads
    // ceil(nbits/8) bytes, so a larger nbits would read out of bounds.
    let nbits = nbits.min(scalar.len() * 8);
    let mut out = blst_p1::default();
    unsafe { blst_p1_mult(&mut out, &self.0, scalar.as_ptr(), nbits) };
    Self(out)
  }
}

type_cvrt!(From<G1> for blst_p1, |g| g.0);

type_cvrt!(From<blst_p1> for G1, |raw| Self(*raw));

/// A point of the G1 group in affine coordinates, the canonical form
/// used for serialization and pairing inputs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct G1Affine(blst_p1_affine);

impl G1Affine {
  /// The conventional G1 generator.
  pub(crate) fn generator() -> Self {
    Self(unsafe { *blst_p1_affine_generator() })
  }

  /// Convert to projective coordinates.
  pub(crate) fn to_projective(self) -> G1 {
    let mut out = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut out, &self.0) };
    G1(out)
  }

  /// Serialize to the 48-byte compressed encoding.
  pub(crate) fn compress(&self) -> [u8; 48] {
    let mut out = [0u8; 48];
    unsafe { blst_p1_affine_compress(out.as_mut_ptr(), &self.0) };
    out
  }

  /// Scalar multiplication via the projective representation.
  pub(crate) fn mul_scalar(&self, scalar: &[u8], nbits: usize) -> Self {
    self.to_projective().mul_scalar(scalar, nbits).to_affine()
  }

  /// Uncompress a 48-byte G1 point.
  ///
  /// # Errors
  ///
  /// Returns the blst error code when the bytes do not encode a valid
  /// compressed G1 point.
  pub(crate) fn uncompress(bytes: &[u8; 48]) -> Result<Self, BLST_ERROR> {
    let mut aff = blst_p1_affine::default();
    let rc = unsafe { blst_p1_uncompress(&mut aff, bytes.as_ptr()) };
    if rc != BLST_ERROR::BLST_SUCCESS {
      return Err(rc);
    }
    Ok(Self(aff))
  }
}

type_cvrt!(From<G1Affine> for blst_p1_affine, |a| a.0);

type_cvrt!(From<blst_p1_affine> for G1Affine, |raw| Self(*raw));

/// A point of the G2 group (over `Fp2`) in projective coordinates,
/// suitable for accumulation before a single conversion to affine.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct G2(blst_p2);

impl G2 {
  /// The conventional G2 generator.
  pub(crate) fn generator() -> Self {
    Self(unsafe { *blst_p2_generator() })
  }

  /// Point doubling.
  pub(crate) fn double(&self) -> Self {
    let mut out = blst_p2::default();
    unsafe { blst_p2_double(&mut out, &self.0) };
    Self(out)
  }

  /// Convert to affine coordinates.
  pub(crate) fn to_affine(self) -> G2Affine {
    let mut aff = blst_p2_affine::default();
    unsafe { blst_p2_to_affine(&mut aff, &self.0) };
    G2Affine(aff)
  }
}

impl Add for G2 {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    let mut out = blst_p2::default();
    unsafe { blst_p2_add_or_double(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Neg for G2 {
  type Output = Self;

  fn neg(self) -> Self::Output {
    let mut out = self.0;
    unsafe { blst_p2_cneg(&mut out, true) };
    Self(out)
  }
}

impl Point for G2 {
  fn mul_scalar(&self, scalar: &[u8], nbits: usize) -> Self {
    // Clamp to the bits actually backed by the slice: blst reads
    // ceil(nbits/8) bytes, so a larger nbits would read out of bounds.
    let nbits = nbits.min(scalar.len() * 8);
    let mut out = blst_p2::default();
    unsafe { blst_p2_mult(&mut out, &self.0, scalar.as_ptr(), nbits) };
    Self(out)
  }
}

type_cvrt!(From<blst_p2> for G2, |raw| Self(*raw));

type_cvrt!(From<G2> for blst_p2, |g| g.0);

/// A point of the G2 group in affine coordinates, the canonical form
/// used for serialization and pairing inputs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct G2Affine(blst_p2_affine);

impl G2Affine {
  /// Construct from affine `x` and `y` coordinates in `Fp2`.
  pub(crate) fn from_coords(x: Fp2, y: Fp2) -> Self {
    Self(blst_p2_affine {
      x: x.into(),
      y: y.into(),
    })
  }

  /// The affine `x` coordinate.
  pub(crate) fn x(&self) -> Fp2 {
    Fp2::from(self.0.x)
  }

  /// The affine `y` coordinate.
  pub(crate) fn y(&self) -> Fp2 {
    Fp2::from(self.0.y)
  }

  /// Convert to projective coordinates.
  pub(crate) fn to_projective(self) -> G2 {
    let mut out = blst_p2::default();
    unsafe { blst_p2_from_affine(&mut out, &self.0) };
    G2(out)
  }

  /// Serialize to the 96-byte compressed encoding.
  pub(crate) fn compress(&self) -> [u8; 96] {
    let mut out = [0u8; 96];
    unsafe { blst_p2_affine_compress(out.as_mut_ptr(), &self.0) };
    out
  }

  /// Serialize to the 192-byte uncompressed encoding.
  pub(crate) fn serialize(&self) -> [u8; 192] {
    let mut out = [0u8; 192];
    unsafe { blst_p2_affine_serialize(out.as_mut_ptr(), &self.0) };
    out
  }

  /// Uncompress a 96-byte G2 point.
  ///
  /// # Errors
  ///
  /// Returns the blst error code when the bytes do not encode a valid
  /// compressed G2 point.
  pub(crate) fn uncompress(bytes: &[u8; 96]) -> Result<Self, BLST_ERROR> {
    let mut aff = blst_p2_affine::default();
    let rc = unsafe { blst_p2_uncompress(&mut aff, bytes.as_ptr()) };
    if rc != BLST_ERROR::BLST_SUCCESS {
      return Err(rc);
    }
    Ok(Self(aff))
  }
}

type_cvrt!(From<G2Affine> for blst_p2_affine, |a| a.0);

type_cvrt!(From<blst_p2_affine> for G2Affine, |raw| Self(*raw));
