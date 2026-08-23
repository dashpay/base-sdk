//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The BLS12-381 groups G1 and G2.

use super::scalar::Fp2;

use blst::{blst_p1, blst_p1_affine, blst_p2, blst_p2_affine};
use dash_types::type_cvrt;
use dash_types::type_id::Unencodable;

use core::ops::Add;

/// A projective group element supporting curve addition and scalar multiply.
pub(crate) trait Point: Copy + Default + Add<Output = Self> {
  /// The group identity (point at infinity).
  fn identity() -> Self {
    Self::default()
  }

  /// Scalar multiplication by a little-endian scalar of `nbits` bits.
  fn mul_scalar(&self, scalar: &[u8], nbits: usize) -> Self;
}

/// A point of the G1 group (over `Fp`) in projective coordinates.
#[derive(Clone, Copy, Debug, Default, Unencodable)]
pub struct G1(pub(super) blst_p1);

type_cvrt!(From<G1> for blst_p1, |g| g.0);

type_cvrt!(From<blst_p1> for G1, |raw| Self(*raw));

/// A point of the G1 group in affine coordinates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Unencodable)]
pub struct G1Affine(pub(super) blst_p1_affine);

type_cvrt!(From<G1Affine> for blst_p1_affine, |a| a.0);

type_cvrt!(From<blst_p1_affine> for G1Affine, |raw| Self(*raw));

/// A point of the G2 group (over `Fp2`) in projective coordinates.
#[derive(Clone, Copy, Debug, Default, Unencodable)]
pub struct G2(pub(super) blst_p2);

type_cvrt!(From<blst_p2> for G2, |raw| Self(*raw));

type_cvrt!(From<G2> for blst_p2, |g| g.0);

/// A point of the G2 group in affine coordinates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Unencodable)]
pub struct G2Affine(pub(super) blst_p2_affine);

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
}

type_cvrt!(From<G2Affine> for blst_p2_affine, |a| a.0);

type_cvrt!(From<blst_p2_affine> for G2Affine, |raw| Self(*raw));
