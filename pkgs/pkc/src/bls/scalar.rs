//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The BLS12-381 scalar and base fields.

use blst::{blst_fp, blst_fp2, blst_fr};
use dash_types::type_cvrt;
use dash_types::type_id::Unencodable;
use zeroize::Zeroize;

use core::fmt;

/// Bit-length for scalars known to be reduced mod q (< 2^255).
pub(crate) const FR_BITS: usize = 255;

/// A scalar of the BLS12-381 scalar field, i.e. an integer reduced modulo the
/// group order `r`.
#[derive(Clone, Copy, Default)]
pub(crate) struct Fr(pub(super) blst_fr);

impl fmt::Debug for Fr {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Fr(..)")
  }
}

impl Zeroize for Fr {
  fn zeroize(&mut self) {
    self.0.l.zeroize();
  }
}

/// An element of the BLS12-381 base field, i.e. an integer reduced modulo the
/// field prime `p`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Unencodable)]
pub(crate) struct Fp(pub(super) blst_fp);

impl Fp {
  /// Construct from a `u64`, zero-extended into the low limbs.
  pub(crate) fn from_u64(v: u64) -> Self {
    let mut bytes = [0u8; 48];
    bytes[40..48].copy_from_slice(&v.to_be_bytes());
    Self::from(&bytes)
  }
}

type_cvrt!(From<Fp> for blst_fp, |fp| fp.0);

type_cvrt!(From<blst_fp> for Fp, |raw| Self(*raw));

/// An element of the quadratic extension field `Fp2 = Fp[u]/(u^2 + 1)`, written
/// `c0 + c1*u`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Unencodable)]
pub(crate) struct Fp2(pub(super) blst_fp2);

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

type_cvrt!(From<Fp> for Fp2, |fp| Self::new(*fp, Fp::default()));

type_cvrt!(From<Fp2> for blst_fp2, |fp2| fp2.0);

type_cvrt!(From<blst_fp2> for Fp2, |raw| Self(*raw));
