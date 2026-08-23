//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The BLS12-381 scalar and base fields.

use super::curve_consts;

use blst::{blst_fp, blst_fp2, blst_fr};
use dash_types::type_cvrt;
use dash_types::type_id::Unencodable;
use ff::helpers::{sqrt_ratio_generic, sqrt_tonelli_shanks};
use ff::{Field, PrimeField};
use rand_core::TryRng;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

use core::fmt;
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

/// Bit-length for scalars known to be reduced mod q (< 2^255).
pub(crate) const FR_BITS: usize = 255;

/// Width of the canonical scalar encoding.
const REPR_LEN: usize = 32;

/// Bytes drawn per uniform sample, wide enough that reduction is unbiased.
const WIDE_LEN: usize = 64;

/// A scalar of the BLS12-381 scalar field, i.e. an integer reduced modulo the
/// group order `r`.
#[derive(Clone, Copy, Default)]
pub struct Fr(pub(super) blst_fr);

impl Fr {
  /// Wraps Montgomery-form limbs.
  pub(crate) const fn from_limbs(limbs: [u64; 4]) -> Self {
    Self(blst_fr { l: limbs })
  }

  /// Borrows the Montgomery-form limbs.
  pub(crate) const fn limbs(&self) -> &[u64; 4] {
    &self.0.l
  }
}

impl<'a> Add<&'a Self> for Fr {
  type Output = Self;

  fn add(self, rhs: &'a Self) -> Self::Output {
    self + *rhs
  }
}

impl AddAssign for Fr {
  fn add_assign(&mut self, rhs: Self) {
    *self = *self + rhs;
  }
}

impl<'a> AddAssign<&'a Self> for Fr {
  fn add_assign(&mut self, rhs: &'a Self) {
    *self = *self + *rhs;
  }
}

impl ConditionallySelectable for Fr {
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    let mut out = [0u64; 4];
    for (slot, (x, y)) in out.iter_mut().zip(a.limbs().iter().zip(b.limbs())) {
      *slot = u64::conditional_select(x, y, choice);
    }
    Self::from_limbs(out)
  }
}

impl ConstantTimeEq for Fr {
  fn ct_eq(&self, other: &Self) -> Choice {
    self.limbs().ct_eq(other.limbs())
  }
}

impl fmt::Debug for Fr {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Fr(..)")
  }
}

impl Eq for Fr {}

impl Field for Fr {
  const ONE: Self = curve_consts::ONE;
  const ZERO: Self = curve_consts::ZERO;

  fn double(&self) -> Self {
    Fr::double(self)
  }

  fn invert(&self) -> CtOption<Self> {
    CtOption::new(self.inverse(), !self.is_zero())
  }

  /// Overriding this is mandatory, not stylistic: `ff` implements `sqrt` in
  /// terms of `sqrt_ratio`, so leaving the default beside a `sqrt_ratio` built
  /// from `sqrt_ratio_generic` puts the two in a recursive cycle.
  fn sqrt(&self) -> CtOption<Self> {
    sqrt_tonelli_shanks(self, curve_consts::T_MINUS_1_DIV_2)
  }

  fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
    sqrt_ratio_generic(num, div)
  }

  fn square(&self) -> Self {
    Fr::square(self)
  }

  fn try_random<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
    let mut wide = [0u8; WIDE_LEN];
    rng.try_fill_bytes(&mut wide)?;
    let sampled = Self::from_lendian_reduce(&wide);
    wide.zeroize();
    Ok(sampled)
  }
}

impl From<u64> for Fr {
  fn from(value: u64) -> Self {
    Self::from_u64(value)
  }
}

impl<'a> Mul<&'a Self> for Fr {
  type Output = Self;

  fn mul(self, rhs: &'a Self) -> Self::Output {
    self * *rhs
  }
}

impl MulAssign for Fr {
  fn mul_assign(&mut self, rhs: Self) {
    *self = *self * rhs;
  }
}

impl<'a> MulAssign<&'a Self> for Fr {
  fn mul_assign(&mut self, rhs: &'a Self) {
    *self = *self * *rhs;
  }
}

impl PartialEq for Fr {
  fn eq(&self, other: &Self) -> bool {
    self.ct_eq(other).into()
  }
}

impl PrimeField for Fr {
  type Repr = [u8; REPR_LEN];

  const CAPACITY: u32 = Self::NUM_BITS - 1;
  const DELTA: Self = curve_consts::DELTA;
  const MODULUS: &'static str = curve_consts::MODULUS;
  const MULTIPLICATIVE_GENERATOR: Self = curve_consts::MULTIPLICATIVE_GENERATOR;
  const NUM_BITS: u32 = FR_BITS as u32;
  const ROOT_OF_UNITY: Self = curve_consts::ROOT_OF_UNITY;
  const ROOT_OF_UNITY_INV: Self = curve_consts::ROOT_OF_UNITY_INV;
  const S: u32 = curve_consts::S;
  const TWO_INV: Self = curve_consts::TWO_INV;

  fn from_repr(repr: Self::Repr) -> CtOption<Self> {
    match Self::from_lendian(&repr) {
      Some(fr) => CtOption::new(fr, Choice::from(1)),
      None => CtOption::new(Self::ZERO, Choice::from(0)),
    }
  }

  fn is_odd(&self) -> Choice {
    Choice::from(self.to_repr()[0] & 1)
  }

  fn to_repr(&self) -> Self::Repr {
    *self.to_lendian()
  }
}

impl<'a> Product<&'a Self> for Fr {
  fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
    iter.fold(Self::ONE, |acc, x| acc * x)
  }
}

impl Product for Fr {
  fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
    iter.fold(Self::ONE, |acc, x| acc * x)
  }
}

impl<'a> Sub<&'a Self> for Fr {
  type Output = Self;

  fn sub(self, rhs: &'a Self) -> Self::Output {
    self - *rhs
  }
}

impl SubAssign for Fr {
  fn sub_assign(&mut self, rhs: Self) {
    *self = *self - rhs;
  }
}

impl<'a> SubAssign<&'a Self> for Fr {
  fn sub_assign(&mut self, rhs: &'a Self) {
    *self = *self - *rhs;
  }
}

impl<'a> Sum<&'a Self> for Fr {
  fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
    iter.fold(Self::ZERO, |acc, x| acc + x)
  }
}

impl Sum for Fr {
  fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
    iter.fold(Self::ZERO, |acc, x| acc + x)
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

#[cfg(test)]
mod tests {
  use super::*;

  use getrandom::SysRng;
  use rand_core::UnwrapErr;
  use rstest::rstest;

  #[rstest]
  fn repr_round_trips_and_rejects_the_order() {
    let x = Fr::random(&mut UnwrapErr(SysRng));
    assert_eq!(Fr::from_repr(x.to_repr()).unwrap(), x);

    // The order itself is the least non-canonical encoding.
    let mut order = (-Fr::ONE).to_repr();
    order[0] += 1;
    assert!(bool::from(Fr::from_repr(order).is_none()));
  }

  /// The encoding is little-endian, which the round trip alone cannot tell
  /// apart from big-endian.
  #[rstest]
  fn repr_is_little_endian() {
    assert_eq!(Fr::from(1).to_repr()[0], 1);
    assert_eq!(Fr::from(1).to_repr()[REPR_LEN - 1], 0);
  }

  #[rstest]
  fn arithmetic_agrees_with_the_field_axioms() {
    let mut rng = UnwrapErr(SysRng);
    let a = Fr::random(&mut rng);
    let b = Fr::random(&mut rng);

    assert_eq!(a + b, b + a);
    assert_eq!(a - a, Fr::ZERO);
    assert_eq!(a + a, a.double());
    assert_eq!(a * a, a.square());
    assert_eq!(a * b * b.invert().unwrap(), a);
    assert_eq!(-a + a, Fr::ZERO);
  }

  /// Both halves of the square-root path at once: `sqrt` drives the exponent
  /// above and `sqrt_ratio` drives `ff`'s generic form off the constants.
  #[rstest]
  fn square_roots_recover_the_square() {
    let a = Fr::random(&mut UnwrapErr(SysRng));
    let root = a.square().sqrt().unwrap();
    assert!(root == a || root == -a);

    let (is_square, root) = Fr::sqrt_ratio(&a.square(), &Fr::ONE);
    assert!(bool::from(is_square));
    assert!(root == a || root == -a);

    // A non-residue: the generator is one by construction.
    assert!(bool::from(Fr::MULTIPLICATIVE_GENERATOR.sqrt().is_none()));
  }

  #[rstest]
  fn is_odd_reads_the_low_bit() {
    assert!(bool::from(Fr::from(3).is_odd()));
    assert!(bool::from(Fr::from(4).is_even()));
  }
}
