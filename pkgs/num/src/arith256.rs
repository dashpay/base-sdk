//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! 256-bit unsigned arithmetic integer.

use crate::Hash256;

use ambassador::{delegatable_trait_remote, Delegate};
use bitcoin_internals::u256::U256;
use dash_types::{type_cvrt, Numeric, ParseHexError};

use core::fmt::{self, LowerHex, UpperHex};
use core::ops::{
  Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign, Mul, MulAssign, Neg,
  Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};
use core::str::FromStr;

#[delegatable_trait_remote]
trait LowerHex {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

#[delegatable_trait_remote]
trait UpperHex {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

/// 256-bit unsigned arithmetic integer.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Delegate)]
#[delegate(LowerHex)]
#[delegate(UpperHex)]
#[cfg_attr(
  feature = "serde",
  derive(::serde::Serialize, ::serde::Deserialize),
  serde(from = "Hash256", into = "Hash256")
)]
pub struct Arith256(U256);

impl Numeric for Arith256 {
  type Base = [u8; 32];

  type Bytes = [u8; 32];

  const ZERO: Self = Self(U256::ZERO);

  #[inline]
  fn from_base(v: [u8; 32]) -> Self {
    Self::from_lendian(v)
  }

  #[inline]
  fn to_base(&self) -> [u8; 32] {
    self.to_lendian()
  }

  #[inline]
  fn from_lendian(bytes: [u8; 32]) -> Self {
    Self(U256::from_le_bytes(bytes))
  }

  #[inline]
  fn to_lendian(&self) -> [u8; 32] {
    self.0.to_le_bytes()
  }

  #[inline]
  fn from_bendian(bytes: [u8; 32]) -> Self {
    Self(U256::from_be_bytes(bytes))
  }

  #[inline]
  fn to_bendian(&self) -> [u8; 32] {
    self.0.to_be_bytes()
  }
}

impl Arith256 {
  /// The multiplicative identity.
  pub const ONE: Self = Self(U256::ONE);
  /// The largest representable value (all bits set).
  pub const MAX: Self = Self(U256::MAX);
  /// Create from a `u64`, zero-extending the upper bits.
  #[inline]
  pub fn from_u64(v: u64) -> Self {
    Self(U256::from(v))
  }

  /// Create from a `u128`, zero-extending the upper bits.
  #[inline]
  pub fn from_u128(v: u128) -> Self {
    Self(U256::from(v))
  }

  /// Construct from big-endian bytes (consensus display order).
  ///
  /// This is the natural byte order produced by `hex_conservative::hex!()` when
  /// given a consensus hex value.
  ///
  /// Shadows [`Numeric::from_bendian`] with a `const` form.
  #[inline]
  pub const fn from_bendian(be: [u8; 32]) -> Self {
    let mut high = [0u8; 16];
    let mut low = [0u8; 16];
    let mut i = 0;
    while i < 16 {
      high[i] = be[i];
      low[i] = be[i + 16];
      i += 1;
    }
    Self(U256::new(u128::from_be_bytes(high), u128::from_be_bytes(low)))
  }

  /// Returns the lowest 32 bits of the value.
  #[inline]
  pub fn low_u32(self) -> u32 {
    self.0.low_u32()
  }

  /// Returns the lowest 64 bits of the value.
  #[inline]
  pub fn low_u64(self) -> u64 {
    self.0.low_u64()
  }

  /// Returns the lowest 128 bits of the value.
  #[inline]
  pub fn low_u128(self) -> u128 {
    self.limbs().1
  }

  /// Saturating conversion to u128. Returns u128::MAX if value exceeds 128
  /// bits.
  #[inline]
  pub fn saturating_to_u128(self) -> u128 {
    self.0.saturating_to_u128()
  }

  /// Highest set bit position plus one, or zero if zero.
  #[inline]
  pub fn bits(self) -> u32 {
    self.0.bits()
  }

  /// Wrapping addition.
  #[inline]
  pub fn wrapping_add(self, rhs: Self) -> Self {
    Self(self.0.wrapping_add(rhs.0))
  }

  /// Wrapping subtraction.
  #[inline]
  pub fn wrapping_sub(self, rhs: Self) -> Self {
    Self(self.0.wrapping_sub(rhs.0))
  }

  /// Wrapping multiply.
  #[inline]
  pub fn wrapping_mul(self, rhs: Self) -> Self {
    Self(self.0.wrapping_mul(rhs.0))
  }

  /// Checked division. Returns `None` on divide-by-zero.
  pub fn checked_div(self, rhs: Self) -> Option<Self> {
    if rhs == Self::ZERO {
      return None;
    }
    Some(Self(self.0 / rhs.0))
  }

  /// Quotient and remainder.
  ///
  /// Returns `(ZERO, ZERO)` when `rhs` is zero.
  pub fn div_rem(self, rhs: Self) -> (Self, Self) {
    if rhs == Self::ZERO {
      return (Self::ZERO, Self::ZERO);
    }
    (Self(self.0 / rhs.0), Self(self.0 % rhs.0))
  }

  /// Wrapping left shift.
  ///
  /// Shifts of 256 or more yield zero.
  #[inline]
  pub fn wrapping_shl(self, shift: u32) -> Self {
    if shift >= 256 {
      return Self::ZERO;
    }
    Self(self.0 << shift)
  }

  /// Wrapping right shift.
  ///
  /// Shifts of 256 or more yield zero.
  #[inline]
  pub fn wrapping_shr(self, shift: u32) -> Self {
    if shift >= 256 {
      return Self::ZERO;
    }
    Self(self.0 >> shift)
  }

  /// Multiply by a `u64` scalar, returning the result and an overflow flag.
  #[inline]
  pub fn mul_u64(self, b: u64) -> (Self, bool) {
    let (v, overflow) = self.0.mul_u64(b);
    (Self(v), overflow)
  }

  /// Work contributed by this difficulty target, `2^256 / (self + 1)`.
  pub fn block_proof(self) -> Self {
    if self == Self::ZERO {
      return Self::ZERO;
    }
    if self == Self::MAX {
      return Self::ONE;
    }
    let d = self.wrapping_add(Self::ONE);
    // !self is 2^256 - 1 - self, so (!self) / (self + 1) + 1 equals
    // 2^256 / (self + 1) without needing a 257-bit numerator.
    (!self / d).wrapping_add(Self::ONE)
  }

  /// Approximate conversion to `f64`.
  pub fn to_f64(self) -> f64 {
    let (hi, lo) = self.limbs();
    let a0 = lo as u64;
    let a1 = (lo >> 64) as u64;
    let a2 = hi as u64;
    let a3 = (hi >> 64) as u64;

    let fact1 = 18_446_744_073_709_551_616.0_f64; // 2^64
    let fact2 = fact1 * fact1; // 2^128
    let fact3 = fact2 * fact1; // 2^192

    (a0 as f64) + (a1 as f64) * fact1 + (a2 as f64) * fact2 + (a3 as f64) * fact3
  }

  /// Split into the `(high, low)` 128-bit halves.
  #[inline]
  fn limbs(self) -> (u128, u128) {
    let le = self.0.to_le_bytes();
    let mut low = [0u8; 16];
    let mut high = [0u8; 16];
    low.copy_from_slice(&le[..16]);
    high.copy_from_slice(&le[16..]);
    (u128::from_le_bytes(high), u128::from_le_bytes(low))
  }

  /// Apply `op` to the matching 128-bit halves of both operands.
  #[inline]
  fn zip_limbs(self, rhs: Self, op: impl Fn(u128, u128) -> u128) -> Self {
    let (ah, al) = self.limbs();
    let (bh, bl) = rhs.limbs();
    Self(U256::new(op(ah, bh), op(al, bl)))
  }
}

impl fmt::Debug for Arith256 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Arith256({:#x})", self.0)
  }
}

/// Reversed hex (big-endian display, consensus format).
impl fmt::Display for Arith256 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt::LowerHex::fmt(self, f)
  }
}

/// Parses the big-endian hex rendered by [`Display`](fmt::Display).
impl FromStr for Arith256 {
  type Err = ParseHexError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Hash256::from_hex(s).map(Self::from)
  }
}

type_cvrt!(From<u8> for Arith256, |v| Self::from_u64(u64::from(*v)));
type_cvrt!(From<u16> for Arith256, |v| Self::from_u64(u64::from(*v)));
type_cvrt!(From<u32> for Arith256, |v| Self::from_u64(u64::from(*v)));
type_cvrt!(From<u64> for Arith256, |v| Self::from_u64(*v));
type_cvrt!(From<u128> for Arith256, |v| Self::from_u128(*v));
type_cvrt!(From<Hash256> for Arith256, |h| Self::from_lendian(h.to_lendian()));
type_cvrt!(From<Arith256> for Hash256, |a| Hash256::from_lendian(a.to_lendian()));

impl Add for Arith256 {
  type Output = Self;
  #[inline]
  fn add(self, rhs: Self) -> Self {
    self.wrapping_add(rhs)
  }
}

impl AddAssign for Arith256 {
  #[inline]
  fn add_assign(&mut self, rhs: Self) {
    *self = *self + rhs;
  }
}

impl Sub for Arith256 {
  type Output = Self;
  #[inline]
  fn sub(self, rhs: Self) -> Self {
    self.wrapping_sub(rhs)
  }
}

impl SubAssign for Arith256 {
  #[inline]
  fn sub_assign(&mut self, rhs: Self) {
    *self = *self - rhs;
  }
}

impl Mul for Arith256 {
  type Output = Self;
  #[inline]
  fn mul(self, rhs: Self) -> Self {
    self.wrapping_mul(rhs)
  }
}

impl MulAssign for Arith256 {
  #[inline]
  fn mul_assign(&mut self, rhs: Self) {
    *self = *self * rhs;
  }
}

impl Mul<u32> for Arith256 {
  type Output = Self;
  #[inline]
  fn mul(self, rhs: u32) -> Self {
    self.mul_u64(u64::from(rhs)).0
  }
}

impl MulAssign<u32> for Arith256 {
  #[inline]
  fn mul_assign(&mut self, rhs: u32) {
    *self = *self * rhs;
  }
}

/// Returns `Arith256::ZERO` when `rhs` is zero. Use `checked_div`
/// for an `Option` alternative.
impl Div for Arith256 {
  type Output = Self;
  #[inline]
  fn div(self, rhs: Self) -> Self {
    self.checked_div(rhs).unwrap_or(Self::ZERO)
  }
}

impl DivAssign for Arith256 {
  #[inline]
  fn div_assign(&mut self, rhs: Self) {
    *self = *self / rhs;
  }
}

/// Returns `Arith256::ZERO` when `rhs` is zero.
impl Rem for Arith256 {
  type Output = Self;
  #[inline]
  fn rem(self, rhs: Self) -> Self {
    self.div_rem(rhs).1
  }
}

impl RemAssign for Arith256 {
  #[inline]
  fn rem_assign(&mut self, rhs: Self) {
    *self = *self % rhs;
  }
}

impl Neg for Arith256 {
  type Output = Self;
  #[inline]
  fn neg(self) -> Self {
    (!self).wrapping_add(Self::ONE)
  }
}

impl Not for Arith256 {
  type Output = Self;
  #[inline]
  fn not(self) -> Self {
    Self(!self.0)
  }
}

impl BitAnd for Arith256 {
  type Output = Self;
  #[inline]
  fn bitand(self, rhs: Self) -> Self {
    self.zip_limbs(rhs, |a, b| a & b)
  }
}

impl BitAndAssign for Arith256 {
  #[inline]
  fn bitand_assign(&mut self, rhs: Self) {
    *self = *self & rhs;
  }
}

impl BitOr for Arith256 {
  type Output = Self;
  #[inline]
  fn bitor(self, rhs: Self) -> Self {
    self.zip_limbs(rhs, |a, b| a | b)
  }
}

impl BitOrAssign for Arith256 {
  #[inline]
  fn bitor_assign(&mut self, rhs: Self) {
    *self = *self | rhs;
  }
}

impl BitXor for Arith256 {
  type Output = Self;
  #[inline]
  fn bitxor(self, rhs: Self) -> Self {
    self.zip_limbs(rhs, |a, b| a ^ b)
  }
}

impl BitXorAssign for Arith256 {
  #[inline]
  fn bitxor_assign(&mut self, rhs: Self) {
    *self = *self ^ rhs;
  }
}

impl Shl<u32> for Arith256 {
  type Output = Self;
  #[inline]
  fn shl(self, rhs: u32) -> Self {
    self.wrapping_shl(rhs)
  }
}

impl ShlAssign<u32> for Arith256 {
  #[inline]
  fn shl_assign(&mut self, rhs: u32) {
    *self = *self << rhs;
  }
}

impl Shr<u32> for Arith256 {
  type Output = Self;
  #[inline]
  fn shr(self, rhs: u32) -> Self {
    self.wrapping_shr(rhs)
  }
}

impl ShrAssign<u32> for Arith256 {
  #[inline]
  fn shr_assign(&mut self, rhs: u32) {
    *self = *self >> rhs;
  }
}
