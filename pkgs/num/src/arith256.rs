//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! 256-bit unsigned arithmetic integer.

use crate::Hash256;

use core::cmp::Ordering;
use core::fmt;
use core::ops::{
  Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign, Mul, MulAssign, Neg,
  Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

/// 256-bit unsigned arithmetic integer.
///
/// Stored as two `u128` limbs where `lo` holds bits \[0..128) and `hi` holds
/// bits \[128..256).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Arith256 {
  lo: u128,
  hi: u128,
}

impl Arith256 {
  /// The additive identity (all bits zero).
  pub const ZERO: Self = Self { lo: 0, hi: 0 };
  /// The multiplicative identity.
  pub const ONE: Self = Self { lo: 1, hi: 0 };
  /// The largest representable value (all bits set).
  pub const MAX: Self = Self {
    lo: u128::MAX,
    hi: u128::MAX,
  };
  /// Byte length.
  pub const LEN: usize = 32;

  /// Create from a `u64`, zero-extending the upper bits.
  #[inline]
  pub const fn from_u64(v: u64) -> Self {
    Self { lo: v as u128, hi: 0 }
  }

  /// Create from a `u128`, zero-extending the upper bits.
  #[inline]
  pub const fn from_u128(v: u128) -> Self {
    Self { lo: v, hi: 0 }
  }

  /// Construct from little-endian bytes.
  ///
  /// `bytes[0..16]` maps to `lo`, `bytes[16..32]` to `hi`.
  #[inline]
  pub const fn from_le_bytes(bytes: [u8; 32]) -> Self {
    let lo = u128::from_le_bytes(split_low(bytes));
    let hi = u128::from_le_bytes(split_high(bytes));
    Self { lo, hi }
  }

  /// Construct from big-endian bytes.
  #[inline]
  pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
    let mut le = [0u8; 32];
    let mut i = 0;
    while i < 32 {
      le[i] = bytes[31 - i];
      i += 1;
    }
    Self::from_le_bytes(le)
  }

  /// Construct from big-endian bytes (consensus display order).
  ///
  /// This is the natural byte order produced by `hex_literal::hex!()` when
  /// given a consensus hex value. Internally the value is stored
  /// little-endian, so this reverses the input before decoding.
  #[inline]
  pub const fn new(be: [u8; 32]) -> Self {
    Self::from_be_bytes(be)
  }

  /// Convert to little-endian bytes.
  #[inline]
  pub const fn to_le_bytes(self) -> [u8; 32] {
    let lo = self.lo.to_le_bytes();
    let hi = self.hi.to_le_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 16 {
      out[i] = lo[i];
      out[i + 16] = hi[i];
      i += 1;
    }
    out
  }

  /// Convert to big-endian bytes.
  #[inline]
  pub const fn to_be_bytes(self) -> [u8; 32] {
    let le = self.to_le_bytes();
    let mut be = [0u8; 32];
    let mut i = 0;
    while i < 32 {
      be[i] = le[31 - i];
      i += 1;
    }
    be
  }

  /// Returns `true` if the value is zero.
  #[inline]
  pub const fn is_zero(self) -> bool {
    self.lo == 0 && self.hi == 0
  }

  /// Returns `true` if the value is one.
  #[inline]
  pub const fn is_one(self) -> bool {
    self.lo == 1 && self.hi == 0
  }

  /// Returns `true` if the value is MAX (all bits set).
  #[inline]
  pub const fn is_max(self) -> bool {
    self.lo == u128::MAX && self.hi == u128::MAX
  }

  /// Returns the lowest 32 bits of the value.
  #[inline]
  pub const fn low_u32(self) -> u32 {
    self.lo as u32
  }

  /// Returns the lowest 64 bits of the value.
  #[inline]
  pub const fn low_u64(self) -> u64 {
    self.lo as u64
  }

  /// Returns the lowest 128 bits of the value.
  #[inline]
  pub const fn low_u128(self) -> u128 {
    self.lo
  }

  /// Saturating conversion to u128. Returns u128::MAX if value exceeds 128
  /// bits.
  #[inline]
  pub const fn saturating_to_u128(self) -> u128 {
    if self.hi != 0 {
      u128::MAX
    } else {
      self.lo
    }
  }

  /// Highest set bit position plus one, or zero if zero.
  #[inline]
  pub const fn bits(self) -> u32 {
    if self.hi != 0 {
      256 - self.hi.leading_zeros()
    } else if self.lo != 0 {
      128 - self.lo.leading_zeros()
    } else {
      0
    }
  }

  /// Wrapping addition.
  #[inline]
  pub const fn wrapping_add(self, rhs: Self) -> Self {
    let (lo, carry) = self.lo.overflowing_add(rhs.lo);
    let hi = self.hi.wrapping_add(rhs.hi).wrapping_add(carry as u128);
    Self { lo, hi }
  }

  /// Wrapping subtraction.
  #[inline]
  pub const fn wrapping_sub(self, rhs: Self) -> Self {
    let (lo, borrow) = self.lo.overflowing_sub(rhs.lo);
    let hi = self.hi.wrapping_sub(rhs.hi).wrapping_sub(borrow as u128);
    Self { lo, hi }
  }

  /// Two's complement negation.
  #[inline]
  pub const fn wrapping_neg(self) -> Self {
    self.bitwise_not().wrapping_add(Self::ONE)
  }

  /// Wrapping increment (add one).
  #[inline]
  pub const fn wrapping_inc(self) -> Self {
    self.wrapping_add(Self::ONE)
  }

  /// Bitwise NOT.
  #[inline]
  pub const fn bitwise_not(self) -> Self {
    Self {
      lo: !self.lo,
      hi: !self.hi,
    }
  }

  /// Wrapping multiply via 64-bit limb decomposition.
  pub const fn wrapping_mul(self, rhs: Self) -> Self {
    let a0 = self.lo as u64 as u128;
    let a1 = (self.lo >> 64) as u64 as u128;
    let a2 = self.hi as u64 as u128;
    let a3 = (self.hi >> 64) as u64 as u128;

    let b0 = rhs.lo as u64 as u128;
    let b1 = (rhs.lo >> 64) as u64 as u128;
    let b2 = rhs.hi as u64 as u128;
    let b3 = (rhs.hi >> 64) as u64 as u128;

    let p00 = a0 * b0;
    let r0 = p00 as u64 as u128;
    let mut carry = p00 >> 64;

    let p10 = a1 * b0;
    let p01 = a0 * b1;
    let sum = carry + (p10 as u64 as u128) + (p01 as u64 as u128);
    let r1 = sum as u64 as u128;
    carry = (sum >> 64) + (p10 >> 64) + (p01 >> 64);

    let p20 = a2 * b0;
    let p11 = a1 * b1;
    let p02 = a0 * b2;
    let sum = carry
      .wrapping_add(p20 as u64 as u128)
      .wrapping_add(p11 as u64 as u128)
      .wrapping_add(p02 as u64 as u128);
    let r2 = sum as u64 as u128;
    carry = (sum >> 64)
      .wrapping_add(p20 >> 64)
      .wrapping_add(p11 >> 64)
      .wrapping_add(p02 >> 64);

    let p30 = a3 * b0;
    let p21 = a2 * b1;
    let p12 = a1 * b2;
    let p03 = a0 * b3;
    let r3 = carry
      .wrapping_add(p30 as u64 as u128)
      .wrapping_add(p21 as u64 as u128)
      .wrapping_add(p12 as u64 as u128)
      .wrapping_add(p03 as u64 as u128) as u64 as u128;

    Self {
      lo: r0 | (r1 << 64),
      hi: r2 | (r3 << 64),
    }
  }

  /// Checked division. Returns `None` on divide-by-zero.
  pub const fn checked_div(self, rhs: Self) -> Option<Self> {
    if rhs.is_zero() {
      return None;
    }
    Some(self.div_rem(rhs).0)
  }

  /// Quotient and remainder via bitwise long division.
  ///
  /// Returns `(ZERO, ZERO)` when `rhs` is zero.
  pub const fn div_rem(self, rhs: Self) -> (Self, Self) {
    if rhs.is_zero() {
      return (Self::ZERO, Self::ZERO);
    }

    let num_bits = self.bits();
    let div_bits = rhs.bits();

    if div_bits > num_bits {
      return (Self::ZERO, self);
    }

    let mut quotient = Self::ZERO;
    let mut remainder = self;
    let mut divisor = rhs.wrapping_shl(num_bits - div_bits);
    let mut shift = num_bits - div_bits;

    loop {
      if !is_less(remainder, divisor) {
        remainder = remainder.wrapping_sub(divisor);
        if shift < 128 {
          quotient.lo |= 1u128 << shift;
        } else {
          quotient.hi |= 1u128 << (shift - 128);
        }
      }
      if shift == 0 {
        break;
      }
      divisor = divisor.wrapping_shr(1);
      shift -= 1;
    }

    (quotient, remainder)
  }

  /// Wrapping left shift.
  #[inline]
  pub const fn wrapping_shl(self, shift: u32) -> Self {
    if shift >= 256 {
      return Self::ZERO;
    }
    if shift >= 128 {
      let bit_shift = shift - 128;
      Self {
        lo: 0,
        hi: if bit_shift == 0 { self.lo } else { self.lo << bit_shift },
      }
    } else if shift == 0 {
      self
    } else {
      Self {
        lo: self.lo << shift,
        hi: (self.hi << shift) | (self.lo >> (128 - shift)),
      }
    }
  }

  /// Wrapping right shift.
  #[inline]
  pub const fn wrapping_shr(self, shift: u32) -> Self {
    if shift >= 256 {
      return Self::ZERO;
    }
    if shift >= 128 {
      let bit_shift = shift - 128;
      Self {
        lo: if bit_shift == 0 { self.hi } else { self.hi >> bit_shift },
        hi: 0,
      }
    } else if shift == 0 {
      self
    } else {
      Self {
        lo: (self.lo >> shift) | (self.hi << (128 - shift)),
        hi: self.hi >> shift,
      }
    }
  }

  /// Wrapping multiply by a `u32` scalar.
  pub const fn wrapping_mul_u32(self, b: u32) -> Self {
    let b = b as u128;
    let a0 = self.lo as u64 as u128;
    let a1 = (self.lo >> 64) as u64 as u128;
    let a2 = self.hi as u64 as u128;
    let a3 = (self.hi >> 64) as u64 as u128;

    let n0 = a0 * b;
    let r0 = n0 as u64 as u128;
    let carry = n0 >> 64;

    let n1 = carry + a1 * b;
    let r1 = n1 as u64 as u128;
    let carry = n1 >> 64;

    let n2 = carry + a2 * b;
    let r2 = n2 as u64 as u128;
    let carry = n2 >> 64;

    let r3 = (carry + a3 * b) as u64 as u128;

    Self {
      lo: r0 | (r1 << 64),
      hi: r2 | (r3 << 64),
    }
  }

  /// Multiply by a `u64` scalar, returning the result and an overflow flag.
  pub const fn mul_u64(self, b: u64) -> (Self, bool) {
    let b = b as u128;
    let a0 = self.lo as u64 as u128;
    let a1 = (self.lo >> 64) as u64 as u128;
    let a2 = self.hi as u64 as u128;
    let a3 = (self.hi >> 64) as u64 as u128;

    let n0 = a0 * b;
    let r0 = n0 as u64 as u128;
    let carry = n0 >> 64;

    let n1 = carry + a1 * b;
    let r1 = n1 as u64 as u128;
    let carry = n1 >> 64;

    let n2 = carry + a2 * b;
    let r2 = n2 as u64 as u128;
    let carry = n2 >> 64;

    let n3 = carry + a3 * b;
    let r3 = n3 as u64 as u128;
    let overflow = (n3 >> 64) != 0;

    (
      Self {
        lo: r0 | (r1 << 64),
        hi: r2 | (r3 << 64),
      },
      overflow,
    )
  }

  /// Compute `2^256 / (self + 1)`. Returns MAX when self is zero or one.
  pub const fn inverse(self) -> Self {
    if self.is_zero() || self.is_one() {
      return Self::MAX;
    }
    if self.is_max() {
      return Self::ONE;
    }
    let d = self.wrapping_inc();
    // !self = 2^256 - 1 - self, so (!self) / (self + 1) + 1 ~ 2^256 / (self + 1)
    self.bitwise_not().div_rem(d).0.wrapping_inc()
  }

  /// Approximate conversion to `f64`.
  pub const fn to_f64(self) -> f64 {
    let a0 = self.lo as u64;
    let a1 = (self.lo >> 64) as u64;
    let a2 = self.hi as u64;
    let a3 = (self.hi >> 64) as u64;

    let fact1 = 18_446_744_073_709_551_616.0_f64; // 2^64
    let fact2 = fact1 * fact1; // 2^128
    let fact3 = fact2 * fact1; // 2^192

    (a0 as f64) + (a1 as f64) * fact1 + (a2 as f64) * fact2 + (a3 as f64) * fact3
  }
}

const fn is_less(a: Arith256, b: Arith256) -> bool {
  if a.hi != b.hi {
    a.hi < b.hi
  } else {
    a.lo < b.lo
  }
}

const fn split_low(bytes: [u8; 32]) -> [u8; 16] {
  let mut out = [0u8; 16];
  let mut i = 0;
  while i < 16 {
    out[i] = bytes[i];
    i += 1;
  }
  out
}

const fn split_high(bytes: [u8; 32]) -> [u8; 16] {
  let mut out = [0u8; 16];
  let mut i = 0;
  while i < 16 {
    out[i] = bytes[i + 16];
    i += 1;
  }
  out
}

impl Ord for Arith256 {
  #[inline]
  fn cmp(&self, other: &Self) -> Ordering {
    self.hi.cmp(&other.hi).then(self.lo.cmp(&other.lo))
  }
}

impl PartialOrd for Arith256 {
  #[inline]
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl fmt::Debug for Arith256 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Arith256(0x{:032x}{:032x})", self.hi, self.lo)
  }
}

/// Reversed hex (big-endian display, consensus format).
impl fmt::Display for Arith256 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let h: Hash256 = (*self).into();
    fmt::Display::fmt(&h, f)
  }
}

/// Big-endian numeric hex, 64 chars zero-padded.
impl fmt::LowerHex for Arith256 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if f.alternate() {
      f.write_str("0x")?;
    }
    write!(f, "{:032x}{:032x}", self.hi, self.lo)
  }
}

/// Big-endian numeric hex (uppercase), 64 chars zero-padded.
impl fmt::UpperHex for Arith256 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if f.alternate() {
      f.write_str("0x")?;
    }
    write!(f, "{:032X}{:032X}", self.hi, self.lo)
  }
}

impl From<u8> for Arith256 {
  fn from(v: u8) -> Self {
    Self::from_u64(v as u64)
  }
}

impl From<u16> for Arith256 {
  fn from(v: u16) -> Self {
    Self::from_u64(v as u64)
  }
}

impl From<u32> for Arith256 {
  fn from(v: u32) -> Self {
    Self::from_u64(v as u64)
  }
}

impl From<u64> for Arith256 {
  fn from(v: u64) -> Self {
    Self::from_u64(v)
  }
}

impl From<u128> for Arith256 {
  fn from(v: u128) -> Self {
    Self::from_u128(v)
  }
}

impl From<Hash256> for Arith256 {
  fn from(h: Hash256) -> Self {
    Self::from_le_bytes(h.to_bytes())
  }
}

impl From<Arith256> for Hash256 {
  fn from(a: Arith256) -> Self {
    Hash256::from_bytes(a.to_le_bytes())
  }
}

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
    self.wrapping_mul_u32(rhs)
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
    self.div_rem(rhs).0
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
    self.wrapping_neg()
  }
}

impl Not for Arith256 {
  type Output = Self;
  #[inline]
  fn not(self) -> Self {
    self.bitwise_not()
  }
}

impl BitAnd for Arith256 {
  type Output = Self;
  #[inline]
  fn bitand(self, rhs: Self) -> Self {
    Self {
      lo: self.lo & rhs.lo,
      hi: self.hi & rhs.hi,
    }
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
    Self {
      lo: self.lo | rhs.lo,
      hi: self.hi | rhs.hi,
    }
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
    Self {
      lo: self.lo ^ rhs.lo,
      hi: self.hi ^ rhs.hi,
    }
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

#[cfg(feature = "serde")]
impl serde::Serialize for Arith256 {
  fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
    let h = Hash256::from(*self);
    h.serialize(serializer)
  }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Arith256 {
  fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    let h = Hash256::deserialize(deserializer)?;
    Ok(Self::from(h))
  }
}
