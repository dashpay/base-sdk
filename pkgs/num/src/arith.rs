//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Unified trait for wide unsigned arithmetic integers.

use core::fmt;
use core::hash::Hash;
use core::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Not, Rem, Shl, Shr, Sub};

/// Shared interface for wide unsigned arithmetic integer types.
///
/// All operators are **wrapping**. Wide integer types are **never**
/// displayed in decimal; `Display` outputs reversed hex via the
/// corresponding hash type.
pub trait ArithInt:
  Copy
  + Clone
  + Default
  + Eq
  + Ord
  + Hash
  + Add<Output = Self>
  + Sub<Output = Self>
  + Mul<Output = Self>
  + Div<Output = Self>
  + Rem<Output = Self>
  + Not<Output = Self>
  + Neg<Output = Self>
  + BitAnd<Output = Self>
  + BitOr<Output = Self>
  + BitXor<Output = Self>
  + Shl<u32, Output = Self>
  + Shr<u32, Output = Self>
  + Mul<u32, Output = Self>
  + fmt::Debug
  + fmt::Display
  + fmt::LowerHex
  + fmt::UpperHex
{
  /// The fixed-size byte array type.
  type Bytes: Copy;

  /// The additive identity (all bits zero).
  const ZERO: Self;
  /// The multiplicative identity.
  const ONE: Self;
  /// The largest representable value (all bits set).
  const MAX: Self;
  /// Byte length.
  const LEN: usize;

  /// Create from a `u64`, zero-extending.
  fn from_u64(v: u64) -> Self;
  /// Create from a `u128`, zero-extending (or truncating for 128-bit).
  fn from_u128(v: u128) -> Self;
  /// Construct from little-endian bytes.
  fn from_le_bytes(bytes: Self::Bytes) -> Self;
  /// Construct from big-endian bytes.
  fn from_be_bytes(bytes: Self::Bytes) -> Self;
  /// Construct from big-endian bytes (alias for `from_be_bytes`).
  fn new(be: Self::Bytes) -> Self;

  /// Convert to little-endian bytes.
  fn to_le_bytes(self) -> Self::Bytes;
  /// Convert to big-endian bytes.
  fn to_be_bytes(self) -> Self::Bytes;
  /// Returns the lowest 32 bits.
  fn low_u32(self) -> u32;
  /// Returns the lowest 64 bits.
  fn low_u64(self) -> u64;
  /// Returns the lowest 128 bits.
  fn low_u128(self) -> u128;
  /// Saturating conversion to u128.
  fn saturating_to_u128(self) -> u128;
  /// Approximate conversion to `f64`.
  fn to_f64(self) -> f64;

  /// Returns `true` if the value is zero.
  fn is_zero(self) -> bool;
  /// Returns `true` if the value is one.
  fn is_one(self) -> bool;
  /// Returns `true` if the value is MAX.
  fn is_max(self) -> bool;
  /// Highest set bit position plus one, or zero if zero.
  fn bits(self) -> u32;

  /// Wrapping addition.
  fn wrapping_add(self, rhs: Self) -> Self;
  /// Wrapping subtraction.
  fn wrapping_sub(self, rhs: Self) -> Self;
  /// Wrapping multiplication.
  fn wrapping_mul(self, rhs: Self) -> Self;
  /// Wrapping negation.
  fn wrapping_neg(self) -> Self;
  /// Wrapping increment.
  fn wrapping_inc(self) -> Self;
  /// Wrapping left shift.
  fn wrapping_shl(self, shift: u32) -> Self;
  /// Wrapping right shift.
  fn wrapping_shr(self, shift: u32) -> Self;
  /// Wrapping multiply by u32 scalar.
  fn wrapping_mul_u32(self, b: u32) -> Self;
  /// Multiply by u64 scalar, returning result and overflow flag.
  fn mul_u64(self, b: u64) -> (Self, bool);
  /// Bitwise NOT.
  fn bitwise_not(self) -> Self;
  /// Checked division.
  fn checked_div(self, rhs: Self) -> Option<Self>;
  /// Quotient and remainder.
  fn div_rem(self, rhs: Self) -> (Self, Self);
  /// Compute `2^N / (self + 1)`.
  fn inverse(self) -> Self;
}

impl ArithInt for crate::Arith256 {
  type Bytes = [u8; 32];
  const ZERO: Self = Self::ZERO;
  const ONE: Self = Self::ONE;
  const MAX: Self = Self::MAX;
  const LEN: usize = Self::LEN;

  #[inline]
  fn from_u64(v: u64) -> Self {
    Self::from_u64(v)
  }
  #[inline]
  fn from_u128(v: u128) -> Self {
    Self::from_u128(v)
  }
  #[inline]
  fn from_le_bytes(bytes: [u8; 32]) -> Self {
    Self::from_le_bytes(bytes)
  }
  #[inline]
  fn from_be_bytes(bytes: [u8; 32]) -> Self {
    Self::from_be_bytes(bytes)
  }
  #[inline]
  fn new(be: [u8; 32]) -> Self {
    Self::new(be)
  }
  #[inline]
  fn to_le_bytes(self) -> [u8; 32] {
    Self::to_le_bytes(self)
  }
  #[inline]
  fn to_be_bytes(self) -> [u8; 32] {
    Self::to_be_bytes(self)
  }
  #[inline]
  fn low_u32(self) -> u32 {
    Self::low_u32(self)
  }
  #[inline]
  fn low_u64(self) -> u64 {
    Self::low_u64(self)
  }
  #[inline]
  fn low_u128(self) -> u128 {
    Self::low_u128(self)
  }
  #[inline]
  fn saturating_to_u128(self) -> u128 {
    Self::saturating_to_u128(self)
  }
  #[inline]
  fn to_f64(self) -> f64 {
    Self::to_f64(self)
  }
  #[inline]
  fn is_zero(self) -> bool {
    Self::is_zero(self)
  }
  #[inline]
  fn is_one(self) -> bool {
    Self::is_one(self)
  }
  #[inline]
  fn is_max(self) -> bool {
    Self::is_max(self)
  }
  #[inline]
  fn bits(self) -> u32 {
    Self::bits(self)
  }
  #[inline]
  fn wrapping_add(self, rhs: Self) -> Self {
    Self::wrapping_add(self, rhs)
  }
  #[inline]
  fn wrapping_sub(self, rhs: Self) -> Self {
    Self::wrapping_sub(self, rhs)
  }
  #[inline]
  fn wrapping_mul(self, rhs: Self) -> Self {
    Self::wrapping_mul(self, rhs)
  }
  #[inline]
  fn wrapping_neg(self) -> Self {
    Self::wrapping_neg(self)
  }
  #[inline]
  fn wrapping_inc(self) -> Self {
    Self::wrapping_inc(self)
  }
  #[inline]
  fn wrapping_shl(self, shift: u32) -> Self {
    Self::wrapping_shl(self, shift)
  }
  #[inline]
  fn wrapping_shr(self, shift: u32) -> Self {
    Self::wrapping_shr(self, shift)
  }
  #[inline]
  fn wrapping_mul_u32(self, b: u32) -> Self {
    Self::wrapping_mul_u32(self, b)
  }
  #[inline]
  fn mul_u64(self, b: u64) -> (Self, bool) {
    Self::mul_u64(self, b)
  }
  #[inline]
  fn bitwise_not(self) -> Self {
    Self::bitwise_not(self)
  }
  #[inline]
  fn checked_div(self, rhs: Self) -> Option<Self> {
    Self::checked_div(self, rhs)
  }
  #[inline]
  fn div_rem(self, rhs: Self) -> (Self, Self) {
    Self::div_rem(self, rhs)
  }
  #[inline]
  fn inverse(self) -> Self {
    Self::inverse(self)
  }
}
