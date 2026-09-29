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
use delegate::delegate;

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

  delegate! {
    to U256 {
      #[call(from_le_bytes)]
      #[expr(Self($))]
      fn from_base(v: [u8; 32]) -> Self;

      #[call(from_le_bytes)]
      #[expr(Self($))]
      fn from_lendian(bytes: [u8; 32]) -> Self;

      #[call(from_be_bytes)]
      #[expr(Self($))]
      fn from_bendian(bytes: [u8; 32]) -> Self;
    }
    to self.0 {
      #[call(to_le_bytes)]
      fn to_base(&self) -> [u8; 32];

      #[call(to_le_bytes)]
      fn to_lendian(&self) -> [u8; 32];

      #[call(to_be_bytes)]
      fn to_bendian(&self) -> [u8; 32];
    }
  }
}

impl Arith256 {
  /// The multiplicative identity.
  pub const ONE: Self = Self(U256::ONE);
  /// The largest representable value (all bits set).
  pub const MAX: Self = Self(U256::MAX);

  delegate! {
    to U256 {
      /// Create from a `u64`, zero-extending the upper bits.
      #[call(from)]
      #[expr(Self($))]
      pub fn from_u64(v: u64) -> Self;

      /// Create from a `u128`, zero-extending the upper bits.
      #[call(from)]
      #[expr(Self($))]
      pub fn from_u128(v: u128) -> Self;
    }
    to self.0 {
      /// Returns the lowest 32 bits of the value.
      pub fn low_u32(self) -> u32;

      /// Returns the lowest 64 bits of the value.
      pub fn low_u64(self) -> u64;

      /// Converts to `u128`, saturating at `u128::MAX` above 128 bits.
      pub fn saturating_to_u128(self) -> u128;

      /// Highest set bit position plus one, or zero if zero.
      pub fn bits(self) -> u32;

      /// Wrapping addition.
      #[expr(Self($))]
      pub fn wrapping_add(self, #[newtype] rhs: Self) -> Self;

      /// Wrapping subtraction.
      #[expr(Self($))]
      pub fn wrapping_sub(self, #[newtype] rhs: Self) -> Self;

      /// Wrapping multiply.
      #[expr(Self($))]
      pub fn wrapping_mul(self, #[newtype] rhs: Self) -> Self;

      /// Multiply by a `u64` scalar, returning the result and an overflow flag.
      #[expr({ let (v, overflow) = $; (Self(v), overflow) })]
      pub fn mul_u64(self, b: u64) -> (Self, bool);
    }
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

  /// Returns the lowest 128 bits of the value.
  #[inline]
  pub fn low_u128(self) -> u128 {
    self.limbs().1
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

impl PartialEq<u64> for Arith256 {
  #[inline]
  fn eq(&self, other: &u64) -> bool {
    *self == Self::from_u64(*other)
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

impl AddAssign<u64> for Arith256 {
  #[inline]
  fn add_assign(&mut self, rhs: u64) {
    *self += Self::from_u64(rhs);
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

impl SubAssign<u64> for Arith256 {
  #[inline]
  fn sub_assign(&mut self, rhs: u64) {
    *self -= Self::from_u64(rhs);
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
impl Div<u64> for Arith256 {
  type Output = Self;
  #[inline]
  fn div(self, rhs: u64) -> Self {
    self / Self::from_u64(rhs)
  }
}

impl DivAssign<u64> for Arith256 {
  #[inline]
  fn div_assign(&mut self, rhs: u64) {
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

impl BitOrAssign<u64> for Arith256 {
  #[inline]
  fn bitor_assign(&mut self, rhs: u64) {
    *self |= Self::from_u64(rhs);
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

impl BitXorAssign<u64> for Arith256 {
  #[inline]
  fn bitxor_assign(&mut self, rhs: u64) {
    *self ^= Self::from_u64(rhs);
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::prelude::*;
  use crate::{Arith256, Hash256};

  use dash_types::Numeric;
  use hex_conservative::hex;
  use rstest::*;

  use core::str::FromStr;

  fn arith_from_le(bytes: &[u8; 32]) -> Arith256 {
    Arith256::from(Hash256::from_lendian(*bytes))
  }

  fn arith_from_hex(s: &str) -> Arith256 {
    Arith256::from(Hash256::from_str(s).unwrap())
  }

  /// Construct Arith256 from big-endian array of four u64 limbs.
  fn from_array(a: [u64; 4]) -> Arith256 {
    let hi = (a[0] as u128) << 64 | (a[1] as u128);
    let lo = (a[2] as u128) << 64 | (a[3] as u128);
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&lo.to_le_bytes());
    bytes[16..].copy_from_slice(&hi.to_le_bytes());
    Arith256::from_lendian(bytes)
  }

  #[fixture]
  fn r1_bytes() -> [u8; 32] {
    hex!("9c524adbcf5611122b29125e5d35d2d22281aab533f00832d556b1f9eae51d7d")
  }

  #[fixture]
  fn r1_hex() -> &'static str {
    "7d1de5eaf9b156d53208f033b5aa8122d2d2355d5e12292b121156cfdb4a529c"
  }

  #[fixture]
  fn r2_bytes() -> [u8; 32] {
    hex!("70321d7c47a56b40267e0ac3a69cb6bf133047a3192dda71491372f0b4ca81d7")
  }

  #[fixture]
  fn r2_hex() -> &'static str {
    "d781cab4f072134971da2d19a3473013bfb69ca6c30a7e26406ba5477c1d3270"
  }

  #[fixture]
  fn one_hash() -> Hash256 {
    Hash256::from_lendian({
      let mut a = [0u8; 32];
      a[0] = 1;
      a
    })
  }

  #[fixture]
  fn r1(r1_bytes: [u8; 32]) -> Arith256 {
    arith_from_le(&r1_bytes)
  }

  #[fixture]
  fn r2(r2_bytes: [u8; 32]) -> Arith256 {
    arith_from_le(&r2_bytes)
  }

  mod conversion {
    use super::*;

    #[rstest]
    fn roundtrip_hash_arith_hash(r1_bytes: [u8; 32], r2_bytes: [u8; 32], one_hash: Hash256) {
      for h in [
        Hash256::ZERO,
        one_hash,
        Hash256::from_lendian(r1_bytes),
        Hash256::from_lendian(r2_bytes),
      ] {
        assert_eq!(Hash256::from(Arith256::from(h)), h);
      }
    }

    #[rstest]
    fn hash_to_arith_zero_and_one(one_hash: Hash256) {
      assert_eq!(Arith256::from(Hash256::ZERO), Arith256::ZERO);
      assert_eq!(Arith256::from(one_hash), Arith256::ONE);
    }

    #[rstest]
    fn arith_to_hash_zero_and_one(one_hash: Hash256) {
      assert_eq!(Hash256::from(Arith256::ZERO), Hash256::ZERO);
      assert_eq!(Hash256::from(Arith256::ONE), one_hash);
    }

    #[rstest]
    fn hex_through_arith_matches_hash(r1_bytes: [u8; 32], r2_bytes: [u8; 32]) {
      for bytes in [r1_bytes, r2_bytes] {
        let h = Hash256::from_lendian(bytes);
        let a = Arith256::from(h);
        assert_eq!(format!("{h}"), format!("{a}"));
      }
    }

    #[rstest]
    fn arith_from_hex_equals_from_hash(r1_bytes: [u8; 32], r1_hex: &str, r2_bytes: [u8; 32], r2_hex: &str) {
      assert_eq!(arith_from_le(&r1_bytes), arith_from_hex(r1_hex));
      assert_eq!(arith_from_le(&r2_bytes), arith_from_hex(r2_hex));
    }
  }

  mod byte_conversion {
    use super::*;

    const BE_BYTES: [u8; 32] = [
      0x1b, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe, 0x2b, 0xed, 0xfe, 0xed, 0xba, 0xad, 0xf0,
      0x0d, 0xde, 0xfa, 0xce, 0xda, 0x11, 0xfe, 0xd2, 0xba, 0xd1, 0xc0, 0xff, 0xe0,
    ];

    fn want() -> Arith256 {
      from_array([
        0x1bad_cafe_dead_beef,
        0xdeaf_babe_2bed_feed,
        0xbaad_f00d_defa_ceda,
        0x11fe_d2ba_d1c0_ffe0,
      ])
    }

    #[rstest]
    fn from_bendian() {
      assert_eq!(Arith256::from_bendian(BE_BYTES), want());
    }

    #[rstest]
    fn roundtrip_be() {
      let v = want();
      assert_eq!(Arith256::from_bendian(v.to_bendian()), v);
    }
  }

  mod add_sub {
    use super::*;

    #[rstest]
    fn self_ops() {
      let two = arith_from_hex("02");
      let mut v = two;

      v *= v;
      assert_eq!(v, arith_from_hex("04"));
      v /= v;
      assert_eq!(v, arith_from_hex("01"));
      v += v;
      assert_eq!(v, arith_from_hex("02"));
      v -= v;
      assert_eq!(v, Arith256::ZERO);
    }

    #[rstest]
    fn one_plus_max() {
      assert_eq!(Arith256::ONE + Arith256::MAX, Arith256::ZERO);
      assert_eq!(Arith256::MAX + Arith256::ONE, Arith256::ZERO);
    }

    /// `(Max >> i) + 1 == Half >> (i - 1)` for all valid i.
    #[rstest]
    fn shifted_max_plus_one() {
      let half = Arith256::ONE << 255u32;
      for i in 1..256u32 {
        assert_eq!((Arith256::MAX >> i) + Arith256::ONE, half >> (i - 1));
      }
    }

    #[rstest]
    fn double_negation(r1: Arith256, r2: Arith256) {
      assert_eq!(r1 - (-r2), r1 + r2);
      assert_eq!(r1 - (-Arith256::ONE), r1 + Arith256::ONE);
      assert_eq!(r1 - Arith256::ONE, r1 + (-Arith256::ONE));
    }

    /// `-(1 << i) == Max << i` for all bit positions.
    #[rstest]
    fn neg_shifted_one() {
      for i in 0..256u32 {
        assert_eq!(-(Arith256::ONE << i), Arith256::MAX << i);
      }
    }
  }

  mod multiply {
    use super::*;

    #[rstest]
    fn identity_and_negation(r1: Arith256, r2: Arith256) {
      assert_eq!(r1 * Arith256::ZERO, Arith256::ZERO);
      assert_eq!(r1 * Arith256::ONE, r1);
      assert_eq!(r1 * Arith256::MAX, -r1);
      assert_eq!(r2 * Arith256::ZERO, Arith256::ZERO);
      assert_eq!(r2 * Arith256::ONE, r2);
      assert_eq!(r2 * Arith256::MAX, -r2);
      assert_eq!(Arith256::MAX * Arith256::MAX, Arith256::ONE);
    }
  }

  mod divide {
    use super::*;

    #[rstest]
    fn known_results(r1: Arith256, r2: Arith256) {
      let d1 = arith_from_hex("0AD7133AC1977FA2B7");
      let d2 = arith_from_hex("0ECD751716");

      assert_eq!(
        format!("{}", r1 / d1),
        "00000000000000000b8ac01106981635d9ed112290f8895545a7654dde28fb3a"
      );
      assert_eq!(
        format!("{}", r1 / d2),
        "000000000873ce8efec5b67150bad3aa8c5fcb70e947586153bf2cec7c37c57a"
      );
      assert_eq!(r1 / Arith256::ONE, r1);
      assert_eq!(r1 / Arith256::MAX, Arith256::ZERO);
      assert_eq!(Arith256::MAX / r1, Arith256::from_u64(2));

      assert_eq!(
        format!("{}", r2 / d1),
        "000000000000000013e1665895a1cc981de6d93670105a6b3ec3b73141b3a3c5"
      );
      assert_eq!(
        format!("{}", r2 / d2),
        "000000000e8f0abe753bb0afe2e9437ee85d280be60882cf0bd1aaf7fa3cc2c4"
      );
      assert_eq!(r2 / Arith256::ONE, r2);
      assert_eq!(r2 / Arith256::MAX, Arith256::ZERO);
      assert_eq!(Arith256::MAX / r2, Arith256::from_u64(1));
    }

    #[rstest]
    fn by_zero_returns_zero() {
      assert_eq!(Arith256::from_u64(42) / Arith256::ZERO, Arith256::ZERO);
    }

    #[rstest]
    fn remainder() {
      let (q, r) = Arith256::from_u64(100).div_rem(Arith256::from_u64(7));
      assert_eq!(q, Arith256::from_u64(14));
      assert_eq!(r, Arith256::from_u64(2));
    }
  }

  mod shifts {
    use super::*;

    fn shift_array_right(from: &[u8; 32], n: u32) -> [u8; 32] {
      let mut to = [0u8; 32];
      let bit = (n % 8) as usize;
      for (t, dst) in to.iter_mut().enumerate() {
        let f = t + (n as usize / 8);
        if f < 32 {
          *dst = from[f] >> bit;
        }
        if f + 1 < 32 && bit != 0 {
          *dst |= from[f + 1] << (8 - bit);
        }
      }
      to
    }

    fn shift_array_left(from: &[u8; 32], n: u32) -> [u8; 32] {
      let mut to = [0u8; 32];
      let bit = (n % 8) as usize;
      for (t, dst) in to.iter_mut().enumerate() {
        if t >= n as usize / 8 {
          let f = t - n as usize / 8;
          *dst = from[f] << bit;
          if t > n as usize / 8 && bit != 0 {
            *dst |= from[f - 1] >> (8 - bit);
          }
        }
      }
      to
    }

    /// Test all 256 shift positions against a byte-array
    /// oracle for One, R1, and Max.
    #[rstest]
    fn exhaustive(r1_bytes: [u8; 32]) {
      let r1 = arith_from_le(&r1_bytes);
      let one_arr = {
        let mut a = [0u8; 32];
        a[0] = 1;
        a
      };
      let max_arr = [0xffu8; 32];
      let half = Arith256::ONE << 255u32;

      for i in 0..256u32 {
        assert_eq!(Arith256::ONE << i, arith_from_le(&shift_array_left(&one_arr, i)));
        assert_eq!(half >> (255 - i), Arith256::ONE << i);
        assert_eq!(r1 << i, arith_from_le(&shift_array_left(&r1_bytes, i)));
        assert_eq!(r1 >> i, arith_from_le(&shift_array_right(&r1_bytes, i)));
        assert_eq!(Arith256::MAX << i, arith_from_le(&shift_array_left(&max_arr, i)));
        assert_eq!(Arith256::MAX >> i, arith_from_le(&shift_array_right(&max_arr, i)));
      }

      assert_eq!(Arith256::ONE << 256u32, Arith256::ZERO);
    }

    #[rstest]
    fn symmetry() {
      let c1 = Arith256::from_u64(0x0123456789abcdef);
      let c2 = c1 << 128u32;
      for i in 0..128u32 {
        assert_eq!(c1 << i, c2 >> (128 - i));
      }
      for i in 128..256u32 {
        assert_eq!(c1 << i, c2 << (i - 128));
      }
    }
  }

  mod bitwise {
    use super::*;

    #[rstest]
    fn against_bytes(r1_bytes: [u8; 32], r2_bytes: [u8; 32]) {
      let r1 = arith_from_le(&r1_bytes);
      let r2 = arith_from_le(&r2_bytes);

      let mut xor = [0u8; 32];
      let mut or = [0u8; 32];
      let mut and = [0u8; 32];
      for i in 0..32 {
        xor[i] = r1_bytes[i] ^ r2_bytes[i];
        or[i] = r1_bytes[i] | r2_bytes[i];
        and[i] = r1_bytes[i] & r2_bytes[i];
      }

      assert_eq!(r1 ^ r2, arith_from_le(&xor));
      assert_eq!(r1 | r2, arith_from_le(&or));
      assert_eq!(r1 & r2, arith_from_le(&and));
    }

    #[rstest]
    fn xor_cancellation(r1: Arith256, r2: Arith256) {
      assert_eq!((r1 ^ r2) ^ r1, r2);
    }

    #[rstest]
    fn not_against_bytes(r1_bytes: [u8; 32]) {
      let r1 = arith_from_le(&r1_bytes);
      let mut not = [0u8; 32];
      for i in 0..32 {
        not[i] = !r1_bytes[i];
      }
      assert_eq!(!r1, arith_from_le(&not));
    }

    #[rstest]
    fn neg() {
      assert_eq!(-Arith256::ZERO, Arith256::ZERO);
      assert_eq!(-Arith256::ONE, Arith256::MAX);
    }
  }

  mod comparison {
    use super::*;

    /// `(1 << i) | R1 >= R1` and related ordering
    /// properties at every bit position.
    #[rstest]
    fn exhaustive(r1: Arith256) {
      for i in 0..256u32 {
        let tmp = Arith256::ONE << i;
        assert!(tmp >= Arith256::ZERO);
        assert!(tmp > Arith256::ZERO);

        let tmp_or = tmp | r1;
        assert!(tmp_or >= r1);
        assert!((tmp_or == r1) != (tmp_or > r1));
      }
    }
  }

  mod methods {
    use super::*;

    #[rstest]
    fn to_f64_powers_of_two() {
      for i in 0..255u32 {
        let val = (Arith256::ONE << i).to_f64();
        let expected = (2.0_f64).powi(i as i32);
        assert_eq!(val, expected, "mismatch at 1 << {i}");
      }
      assert_eq!(Arith256::ZERO.to_f64(), 0.0);
    }

    /// `(R1 >> (256 - i)).to_f64()` is approximately
    /// `R1_DOUBLE * 2^i` for i in (53..256].
    #[rstest]
    fn to_f64_r1_shifted(r1: Arith256) {
      let r1_double = 0.488_737_459_055_930_9_f64;
      for i in (54..=256).rev() {
        let actual = (r1 >> (256 - i as u32)).to_f64();
        let expected = r1_double * (2.0_f64).powi(i);
        let rel_err = ((actual - expected) / actual).abs();
        assert!(rel_err < 1e-12, "to_f64 drift at i={i}: {actual} vs {expected}");
      }
    }

    /// For small shifts the result fits in u64, so to_f64
    /// must be exact.
    #[rstest]
    fn to_f64_exact_small(r1: Arith256) {
      let r1_top64 = (r1 >> 192u32).low_u64();
      for i in 1..=53u32 {
        let actual = (r1 >> (256 - i)).to_f64();
        let expected = (r1_top64 >> (64 - i)) as f64;
        assert_eq!(actual, expected, "exact mismatch at i={i}");
      }
    }

    #[rstest]
    fn to_f64_known_values() {
      assert_eq!(Arith256::ZERO.to_f64(), 0.0_f64);
      assert_eq!(Arith256::ONE.to_f64(), 1.0_f64);
      assert_eq!(Arith256::MAX.to_f64(), 1.157920892373162e77_f64);
      assert_eq!((Arith256::MAX >> 1u32).to_f64(), 5.78960446186581e76_f64);
      assert_eq!((Arith256::MAX >> 128u32).to_f64(), 3.402823669209385e38_f64);
      assert_eq!((Arith256::MAX >> (256 - 54) as u32).to_f64(), 1.8014398509481984e16_f64);
      // 53 bits and below should not use exponents
      assert_eq!((Arith256::MAX >> (256 - 53) as u32).to_f64(), 9007199254740991.0_f64);
      assert_eq!((Arith256::MAX >> (256 - 32) as u32).to_f64(), 4294967295.0_f64);
      assert_eq!((Arith256::MAX >> (256 - 16) as u32).to_f64(), 65535.0_f64);
      assert_eq!((Arith256::MAX >> (256 - 8) as u32).to_f64(), 255.0_f64);
    }

    /// Each `(1 << i) != Zero` and `R1 ^ (1 << i) != R1`.
    #[rstest]
    fn shifted_one_nonzero(r1: Arith256) {
      let tmp64 = 0xc4dab720d9c7acaa_u64;
      for i in 0..256u32 {
        assert_ne!(Arith256::ZERO, Arith256::ONE << i);
        assert_ne!(r1, r1 ^ (Arith256::ONE << i));
        assert_ne!(
          Arith256::from_u64(tmp64) ^ (Arith256::ONE << i),
          Arith256::from_u64(tmp64)
        );
      }
    }
  }

  mod u64_operand {
    use super::*;

    #[rstest]
    fn add_sub_wrap() {
      let mut v = Arith256::MAX;
      v += 1u64;
      assert_eq!(v, Arith256::ZERO);
      v -= 1u64;
      assert_eq!(v, Arith256::MAX);
      v -= u64::MAX;
      assert_eq!(v, Arith256::MAX - Arith256::from_u64(u64::MAX));
    }

    #[rstest]
    fn or_xor_leave_high_limbs(r1: Arith256) {
      let mut or = r1;
      or |= 0xff00_ff00_ff00_ff00u64;
      assert_eq!(or, r1 | Arith256::from_u64(0xff00_ff00_ff00_ff00));
      let mut xor = r1;
      xor ^= u64::MAX;
      assert_eq!(xor >> 64u32, r1 >> 64u32);
      assert_eq!(xor.low_u64(), !r1.low_u64());
    }

    #[rstest]
    #[case(0x1234_5678)]
    #[case(0x1_0000_0000)]
    #[case(u64::MAX)]
    fn div_matches_wide_divisor(r1: Arith256, #[case] d: u64) {
      assert_eq!(r1 / d, r1 / Arith256::from_u64(d));
      let mut v = r1;
      v /= d;
      assert_eq!(v, r1 / d);
    }

    #[rstest]
    fn div_by_zero_returns_zero(r1: Arith256) {
      assert_eq!(r1 / 0u64, Arith256::ZERO);
    }

    #[rstest]
    fn eq_compares_all_limbs(r1: Arith256) {
      assert!(Arith256::from_u64(42) == 42u64);
      assert!(Arith256::ZERO == 0u64);
      assert!(r1 != r1.low_u64());
      assert!((Arith256::ONE << 64u32) != 0u64);
    }
  }

  mod block_proof {
    use super::*;

    #[rstest]
    fn zero_min_max() {
      assert_eq!(Arith256::MAX.block_proof(), Arith256::ONE);
      assert_eq!(Arith256::ONE.block_proof(), Arith256::ONE << 255u32);
      assert_eq!(Arith256::ZERO.block_proof(), Arith256::ZERO);
    }

    #[rstest]
    fn pow_limit() {
      let target = (Arith256::ONE << 224u32) - Arith256::ONE;
      let expected = Arith256::ONE << 32u32;
      assert_eq!(target.block_proof(), expected);
    }
  }

  mod from_str {
    use super::*;

    #[rstest]
    fn display_round_trips(r1: Arith256) {
      assert_eq!(Arith256::from_str(&format!("{r1}")).unwrap(), r1);
      assert_eq!(Arith256::from_str(&format!("{:#x}", r1)).unwrap(), r1);
    }

    #[rstest]
    fn short_input_zero_extends() {
      assert_eq!(Arith256::from_str("ff").unwrap(), Arith256::from_u64(0xff));
    }

    #[rstest]
    fn rejects_over_long() {
      let long = "0".repeat(66);
      assert!(Arith256::from_str(&long).is_err());
    }
  }
}
