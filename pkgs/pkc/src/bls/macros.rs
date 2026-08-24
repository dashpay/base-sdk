//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared macro definitions.

/// Implements the `group` traits over one curve group.
macro_rules! impl_group {
  ($name:ident, $affine:ty, $len:expr) => {
    impl<'a> Add<&'a Self> for $name {
      type Output = Self;

      fn add(self, rhs: &'a Self) -> Self::Output {
        self + *rhs
      }
    }

    impl AddAssign for $name {
      fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
      }
    }

    impl<'a> AddAssign<&'a Self> for $name {
      fn add_assign(&mut self, rhs: &'a Self) {
        *self = *self + *rhs;
      }
    }

    impl Debug for $name {
      fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, concat!(stringify!($name), "({})"), self.to_bytes().as_ref().as_hex())
      }
    }

    impl Eq for $name {}

    impl Group for $name {
      type Scalar = Fr;

      fn identity() -> Self {
        Self::default()
      }

      fn generator() -> Self {
        Self::generator()
      }

      fn is_identity(&self) -> Choice {
        Choice::from(u8::from(self.is_inf()))
      }

      fn double(&self) -> Self {
        Self::double(self)
      }

      fn try_random<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        Ok(<Self as Group>::generator() * Fr::try_random(rng)?)
      }
    }

    impl GroupEncoding for $name {
      type Repr = BlsPointRepr<$len>;

      fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        // The subgroup check is the difference from `from_bytes_unchecked`:
        // the encoding only pins a curve point, and a point off the prime-order
        // subgroup breaks the arithmetic every caller assumes.
        match <$affine>::uncompress(bytes.as_bytes()) {
          Ok(affine) => {
            let point = affine.to_projective();
            let ok = point.in_subgroup();
            CtOption::new(point, Choice::from(u8::from(ok)))
          }
          Err(_) => CtOption::new(<Self as Group>::identity(), Choice::from(0)),
        }
      }

      fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        match <$affine>::uncompress(bytes.as_bytes()) {
          Ok(affine) => CtOption::new(affine.to_projective(), Choice::from(1)),
          Err(_) => CtOption::new(<Self as Group>::identity(), Choice::from(0)),
        }
      }

      fn to_bytes(&self) -> Self::Repr {
        BlsPointRepr(self.to_affine().compress())
      }
    }

    impl Mul<Fr> for $name {
      type Output = Self;

      fn mul(self, rhs: Fr) -> Self::Output {
        self.mul_scalar(&rhs.to_repr(), FR_BITS)
      }
    }

    impl<'a> Mul<&'a Fr> for $name {
      type Output = Self;

      fn mul(self, rhs: &'a Fr) -> Self::Output {
        self * *rhs
      }
    }

    impl MulAssign<Fr> for $name {
      fn mul_assign(&mut self, rhs: Fr) {
        *self = *self * rhs;
      }
    }

    impl<'a> MulAssign<&'a Fr> for $name {
      fn mul_assign(&mut self, rhs: &'a Fr) {
        *self = *self * *rhs;
      }
    }

    impl PartialEq for $name {
      fn eq(&self, other: &Self) -> bool {
        self.is_equal(other)
      }
    }

    impl Sub for $name {
      type Output = Self;

      fn sub(self, rhs: Self) -> Self::Output {
        self + -rhs
      }
    }

    impl<'a> Sub<&'a Self> for $name {
      type Output = Self;

      fn sub(self, rhs: &'a Self) -> Self::Output {
        self - *rhs
      }
    }

    impl SubAssign for $name {
      fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
      }
    }

    impl<'a> SubAssign<&'a Self> for $name {
      fn sub_assign(&mut self, rhs: &'a Self) {
        *self = *self - *rhs;
      }
    }

    impl<'a> Sum<&'a Self> for $name {
      fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(<Self as Group>::identity(), |acc, x| acc + x)
      }
    }

    impl Sum for $name {
      fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(<Self as Group>::identity(), |acc, x| acc + x)
      }
    }
  };
}

pub(super) use impl_group;
