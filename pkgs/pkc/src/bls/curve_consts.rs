//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS12-381 constants.

use hex_conservative::hex;

/// BLS12-381 curve parameter `|x|`, little-endian.
///
/// `x = -(2^63 + 2^62 + 2^60 + 2^57 + 2^48 + 2^16)`, so callers multiply by
/// the magnitude and negate.
pub(super) const BLS_X_LE: [u8; 8] = hex!("00000100000001d2");

/// Bit width of [`BLS_X_LE`].
pub(super) const BLS_X_BITS: usize = 64;

/// `sqrt(-3) mod p`, for the Shallue-van de Woestijne map.
pub(super) const S3: [u8; 48] =
  hex!("0000000000000000be32ce5fbeed9ca374d38c0ed41eefd5bb675277cdf12d11bc2fb026c41400045c03fffffffdfffd");

/// `(sqrt(-3) - 1) / 2 mod p`, for the same map.
pub(super) const S32: [u8; 48] =
  hex!("00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe");

/// The Montgomery radix `2^384 mod p`, for folding a wide value into `Fp`.
///
/// Named for the radix rather than the group order: this is `R`, not `r`.
pub(super) const MONT_R_MOD_P: [u8; 48] =
  hex!("15f65ec3fa80e4935c071a97a256ec6d77ce5853705257455f48985753c758baebf4000bc40c0002760900000002fffd");

/// `(p - 1) / 2`, the midpoint the legacy sign convention compares against.
pub(super) const HALF_P: [u8; 48] =
  hex!("0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555");

/// `c1` of the Frobenius `psi` x-coefficient on the M-type twist; `c0` is
/// zero, so only this half is carried.
pub(super) const PSI_COEFF_X_C1: [u8; 48] =
  hex!("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad");

/// `c0` of the Frobenius `psi` y-coefficient.
pub(super) const PSI_COEFF_Y_C0: [u8; 48] =
  hex!("135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2");

/// `c1` of the Frobenius `psi` y-coefficient.
pub(super) const PSI_COEFF_Y_C1: [u8; 48] =
  hex!("06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09");

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::scalar::{Fp, Fp2};

  use rstest::rstest;

  /// The curve parameter is read little-endian, so the bytes as written are the
  /// magnitude the cofactor routine multiplies by.
  #[rstest]
  fn bls_x_is_the_curve_parameter() {
    assert_eq!(u64::from_le_bytes(BLS_X_LE), 0xd201_0000_0001_0000);
    assert_eq!(BLS_X_BITS, u64::BITS as usize);
  }

  /// Stated as `2 * HALF_P + 1 == p` by way of `-1`, the largest element, since
  /// `p` itself is not a representable field value.
  #[rstest]
  fn half_p_is_the_field_midpoint() {
    let half = Fp::from(&HALF_P);
    assert_eq!(half + half, -Fp::from_u64(1));
  }

  #[rstest]
  fn s3_squares_to_minus_three() {
    let s3 = Fp::from(&S3);
    assert_eq!(s3 * s3, -Fp::from_u64(3));
  }

  /// Stated as `2 * S32 + 1 == S3` so the check needs no division.
  #[rstest]
  fn s32_is_s3_less_one_halved() {
    let s32 = Fp::from(&S32);
    assert_eq!(s32 + s32 + Fp::from_u64(1), Fp::from(&S3));
  }

  #[rstest]
  fn mont_r_is_two_to_the_384() {
    let mut acc = Fp::from_u64(1);
    for _ in 0..384 {
      acc = acc + acc;
    }
    assert_eq!(acc, Fp::from(&MONT_R_MOD_P));
  }

  /// `psi` untwists, so its coefficients are the reciprocals
  /// `1/(1+u)^((p-1)/3)` and `1/(1+u)^((p-1)/2)`.
  ///
  /// Cubing and squaring them clears the fractional exponent, and Frobenius
  /// gives `(1+u)^p = 1-u`, so each reduces to `(1+u)/(1-u)` and the check
  /// needs no 381-bit exponent of its own.
  #[rstest]
  fn psi_coefficients_untwist_the_frobenius() {
    let one = Fp::from_u64(1);
    let plus = Fp2::new(one, one);
    let minus = Fp2::new(one, -one);

    let psi_x = Fp2::new(Fp::default(), Fp::from(&PSI_COEFF_X_C1));
    let psi_y = Fp2::new(Fp::from(&PSI_COEFF_Y_C0), Fp::from(&PSI_COEFF_Y_C1));

    assert_eq!(psi_x.c0(), Fp::default(), "the x coefficient is purely imaginary");
    assert_eq!(psi_x * psi_x * psi_x * minus, plus);
    assert_eq!(psi_y * psi_y * minus, plus);
  }
}
