//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS12-381 constants.

use super::scalar::Fr;

use hex_conservative::hex;

/// Two-adicity of `r - 1`, the number of times two divides it.
pub(super) const S: u32 = 32;

/// The field order, as `ff` asks it to be spelled.
pub(super) const MODULUS: &str = "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

/// `(t - 1) / 2`, where `t` is the odd part of `r - 1`, little-endian.
pub(super) const T_MINUS_1_DIV_2: [u64; 4] = [
  0x7fff_2dff_7fff_ffff,
  0x04d0_ec02_a9de_d201,
  0x94ce_bea4_199c_ec04,
  0x0000_0000_39f6_d3a9,
];

/// Zero.
pub(super) const ZERO: Fr = Fr::from_limbs([0, 0, 0, 0]);

/// One.
pub(super) const ONE: Fr = Fr::from_limbs([
  0x0000_0001_ffff_fffe,
  0x5884_b7fa_0003_4802,
  0x998c_4fef_ecbc_4ff5,
  0x1824_b159_acc5_056f,
]);

/// The inverse of two.
pub(super) const TWO_INV: Fr = Fr::from_limbs([
  0x0000_0000_ffff_ffff,
  0xac42_5bfd_0001_a401,
  0xccc6_27f7_f65e_27fa,
  0x0c12_58ac_d662_82b7,
]);

/// A generator of the multiplicative group, seven for this field.
pub(super) const MULTIPLICATIVE_GENERATOR: Fr = Fr::from_limbs([
  0x0000_000e_ffff_fff1,
  0x17e3_63d3_0018_9c0f,
  0xff9c_5787_6f84_57b0,
  0x3513_3220_8fc5_a8c4,
]);

/// A primitive root of unity of order `2^S`, the generator raised to `t`.
pub(super) const ROOT_OF_UNITY: Fr = Fr::from_limbs([
  0xb9b5_8d8c_5f0e_466a,
  0x5b1b_4c80_1819_d7ec,
  0x0af5_3ae3_52a3_1e64,
  0x5bf3_adda_19e9_b27b,
]);

/// The inverse of [`ROOT_OF_UNITY`].
pub(super) const ROOT_OF_UNITY_INV: Fr = Fr::from_limbs([
  0x4256_481a_dcf3_219a,
  0x45f3_7b7f_96b6_cad3,
  0xf9c3_f1d7_5f7a_3b27,
  0x2d2f_c049_658a_fd43,
]);

/// The generator raised to `2^S`, a non-square by construction.
pub(super) const DELTA: Fr = Fr::from_limbs([
  0x70e3_10d3_d146_f96a,
  0x4b64_c089_19e2_99e6,
  0x51e1_1418_6a8b_970d,
  0x6185_d066_27c0_67cb,
]);

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
  use crate::prelude::*;

  use ff::{Field, PrimeField};
  use hex_conservative::DisplayHex;
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
  /// `t`, the odd part of `r - 1`, little-endian.
  ///
  /// Doubling [`T_MINUS_1_DIV_2`] and restoring the low bit, in plain integer
  /// arithmetic so the field plays no part in the exponent it is tested with.
  fn odd_part() -> [u64; 4] {
    let mut t = [0u64; 4];
    let mut carry = 1u64;
    for (out, limb) in t.iter_mut().zip(T_MINUS_1_DIV_2) {
      *out = (limb << 1) | carry;
      carry = limb >> 63;
    }
    t
  }

  /// Exponentiation by squaring over a little-endian limb exponent.
  fn pow(base: Fr, exp: &[u64; 4]) -> Fr {
    let mut acc = ONE;
    for limb in exp.iter().rev() {
      for bit in (0..64).rev() {
        acc = acc.square();
        if (limb >> bit) & 1 == 1 {
          acc *= base;
        }
      }
    }
    acc
  }

  /// The two constants blst can hand back directly.
  #[rstest]
  #[case::zero(ZERO, 0)]
  #[case::one(ONE, 1)]
  #[case::generator(MULTIPLICATIVE_GENERATOR, 7)]
  fn small_constants_match_blst(#[case] literal: Fr, #[case] value: u64) {
    assert_eq!(literal, Fr::from(value));
  }

  /// The inverses come from blst's own inversion rather than from a product
  /// with the value they invert, so a matched pair of wrong literals cannot
  /// satisfy the check between them.
  #[rstest]
  #[case::two_inv(TWO_INV, Fr::from(2))]
  #[case::root_of_unity_inv(ROOT_OF_UNITY_INV, ROOT_OF_UNITY)]
  fn inverses_match_blst(#[case] literal: Fr, #[case] of: Fr) {
    assert_eq!(literal, of.invert().unwrap());
  }

  /// `ff` specifies the root as the generator raised to the odd part of
  /// `r - 1`, which is one value; having order `2^S` admits every primitive
  /// root and so would not pin it.
  #[rstest]
  fn root_of_unity_is_the_generator_raised_to_the_odd_part() {
    assert_eq!(ROOT_OF_UNITY, pow(MULTIPLICATIVE_GENERATOR, &odd_part()));
  }

  /// Squaring the root `S` times reaches one and `S - 1` times does not, so
  /// its order is exactly `2^S` and `S` is the two-adicity it claims.
  #[rstest]
  fn root_of_unity_has_the_stated_order() {
    let mut acc = ROOT_OF_UNITY;
    for _ in 0..S - 1 {
      acc = acc.square();
    }
    assert_ne!(acc, ONE);
    assert_eq!(acc.square(), ONE);
  }

  #[rstest]
  fn delta_is_the_generator_raised_to_two_to_the_s() {
    let mut delta = MULTIPLICATIVE_GENERATOR;
    for _ in 0..S {
      delta = delta.square();
    }
    assert_eq!(DELTA, delta);
  }

  /// The odd part is odd and restores `r - 1` once the power of two is put
  /// back, which is the whole of what makes `S` and `t` a valid split.
  #[rstest]
  fn odd_part_rebuilds_the_order() {
    let t = odd_part();
    assert_eq!(t[0] & 1, 1, "the odd part must be odd");

    let mut rebuilt = pow(MULTIPLICATIVE_GENERATOR, &t);
    for _ in 0..S {
      rebuilt = rebuilt.square();
    }
    assert_eq!(rebuilt, ONE, "g^(t * 2^S) is g^(r - 1), which is one");
  }

  /// The string is the field order, one past the largest element.
  #[rstest]
  fn modulus_string_matches_the_order() {
    let mut order = (-ONE).to_repr();
    order.reverse();
    let last = order.len() - 1;
    order[last] += 1;

    assert_eq!(format!("0x{}", order.as_hex()), MODULUS);
  }

  #[rstest]
  fn montgomery_form_is_what_the_literals_assume() {
    let mut expected = [0u8; 32];
    expected[0] = 1;
    assert_eq!(ONE.to_repr(), expected);
  }
}
