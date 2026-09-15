//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 constants.

use super::secret_bytes::ECDSA_SK_LEN;

use hex_conservative::hex;

/// DER lengths of a private key with a compressed and an uncompressed public
/// key respectively.
pub(super) const DER_SIZES: &[usize] = &[214, 279];

/// ASN.1 object identifier for a prime-field curve.
pub(super) const OID_PRIME_FIELD: &[u8] = &hex!("2a8648ce3d0101");

/// The field prime.
pub(super) const PRIME: &[u8; ECDSA_SK_LEN] = &hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

/// The group order.
pub(super) const ORDER: &[u8; ECDSA_SK_LEN] = &hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

/// The generator point in SEC1 uncompressed form.
pub(super) const GENERATOR: &[u8; 65] = &hex!(
  "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
   483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
);

/// The generator point in SEC1 compressed form.
pub(super) const GENERATOR_COMPRESSED: [u8; 33] =
  hex!("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

#[cfg(test)]
mod tests {
  use super::{GENERATOR, GENERATOR_COMPRESSED, ORDER};

  use hex_conservative::DisplayHex;
  use k256::elliptic_curve::sec1::ToSec1Point;
  use k256::elliptic_curve::PrimeField;
  use rstest::rstest;

  #[rstest]
  fn constants_match_k256() {
    let generator = k256::AffinePoint::GENERATOR;

    assert_eq!(generator.to_sec1_point(false).as_bytes(), &GENERATOR[..]);
    assert_eq!(generator.to_sec1_point(true).as_bytes(), &GENERATOR_COMPRESSED[..]);
    assert_eq!(ORDER.to_upper_hex_string(), <k256::Scalar as PrimeField>::MODULUS);
  }
}
