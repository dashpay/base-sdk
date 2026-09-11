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
