//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Serialization format KAT tests for bls_chia.

#![expect(clippy::unwrap_used, reason = "test code")]

mod common;

mod kat {
  use super::common::{self, VectorFile};

  use dash_dev::vec_from_hex;
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct SerInternalVector {
    pk_legacy: String,
    pk_ietf: String,
  }

  #[derive(Deserialize)]
  struct SigSerInternalVector {
    sig_legacy: String,
    sig_ietf: String,
  }

  /// Validate that the same G1 point serializes differently
  /// under legacy vs IETF formats.
  #[test]
  fn kat_ser_pk_formats() {
    let f: VectorFile = common::load("bls_chia_ser_internals");
    let vecs: Vec<SerInternalVector> = common::parse_sub(&f, "pk_serialization");

    for v in &vecs {
      // Legacy bytes should deserialize and re-serialize
      // identically.
      let legacy_bytes: [u8; 48] = vec_from_hex(&v.pk_legacy).try_into().unwrap();
      let pk = dash_pkc::bls_chia::PublicKey::from_bytes(&legacy_bytes).unwrap();
      assert_eq!(
        pk.to_bytes().to_lower_hex_string(),
        v.pk_legacy,
        "legacy pk roundtrip mismatch"
      );

      // The two formats must differ for the same point.
      assert_ne!(v.pk_legacy, v.pk_ietf, "legacy and ietf should differ");
    }
  }

  /// Validate legacy G2 serialization roundtrip.
  #[test]
  fn kat_ser_sig_formats() {
    let f: VectorFile = common::load("bls_chia_ser_internals");
    let vecs: Vec<SigSerInternalVector> = common::parse_sub(&f, "sig_serialization");

    for v in &vecs {
      let legacy_bytes: [u8; 96] = vec_from_hex(&v.sig_legacy).try_into().unwrap();
      let sig = dash_pkc::bls_chia::Signature::from_bytes(&legacy_bytes).unwrap();
      assert_eq!(
        sig.to_bytes().to_lower_hex_string(),
        v.sig_legacy,
        "legacy sig roundtrip mismatch"
      );

      assert_ne!(v.sig_legacy, v.sig_ietf, "legacy and ietf should differ");
    }
  }
}

/// The identity passes the subgroup check yet verifies any message, so the
/// decoder rejects the canonical infinity encoding for both public keys and
/// signatures.
#[test]
fn rejects_identity_public_key() {
  let mut bytes = [0u8; 48];
  bytes[0] = 0xc0; // compressed identity marker
  assert!(dash_pkc::bls_chia::PublicKey::from_bytes(&bytes).is_err());
}

#[test]
fn rejects_identity_signature() {
  let mut bytes = [0u8; 96];
  bytes[0] = 0xc0; // compressed identity marker
  assert!(dash_pkc::bls_chia::Signature::from_bytes(&bytes).is_err());
}

/// Only bit 7 of byte 0 is the legacy sign flag. Stray high bits are
/// masked in G1 (the reference masks them too) but rejected in G2, where
/// the reference reads them as an out-of-range `x >= p` coordinate.
#[test]
fn masks_g1_and_rejects_g2_stray_high_bits() {
  let sk = dash_pkc::bls_chia::SecretKey::generate(&[7u8; 32]).unwrap();

  let clean = sk.public_key().to_bytes();
  let mut pk = clean;
  pk[0] |= 0x20;
  let decoded = dash_pkc::bls_chia::PublicKey::from_bytes(&pk).unwrap();
  assert_eq!(decoded.to_bytes(), clean);

  let sig = sk.sign(&[0x55u8; 32]).to_bytes();
  for (index, mask) in [(0, 0x20), (48, 0x40)] {
    let mut bytes = sig;
    bytes[index] |= mask;
    assert!(dash_pkc::bls_chia::Signature::from_bytes(&bytes).is_err());
  }
}

/// The y-sign convention (c1 compared against `(p-1)/2`) must be stable
/// across a serialize/parse/serialize round-trip.
#[test]
fn signature_serialization_is_idempotent() {
  let sk = dash_pkc::bls_chia::SecretKey::generate(&[9u8; 32]).unwrap();
  let once = sk.sign(&[0x44u8; 32]).to_bytes();
  let twice = dash_pkc::bls_chia::Signature::from_bytes(&once).unwrap().to_bytes();
  assert_eq!(once, twice);
}
