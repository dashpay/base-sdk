//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Diffie-Hellman exchange tests for bls_chia.

#![expect(clippy::unwrap_used, reason = "test code")]

use common::*;
use dash_pkc::bls::tests as common;
use dash_pkc::bls_chia::{PublicKey, SecretKey};
use rstest::*;

/// DH exchange produces a shared secret.
#[rstest]
fn dh_exchange_roundtrip(chia_sk0: SecretKey, chia_sk1: SecretKey) {
  let pk0 = chia_sk0.public_key();
  let pk1 = chia_sk1.public_key();
  // sk0 * pk1 == sk1 * pk0
  let shared_a = PublicKey::dh_exchange(&chia_sk0, &pk1).unwrap();
  let shared_b = PublicKey::dh_exchange(&chia_sk1, &pk0).unwrap();
  assert_eq!(shared_a.to_bytes(), shared_b.to_bytes());
}

/// Reference vectors through the public wrapper.
///
/// The scheme-level KAT pins `dh_exchange` on the trait; this pins that
/// `PublicKey::dh_exchange` is still wired to it.
mod kat {
  use dash_dev::{arr_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct DhVector {
    sk: String,
    peer_pk: String,
    shared: String,
  }

  #[test]
  fn public_api_dh_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_chia_dh");
    for v in corpus.vectors::<DhVector>("dh_exchange") {
      let sk = super::SecretKey::from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let peer = super::PublicKey::from_bytes(&arr_from_hex(&v.peer_pk)).unwrap();
      let shared = super::PublicKey::dh_exchange(&sk, &peer).unwrap();
      assert_eq!(shared.to_bytes().to_lower_hex_string(), v.shared);
    }
  }
}
