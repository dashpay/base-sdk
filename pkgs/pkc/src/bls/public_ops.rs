//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scheme-generic BLS public key.

use super::error::BlsError;
use super::scheme_ops::BlsScheme;
use super::{BlsPkBytes, BLS_PK_LEN};
use crate::prelude::*;

use dash_num::Hash256;
use dash_types::codec::TypeId;
use dash_types::{dlgt_codec, qtypestr, type_cvrt};
use hex_conservative::DisplayHex;

use core::any::type_name;
use core::fmt::{Debug, Formatter, Result as FmtResult};
use core::hash::{Hash, Hasher};

/// A BLS public key (48-byte compressed G1 point)
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "BlsPkBytes<S>", try_from = "BlsPkBytes<S>",))]
#[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
pub struct BlsPublicKey<S: BlsScheme>(pub(crate) S::InnerPk);

dlgt_codec!(for[S: BlsScheme] BlsPublicKey<S> => BlsPkBytes<S>, Hash256, BlsError, BLS_PK_LEN);

impl<S: BlsScheme> BlsPublicKey<S> {
  /// Deserialize from 48 bytes.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the bytes are not a valid point.
  pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, BlsError> {
    S::pk_from_bytes(bytes).map(Self)
  }

  /// Serialize to 48 bytes.
  pub fn to_bytes(&self) -> [u8; 48] {
    S::pk_to_bytes(&self.0)
  }

  /// Aggregate multiple public keys into one.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, or `InvalidPublicKey`
  /// when a key fails to aggregate.
  pub fn aggregate(keys: &[&Self]) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerPk> = keys.iter().map(|k| &k.0).collect();
    S::aggregate_pk(&inner_refs).map(Self::from_inner)
  }

  pub(crate) fn from_inner(inner: S::InnerPk) -> Self {
    Self(inner)
  }
}

impl<S: BlsScheme> Clone for BlsPublicKey<S> {
  fn clone(&self) -> Self {
    Self(self.0.clone())
  }
}

impl<S: BlsScheme> Debug for BlsPublicKey<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    qtypestr(f, type_name::<Self>())?;
    write!(f, "({})", self.to_bytes().as_hex())
  }
}

impl<S: BlsScheme> Eq for BlsPublicKey<S> {}

impl<S: BlsScheme> Hash for BlsPublicKey<S> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

impl<S: BlsScheme> PartialEq for BlsPublicKey<S> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}

impl<S: BlsScheme> TypeId for BlsPublicKey<S> {
  const TYPE_ID: u32 = S::PK_TYPE_ID;
}

type_cvrt!(for[S: BlsScheme] From<BlsPublicKey<S>> for BlsPkBytes<S>, |pk| {
  Self::from_bytes(pk.to_bytes())
});

type_cvrt!(for[S: BlsScheme] TryFrom<BlsPkBytes<S>> for BlsPublicKey<S>, BlsError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

#[cfg(all(test, feature = "tests"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::{SEED_0, SEED_1};
  use crate::bls::{BlsScChia, BlsScIetf, BlsSecretKey};

  use cfg_if::cfg_if;
  use dash_dev::{arr_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct PkSerVec {
    pk_legacy: String,
    pk_ietf: String,
  }

  #[derive(Deserialize)]
  struct AggPkVec {
    pks: Vec<String>,
    agg_pk: String,
  }

  #[derive(Deserialize)]
  struct DhVec {
    sk: String,
    peer_pk: String,
    shared: String,
  }

  fn assert_dh_matches_vectors<S: BlsScheme>(corpus: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), corpus);
    let vecs: Vec<DhVec> = corpus.vectors("dh_exchange");

    for v in &vecs {
      let sk = BlsSecretKey::<S>::from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let peer = BlsPublicKey::<S>::from_bytes(&arr_from_hex(&v.peer_pk)).unwrap();
      let shared = sk.dh_exchange(&peer).unwrap();
      assert_eq!(shared.to_bytes().to_lower_hex_string(), v.shared);
    }
  }

  #[rstest]
  #[case::chia(assert_dh_matches_vectors::<BlsScChia>, "bls_chia_dh")]
  #[case::ietf(assert_dh_matches_vectors::<BlsScIetf>, "bls_ietf_dh")]
  fn dh_exchange_matches_vectors(#[case] assertion: fn(&str), #[case] corpus: &str) {
    assertion(corpus);
  }

  fn assert_dh_roundtrip<S: BlsScheme>() {
    let sk_a = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let sk_b = BlsSecretKey::<S>::generate(&SEED_1).unwrap();

    let shared_ab = sk_a.dh_exchange(&sk_b.public_key()).unwrap();
    let shared_ba = sk_b.dh_exchange(&sk_a.public_key()).unwrap();
    assert_eq!(shared_ab.to_bytes(), shared_ba.to_bytes());
  }

  #[rstest]
  #[case::chia(assert_dh_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_dh_roundtrip::<BlsScIetf>)]
  fn dh_exchange_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_pk_roundtrip<S: BlsScheme>() {
    let pk = BlsSecretKey::<S>::generate(&SEED_0).unwrap().public_key();
    let bytes = pk.to_bytes();
    assert_eq!(BlsPublicKey::<S>::from_bytes(&bytes).unwrap().to_bytes(), bytes);
  }

  #[rstest]
  #[case::chia(assert_pk_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_pk_roundtrip::<BlsScIetf>)]
  fn serialization_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  /// The legacy decoder rejects the infinity marker rather than yielding an
  /// identity public key.
  #[rstest]
  fn chia_rejects_identity_public_key() {
    let mut infinity = [0u8; 48];
    infinity[0] = 0xc0;
    assert!(BlsPublicKey::<BlsScChia>::from_bytes(&infinity).is_err());
  }

  /// The legacy decoder normalizes stray high bits, so a mutated encoding
  /// round-trips back to its canonical form.
  #[rstest]
  fn chia_masks_stray_public_key_bits() {
    let clean = BlsSecretKey::<BlsScChia>::generate(&SEED_0)
      .unwrap()
      .public_key()
      .to_bytes();

    let mut mutated = clean;
    mutated[0] |= 0x20;
    let decoded = BlsPublicKey::<BlsScChia>::from_bytes(&mutated).unwrap();
    assert_eq!(decoded.to_bytes(), clean);
  }

  /// The same G1 point encodes differently under the two schemes, and the
  /// legacy encoding must round-trip through the wrapper.
  #[rstest]
  fn serialization_formats_match_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_chia_ser_internals");
    let vecs: Vec<PkSerVec> = corpus.vectors("pk_serialization");

    for v in &vecs {
      let legacy = BlsPublicKey::<BlsScChia>::from_bytes(&arr_from_hex(&v.pk_legacy)).unwrap();
      assert_eq!(legacy.to_bytes().to_lower_hex_string(), v.pk_legacy);

      assert_ne!(v.pk_legacy, v.pk_ietf, "legacy and ietf should differ");
    }
  }

  fn assert_aggregate_vectors<S: BlsScheme>(corpus: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), corpus);
    let vecs: Vec<AggPkVec> = corpus.vectors("aggregate_pk");

    for v in &vecs {
      let pks: Vec<BlsPublicKey<S>> = v
        .pks
        .iter()
        .map(|pk| BlsPublicKey::<S>::from_bytes(&arr_from_hex(pk)).unwrap())
        .collect();
      let refs: Vec<&BlsPublicKey<S>> = pks.iter().collect();
      let agg = BlsPublicKey::<S>::aggregate(&refs).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_pk);
    }
  }

  #[rstest]
  #[case::chia(assert_aggregate_vectors::<BlsScChia>, "bls_chia_aggregate")]
  #[case::ietf(assert_aggregate_vectors::<BlsScIetf>, "bls_ietf_aggregate")]
  fn aggregate_matches_vectors(#[case] assertion: fn(&str), #[case] corpus: &str) {
    assertion(corpus);
  }

  cfg_if! {
    if #[cfg(feature = "serde")] {
      use dash_dev::assert_json_rt;

      #[rstest]
      fn serde_roundtrip() {
        let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_chia_ser_internals");
        let v = corpus.vectors::<PkSerVec>("pk_serialization").swap_remove(0);

        assert_json_rt(&BlsPublicKey::<BlsScChia>::from_bytes(&arr_from_hex(&v.pk_legacy)).unwrap());
        assert_json_rt(&BlsPublicKey::<BlsScIetf>::from_bytes(&arr_from_hex(&v.pk_ietf)).unwrap());
      }
    }
  }
}
