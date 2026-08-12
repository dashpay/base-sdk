//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scheme-generic BLS secret key.

use super::dh_bytes::BlsDhBytes;
use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::BlsScheme;
use super::sig_basic::BlsSignature;
use super::{BlsScIetf, BlsSigId, BlsSkBytes, BLS_SK_LEN};
use crate::prelude::*;

use dash_num::Hash256;
use dash_types::codec::TypeId;
use dash_types::{dlgt_scodec, qtypestr, type_cvrt};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use core::fmt::{Debug, Formatter, Result as FmtResult};

/// A BLS secret key (32-byte scalar).
pub struct BlsSecretKey<S: BlsScheme>(pub(crate) S::InnerSk);

dlgt_scodec!(for[S: BlsScheme] BlsSecretKey<S> => BlsSkBytes<S>, Hash256, BlsError, BLS_SK_LEN);

impl<S: BlsScheme> BlsSecretKey<S> {
  /// Derive a secret key from input keying material (>= 32 bytes).
  ///
  /// # Errors
  ///
  /// Returns `InvalidKeyMaterial` or `InvalidSecretKey` when `ikm`
  /// is shorter than 32 bytes.
  pub fn generate(ikm: &[u8]) -> Result<Self, BlsError> {
    S::generate(ikm).map(Self)
  }

  /// Parse from a 32-byte big-endian scalar.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSecretKey` when the bytes are not a valid scalar.
  pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BlsError> {
    S::sk_from_bytes(bytes).map(Self)
  }

  /// Serialize to 32 bytes, wiped when the returned value drops.
  pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(S::sk_to_bytes(&self.0))
  }

  /// Derive the corresponding public key.
  pub fn public_key(&self) -> BlsPublicKey<S> {
    BlsPublicKey(S::derive_pk(&self.0))
  }

  /// Sign a message of the scheme's message type.
  pub fn sign(&self, msg: &S::Msg) -> BlsSignature<S> {
    BlsSignature::from_inner(S::sign(&self.0, msg))
  }

  /// Compute a DH shared key: `self * peer_pk`.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the peer key or the product point
  /// is invalid.
  pub fn dh_exchange(&self, peer_pk: &BlsPublicKey<S>) -> Result<BlsDhBytes<S>, BlsError> {
    let shared = S::dh_exchange(&self.0, &peer_pk.0)?;
    Ok(BlsDhBytes::from_bytes(S::pk_to_bytes(&shared)))
  }

  /// Sum multiple secret keys (mod group order).
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, or `InvalidSecretKey`
  /// when the sum is not a valid scalar.
  pub fn aggregate(keys: &[&Self]) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerSk> = keys.iter().map(|k| &k.0).collect();
    S::aggregate_sk(&inner_refs).map(Self::from_inner)
  }

  pub(crate) fn from_inner(inner: S::InnerSk) -> Self {
    Self(inner)
  }
}

impl BlsSecretKey<BlsScIetf> {
  /// Sign under the domain separation tag selected by `scheme`.
  pub fn sign_with(&self, msg: &[u8], scheme: BlsSigId) -> BlsSignature<BlsScIetf> {
    BlsSignature::from_inner(BlsScIetf::sign_with(&self.0, msg, scheme))
  }
}

impl<S: BlsScheme> Clone for BlsSecretKey<S> {
  fn clone(&self) -> Self {
    Self(self.0.clone())
  }
}

impl<S: BlsScheme> Drop for BlsSecretKey<S> {
  fn drop(&mut self) {
    self.zeroize();
  }
}

impl<S: BlsScheme> Debug for BlsSecretKey<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    qtypestr(f, core::any::type_name::<Self>())?;
    f.write_str("(..)")
  }
}

impl<S: BlsScheme> Eq for BlsSecretKey<S> {}

impl<S: BlsScheme> PartialEq for BlsSecretKey<S> {
  fn eq(&self, other: &Self) -> bool {
    use subtle::ConstantTimeEq;
    (*self.to_bytes()).ct_eq(&*other.to_bytes()).into()
  }
}

impl<S: BlsScheme> Zeroize for BlsSecretKey<S> {
  fn zeroize(&mut self) {
    S::zeroize_sk(&mut self.0);
  }
}

impl<S: BlsScheme> ZeroizeOnDrop for BlsSecretKey<S> {}

impl<S: BlsScheme> TypeId for BlsSecretKey<S> {
  const TYPE_ID: u32 = S::SK_TYPE_ID;
}

type_cvrt!(for[S: BlsScheme] From<BlsSecretKey<S>> for BlsSkBytes<S>, |sk| {
  Self::from_bytes(*sk.to_bytes())
});

type_cvrt!(for[S: BlsScheme] TryFrom<BlsSkBytes<S>> for BlsSecretKey<S>, BlsError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::{RSEED, SEED_0};
  use crate::bls::{BlsScChia, BlsScIetf};

  use dash_dev::{arr_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct KeygenVec {
    sk: String,
    pk: String,
  }

  #[derive(Deserialize)]
  struct AggSkVec {
    sks: Vec<String>,
    agg_sk: String,
  }

  fn assert_roundtrip<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let bytes = sk.to_bytes();
    let decoded = BlsSecretKey::<S>::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
  }

  #[rstest]
  #[case::chia(assert_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_roundtrip::<BlsScIetf>)]
  fn serialization_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_derive_pk<S: BlsScheme>(corpus: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), corpus);
    let vecs: Vec<KeygenVec> = corpus.vectors("derive_pk");
    for v in &vecs {
      let sk = BlsSecretKey::<S>::from_bytes(&arr_from_hex(&v.sk)).unwrap();
      assert_eq!(sk.public_key().to_bytes().to_lower_hex_string(), v.pk);
    }
  }

  #[rstest]
  #[case::chia(assert_derive_pk::<BlsScChia>, "bls_chia_keygen")]
  #[case::ietf(assert_derive_pk::<BlsScIetf>, "bls_ietf_keygen")]
  fn derive_public_key_matches_vectors(#[case] assertion: fn(&str), #[case] corpus: &str) {
    assertion(corpus);
  }

  /// Key generation follows the KeyGen of draft-irtf-cfrg-bls-signature-03
  /// for both schemes; another variant would change these bytes.
  fn assert_keygen_draft03<S: BlsScheme>(ikm: &[u8], expected: &str) {
    let sk = BlsSecretKey::<S>::generate(ikm).unwrap();
    assert_eq!(sk.to_bytes().to_lower_hex_string(), expected);
  }

  #[rstest]
  #[case::seed0(&RSEED[0], "4a353be3dac091a0a7e640620372f5e1e2e4401717c1e79cac6ffba8f6905604")]
  #[case::seed1(&RSEED[1], "6fc9d9a2b05fd1f0e51bc91041a03be8657081f272ec281aff731624f0d1c220")]
  #[case::seed2(&RSEED[2], "01433a85a09ef4c9f7a2cd973c007c1150631a35a1d0e199eca4364e051809bb")]
  fn keygen_uses_draft03_variant(#[case] ikm: &[u8], #[case] expected: &str) {
    assert_keygen_draft03::<BlsScChia>(ikm, expected);
    assert_keygen_draft03::<BlsScIetf>(ikm, expected);
  }

  /// The keygen variant requires at least 32 bytes of input key material.
  fn assert_short_ikm_rejected<S: BlsScheme>() {
    assert!(BlsSecretKey::<S>::generate(&[0u8; 31]).is_err());
  }

  #[rstest]
  #[case::chia(assert_short_ikm_rejected::<BlsScChia>)]
  #[case::ietf(assert_short_ikm_rejected::<BlsScIetf>)]
  fn generate_rejects_short_ikm(#[case] assertion: fn()) {
    assertion();
  }

  /// One secret scalar derives two differently encoded public keys, so a
  /// scheme mix-up cannot go unnoticed.
  #[rstest]
  fn public_key_formats_differ() {
    let chia = BlsSecretKey::<BlsScChia>::generate(&SEED_0).unwrap();
    let ietf = BlsSecretKey::<BlsScIetf>::from_bytes(&chia.to_bytes()).unwrap();
    assert_ne!(chia.public_key().to_bytes(), ietf.public_key().to_bytes());
  }

  fn assert_codec_roundtrip<S: BlsScheme>() {
    use dash_types::codec::BaseCodec;

    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let mut buf = Vec::new();
    sk.encode(&mut buf);
    assert_eq!(buf.len(), 32);

    let mut slice = buf.as_slice();
    let decoded = BlsSecretKey::<S>::decode(&mut slice).unwrap();
    assert_eq!(decoded.to_bytes(), sk.to_bytes());
    assert!(slice.is_empty());
  }

  #[rstest]
  #[case::chia(assert_codec_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_codec_roundtrip::<BlsScIetf>)]
  fn codec_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  /// Summing scalars is scheme-independent, so one corpus serves both.
  fn assert_aggregate_vectors<S: BlsScheme>() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_aggregate");
    let vecs: Vec<AggSkVec> = corpus.vectors("aggregate_sk");

    for v in &vecs {
      let sks: Vec<BlsSecretKey<S>> = v
        .sks
        .iter()
        .map(|sk| BlsSecretKey::<S>::from_bytes(&arr_from_hex(sk)).unwrap())
        .collect();
      let refs: Vec<&BlsSecretKey<S>> = sks.iter().collect();
      let agg = BlsSecretKey::<S>::aggregate(&refs).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_sk);
    }
  }

  #[rstest]
  #[case::chia(assert_aggregate_vectors::<BlsScChia>)]
  #[case::ietf(assert_aggregate_vectors::<BlsScIetf>)]
  fn aggregate_matches_vectors(#[case] assertion: fn()) {
    assertion();
  }
}
