//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scheme-generic BLS signature.

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::BlsScheme;
use super::{BlsScIetf, BlsSigBytes, BlsSigId, BLS_SIG_LEN};

use dash_num::Hash256;
use dash_types::codec::TypeId;
use dash_types::{dlgt_codec, qtypestr, type_cvrt};
use hex_conservative::DisplayHex;

use core::fmt::{Debug, Formatter, Result as FmtResult};
use core::hash::{Hash, Hasher};

/// A BLS signature (96-byte compressed G2 point)
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "BlsSigBytes<S>", try_from = "BlsSigBytes<S>"))]
#[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
pub struct BlsSignature<S: BlsScheme>(pub(crate) S::InnerSig);

dlgt_codec!(for[S: BlsScheme] BlsSignature<S> => BlsSigBytes<S>, Hash256, BlsError, BLS_SIG_LEN);

impl<S: BlsScheme> BlsSignature<S> {
  /// Deserialize from 96 bytes.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSignature` when the bytes are not a valid point.
  pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, BlsError> {
    S::sig_from_bytes(bytes).map(Self)
  }

  /// Serialize to 96 bytes.
  pub fn to_bytes(&self) -> [u8; 96] {
    S::sig_to_bytes(&self.0)
  }

  /// Verify over a message of the scheme's message type.
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` when the pairing check does not hold.
  pub fn verify(&self, msg: &S::Msg, pk: &BlsPublicKey<S>) -> Result<(), BlsError> {
    S::verify(&self.0, msg, &pk.0)
  }

  pub(crate) fn from_inner(inner: S::InnerSig) -> Self {
    Self(inner)
  }
}

impl BlsSignature<BlsScIetf> {
  /// Verify under the domain separation tag selected by `scheme`.
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` when the pairing check does not hold.
  pub fn verify_with(&self, msg: &[u8], pk: &BlsPublicKey<BlsScIetf>, scheme: BlsSigId) -> Result<(), BlsError> {
    BlsScIetf::verify_with(&self.0, msg, &pk.0, scheme)
  }
}

impl<S: BlsScheme> Clone for BlsSignature<S> {
  fn clone(&self) -> Self {
    Self(self.0.clone())
  }
}

impl<S: BlsScheme> Debug for BlsSignature<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    qtypestr(f, core::any::type_name::<Self>())?;
    write!(f, "({})", self.to_bytes().as_hex())
  }
}

impl<S: BlsScheme> PartialEq for BlsSignature<S> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}

impl<S: BlsScheme> Eq for BlsSignature<S> {}

impl<S: BlsScheme> Hash for BlsSignature<S> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

impl<S: BlsScheme> TypeId for BlsSignature<S> {
  const TYPE_ID: u32 = S::SIG_TYPE_ID;
}

type_cvrt!(for[S: BlsScheme] From<BlsSignature<S>> for BlsSigBytes<S>, |sig| {
  Self::from_bytes(sig.to_bytes())
});

type_cvrt!(for[S: BlsScheme] TryFrom<BlsSigBytes<S>> for BlsSignature<S>, BlsError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

#[cfg(all(test, feature = "tests"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::secret_ops::BlsSecretKey;
  use crate::bls::tests::{MSG_DEADBEEF, SEED_0, SEED_1};
  use crate::bls::{BlsScChia, BlsScIetf};
  use crate::prelude::*;

  use cfg_if::cfg_if;
  use dash_dev::{arr_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct SigSerVec {
    sig_legacy: String,
    sig_ietf: String,
  }

  #[derive(Deserialize)]
  struct SignVec {
    sk: String,
    msg: String,
    sig: String,
  }

  fn assert_sign_verify<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let pk = sk.public_key();
    let sig = sk.sign(S::msg_ref(&MSG_DEADBEEF));

    assert!(sig.verify(S::msg_ref(&MSG_DEADBEEF), &pk).is_ok());
    assert!(sig.verify(S::msg_ref(&[0x42; 32]), &pk).is_err());

    let other_pk = BlsSecretKey::<S>::generate(&SEED_1).unwrap().public_key();
    assert!(sig.verify(S::msg_ref(&MSG_DEADBEEF), &other_pk).is_err());
  }

  #[rstest]
  #[case::chia(assert_sign_verify::<BlsScChia>)]
  #[case::ietf(assert_sign_verify::<BlsScIetf>)]
  fn signing_roundtrip_and_rejections(#[case] assertion: fn()) {
    assertion();
  }

  /// BLS signing draws no randomness, so the same key over the same message
  /// yields the same signature every time.
  fn assert_sign_is_deterministic<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let msg = S::msg_ref(&MSG_DEADBEEF);
    assert_eq!(sk.sign(msg), sk.sign(msg));
  }

  #[rstest]
  #[case::chia(assert_sign_is_deterministic::<BlsScChia>)]
  #[case::ietf(assert_sign_is_deterministic::<BlsScIetf>)]
  fn signing_is_deterministic(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_sig_roundtrip<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let bytes = sk.sign(S::msg_ref(&MSG_DEADBEEF)).to_bytes();
    assert_eq!(BlsSignature::<S>::from_bytes(&bytes).unwrap().to_bytes(), bytes);
  }

  #[rstest]
  #[case::chia(assert_sig_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_sig_roundtrip::<BlsScIetf>)]
  fn serialization_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  /// The legacy decoder rejects the all-zero encoding and the infinity marker
  /// rather than yielding an identity signature.
  #[rstest]
  fn chia_rejects_identity_signature() {
    assert!(BlsSignature::<BlsScChia>::from_bytes(&[0u8; 96]).is_err());

    let mut infinity = [0u8; 96];
    infinity[0] = 0xc0;
    assert!(BlsSignature::<BlsScChia>::from_bytes(&infinity).is_err());
  }

  /// Only bit 7 of byte 0 is the legacy sign flag, and unlike G1 the legacy
  /// G2 decoder rejects stray high bits rather than masking them, at the sign
  /// byte (index 0) and the swizzled `x.c1` byte (index 48) alike.
  ///
  /// Rejecting at the decoder is stricter than decoding the bits into an
  /// out-of-range point and failing later, but a point so decoded never
  /// verifies, so the two agree on every observable outcome.
  #[rstest]
  #[case::sign_byte(0, 0x20)]
  #[case::swizzled_byte(48, 0x40)]
  fn chia_rejects_stray_signature_bits(#[case] index: usize, #[case] mask: u8) {
    let clean = BlsSecretKey::<BlsScChia>::generate(&SEED_0)
      .unwrap()
      .sign(&MSG_DEADBEEF)
      .to_bytes();

    let mut mutated = clean;
    mutated[index] |= mask;
    assert!(BlsSignature::<BlsScChia>::from_bytes(&mutated).is_err());
  }

  /// The IETF decoder runs `validate`, which rejects the identity even though
  /// its encoding is canonical.
  #[rstest]
  fn ietf_rejects_identity_signature() {
    let mut infinity = [0u8; 96];
    infinity[0] = 0xc0;
    assert!(BlsSignature::<BlsScIetf>::from_bytes(&infinity).is_err());
    assert!(BlsSignature::<BlsScIetf>::from_bytes(&[0u8; 96]).is_err());
  }

  /// The same G2 point encodes differently under the two schemes, and each
  /// encoding must round-trip through the wrapper of its own scheme.
  #[rstest]
  fn serialization_formats_match_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_chia_ser_internals");
    let vecs: Vec<SigSerVec> = corpus.vectors("sig_serialization");

    for v in &vecs {
      let legacy = BlsSignature::<BlsScChia>::from_bytes(&arr_from_hex(&v.sig_legacy)).unwrap();
      assert_eq!(legacy.to_bytes().to_lower_hex_string(), v.sig_legacy);

      let ietf = BlsSignature::<BlsScIetf>::from_bytes(&arr_from_hex(&v.sig_ietf)).unwrap();
      assert_eq!(ietf.to_bytes().to_lower_hex_string(), v.sig_ietf);

      assert_ne!(v.sig_legacy, v.sig_ietf, "legacy and ietf should differ");
    }
  }

  /// The scheme-level KAT pins `BlsScheme::sign`; this pins that the wrapper's
  /// byte-oriented bridge is still wired to it, message length checks included.
  fn assert_signing_matches_vectors<S: BlsScheme>(corpus: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), corpus);
    let vecs: Vec<SignVec> = corpus.vectors("sign");

    for v in &vecs {
      let sk = BlsSecretKey::<S>::from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let sig = sk.sign(S::msg_ref(&arr_from_hex(&v.msg)));
      assert_eq!(sig.to_bytes().to_lower_hex_string(), v.sig);
    }
  }

  #[rstest]
  #[case::chia(assert_signing_matches_vectors::<BlsScChia>, "bls_chia_sign")]
  #[case::ietf(assert_signing_matches_vectors::<BlsScIetf>, "bls_ietf_sign")]
  fn signing_matches_vectors(#[case] assertion: fn(&str), #[case] corpus: &str) {
    assertion(corpus);
  }

  /// One secret scalar over one message yields two different signatures, so a
  /// scheme mix-up cannot go unnoticed.
  #[rstest]
  fn signatures_differ_across_schemes() {
    let chia = BlsSecretKey::<BlsScChia>::generate(&SEED_0).unwrap();
    let ietf = BlsSecretKey::<BlsScIetf>::from_bytes(&chia.to_bytes()).unwrap();
    assert_ne!(chia.sign(&MSG_DEADBEEF).to_bytes(), ietf.sign(&MSG_DEADBEEF).to_bytes());
  }

  cfg_if! {
    if #[cfg(feature = "serde")] {
      use dash_dev::assert_json_rt;

      /// The wrapper serializes through the byte bag, so the round-trip is
      /// pinned per scheme.
      #[rstest]
      fn serde_roundtrip() {
        let chia = BlsSecretKey::<BlsScChia>::generate(&SEED_0).unwrap();
        assert_json_rt(&chia.sign(&MSG_DEADBEEF));
        let ietf = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
        assert_json_rt(&ietf.sign(&MSG_DEADBEEF));
      }
    }
  }
}
