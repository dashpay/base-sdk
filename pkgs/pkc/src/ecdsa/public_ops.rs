//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 public key.

use super::error::EcdsaError;
use super::public_bytes::{EcdsaPkBytes, Sec1Byte, ECDSA_PK_LEN};
use super::sig_ops::EcdsaSignature;
use super::sig_rec_ops::EcdsaRecSignature;
use super::{Compression, EcdsaRecSigBytes, PubKeyHash};

use dash_types::{dlgt_codec, type_cvrt, TypeId, Unencodable};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};

use core::hash::{Hash, Hasher};

/// The SEC1 form a public key serializes back to.
///
/// Retained separately from the curve point because the point alone cannot
/// distinguish the uncompressed and hybrid encodings, and re-emitting one as
/// the other would change the key's wire image and therefore its hash.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub(super) enum PkForm {
  /// 33-byte `0x02`/`0x03` form.
  Compressed,
  /// 65-byte `0x04` form.
  Uncompressed,
  /// 65-byte `0x06`/`0x07` form carrying a redundant parity hint.
  Hybrid,
}

/// A secp256k1 public key.
#[derive(Clone, Debug, Eq, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "EcdsaPkBytes", try_from = "EcdsaPkBytes"))]
pub struct EcdsaPublicKey {
  inner: VerifyingKey,
  form: PkForm,
}

dlgt_codec!(EcdsaPublicKey => EcdsaPkBytes, PubKeyHash, EcdsaError, ECDSA_PK_LEN + 2);

impl EcdsaPublicKey {
  pub(super) fn from_inner(inner: VerifyingKey, compressed: Compression) -> Self {
    Self {
      inner,
      form: match compressed {
        Compression::Compressed => PkForm::Compressed,
        Compression::Uncompressed => PkForm::Uncompressed,
      },
    }
  }

  /// Borrow the inner verifying key.
  pub(super) fn as_inner(&self) -> &VerifyingKey {
    &self.inner
  }

  /// The SEC1 header byte this key serializes with.
  pub(super) fn sec1_prefix(&self) -> Sec1Byte {
    let odd = self.to_compressed()[0] == Sec1Byte::CompOdd.to_base();
    match (self.form, odd) {
      (PkForm::Compressed, false) => Sec1Byte::CompEven,
      (PkForm::Compressed, true) => Sec1Byte::CompOdd,
      (PkForm::Uncompressed, _) => Sec1Byte::Uncomp,
      (PkForm::Hybrid, false) => Sec1Byte::HybridEven,
      (PkForm::Hybrid, true) => Sec1Byte::HybridOdd,
    }
  }

  /// Switch the serialization form to uncompressed.
  ///
  /// A hybrid key also becomes plain uncompressed, dropping its parity hint.
  pub fn decompress(&mut self) {
    self.form = PkForm::Uncompressed;
  }

  /// Parse from SEC1 compressed, uncompressed, or hybrid bytes.
  ///
  /// The encoding form is retained so that re-serializing reproduces the input
  /// bytes exactly.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidPublicKey`] when the header byte is not a
  /// SEC1 prefix, the length disagrees with the prefix, a hybrid prefix
  /// contradicts the Y coordinate's parity, or the coordinates do not lie on
  /// the curve.
  pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdsaError> {
    let prefix = bytes.first().and_then(|&b| Sec1Byte::from_base(b));
    match prefix {
      Some(p @ (Sec1Byte::HybridEven | Sec1Byte::HybridOdd)) => {
        if bytes.len() != ECDSA_PK_LEN + 1 || (bytes[ECDSA_PK_LEN] & 1 != 0) != (p == Sec1Byte::HybridOdd) {
          return Err(EcdsaError::InvalidPublicKey);
        }
        let mut buf = [0u8; ECDSA_PK_LEN + 1];
        buf.copy_from_slice(bytes);
        buf[0] = Sec1Byte::Uncomp.to_base();
        VerifyingKey::from_sec1_bytes(&buf)
          .map(|key| Self {
            inner: key,
            form: PkForm::Hybrid,
          })
          .map_err(|_| EcdsaError::InvalidPublicKey)
      }
      _ => {
        let compressed = Compression::from(prefix.is_some_and(|s| s.is_compressed()));
        VerifyingKey::from_sec1_bytes(bytes)
          .map(|key| Self::from_inner(key, compressed))
          .map_err(|_| EcdsaError::InvalidPublicKey)
      }
    }
  }

  /// Whether this key serializes as compressed.
  pub fn is_compressed(&self) -> bool {
    self.form == PkForm::Compressed
  }

  /// Whether this key serializes in the legacy hybrid form.
  pub fn is_hybrid(&self) -> bool {
    self.form == PkForm::Hybrid
  }

  /// Serialize as 33-byte compressed SEC1.
  pub fn to_compressed(&self) -> [u8; 33] {
    let pt = self.inner.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(pt.as_bytes());
    out
  }

  /// Serialize as 65-byte hybrid SEC1, restating the Y parity in the header.
  pub fn to_hybrid(&self) -> [u8; 65] {
    let mut out = self.to_uncompressed();
    out[0] = Sec1Byte::HybridEven.to_base() | (out[ECDSA_PK_LEN] & 1);
    out
  }

  /// Serialize as 65-byte uncompressed SEC1.
  pub fn to_uncompressed(&self) -> [u8; 65] {
    let pt = self.inner.to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(pt.as_bytes());
    out
  }

  /// Recover a public key from a signature and its embedded recovery metadata.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::RecoveryFailed`] when no public key satisfies the
  /// signature and message. The embedded recovery id needs no check: it is in
  /// `0..=3` by construction.
  pub fn recover(msg_hash: &[u8; 32], sig: &EcdsaRecSignature) -> Result<Self, EcdsaError> {
    VerifyingKey::recover_from_prehash(msg_hash, sig.signature().as_inner(), sig.backend_recovery_id())
      .map(|key| Self::from_inner(key, Compression::from(sig.is_compressed())))
      .map_err(|_| EcdsaError::RecoveryFailed)
  }

  /// Recover a public key from a compact recoverable signature.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidSignature`] when the bag's scalars are not a
  /// well-formed signature, plus every error listed for
  /// [`recover`](Self::recover).
  pub fn recover_compact(msg_hash: &[u8; 32], sig: &EcdsaRecSigBytes) -> Result<Self, EcdsaError> {
    let parsed = EcdsaRecSignature::try_from(*sig)?;
    Self::recover(msg_hash, &parsed)
  }

  /// Verify a signature over a 32-byte prehashed message.
  ///
  /// Accepts anything that can view itself as a plain signature, so a
  /// recoverable signature verifies without an explicit downcast. High-S
  /// signatures are rejected, the underlying curve primitive checks `s`
  /// before the curve arithmetic runs.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::VerifyFailed`] when the signature does not verify
  /// against this key and message.
  pub fn verify(&self, msg_hash: &[u8; 32], sig: impl AsRef<EcdsaSignature>) -> Result<(), EcdsaError> {
    self
      .inner
      .verify_prehash(msg_hash, sig.as_ref().as_inner())
      .map_err(|_| EcdsaError::VerifyFailed)
  }
}

impl Hash for EcdsaPublicKey {
  fn hash<H: Hasher>(&self, state: &mut H) {
    EcdsaPkBytes::from(self).as_bytes().hash(state);
  }
}

type_cvrt!(From<EcdsaPublicKey> for EcdsaPkBytes, |pk| {
  let prefix = pk.sec1_prefix();
  match pk.form {
    PkForm::Compressed => Self::from_raw(prefix, &pk.to_compressed()),
    PkForm::Uncompressed => Self::from_raw(prefix, &pk.to_uncompressed()),
    PkForm::Hybrid => Self::from_raw(prefix, &pk.to_hybrid()),
  }
});

type_cvrt!(TryFrom<EcdsaPkBytes> for EcdsaPublicKey, EcdsaError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::ecdsa::tests::*;
  use crate::ecdsa::{
    Compression, EcdsaPkBytes, EcdsaPublicKey, EcdsaRecSigBytes, EcdsaRecSignature, EcdsaSecretKey, EcdsaSigBytes,
    EcdsaSignature,
  };
  use crate::prelude::*;

  #[cfg(feature = "serde")]
  use dash_dev::assert_json_rt;
  use dash_dev::{arr_from_hex, Corpus};
  use dash_types::codec::{BaseCodec, Hashable};
  use rstest::*;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct RecoverVector {
    msg: String,
    sig: String,
    recovery_id: u8,
    pk: String,
  }

  #[rstest]
  fn compressed_roundtrip(alice_pk: EcdsaPublicKey) {
    let bytes = alice_pk.to_compressed();
    assert_eq!(bytes.len(), 33);
    let restored = EcdsaPublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(restored, alice_pk);
  }

  #[rstest]
  fn corpus_recover_compact() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "ecdsa_sign");
    for v in corpus.vectors::<RecoverVector>("recover") {
      let sig = EcdsaSigBytes::from(arr_from_hex::<64>(&v.sig));
      let compact = EcdsaRecSigBytes::from_parts(sig, v.recovery_id, Compression::Compressed).unwrap();
      let pk = EcdsaPublicKey::recover_compact(&arr_from_hex::<32>(&v.msg), &compact).unwrap();
      assert_eq!(pk.to_compressed(), arr_from_hex::<33>(&v.pk));
    }
  }

  #[rstest]
  fn hybrid_bag_converts(alice_pk: EcdsaPublicKey) {
    let mut bytes = alice_pk.to_uncompressed();
    bytes[0] = 0x06 | (bytes[64] & 1);
    let bag = EcdsaPkBytes::from_bytes(&bytes).unwrap();
    let ops = EcdsaPublicKey::try_from(bag).unwrap();
    assert!(!ops.is_compressed());
    assert!(ops.is_hybrid());
  }

  #[rstest]
  #[case::compressed(0x02)]
  #[case::uncompressed(0x04)]
  #[case::hybrid(0x06)]
  fn bag_roundtrip_is_byte_stable(#[case] kind: u8, alice_pk: EcdsaPublicKey) {
    let bag_in = match kind {
      0x02 => EcdsaPkBytes::from_bytes(&alice_pk.to_compressed()),
      0x04 => EcdsaPkBytes::from_bytes(&alice_pk.to_uncompressed()),
      _ => EcdsaPkBytes::from_bytes(&alice_pk.to_hybrid()),
    }
    .unwrap();
    let ops = EcdsaPublicKey::try_from(bag_in).unwrap();
    let bag_out = EcdsaPkBytes::from(&ops);
    assert_eq!(bag_in, bag_out);
    assert_eq!(bag_in.hash(), bag_out.hash());
  }

  #[rstest]
  fn codec_roundtrip_preserves_hybrid(alice_pk: EcdsaPublicKey) {
    let bag = EcdsaPkBytes::from_bytes(&alice_pk.to_hybrid()).unwrap();
    let mut wire = Vec::new();
    bag.encode(&mut wire);
    let decoded = EcdsaPublicKey::decode(&mut wire.as_slice()).unwrap();
    let mut rewire = Vec::new();
    decoded.encode(&mut rewire);
    assert_eq!(wire, rewire);
  }

  #[rstest]
  fn hybrid_rejects_parity_mismatch(alice_pk: EcdsaPublicKey) {
    let mut bytes = alice_pk.to_uncompressed();
    bytes[0] = 0x06 | ((bytes[64] & 1) ^ 1);
    assert!(EcdsaPublicKey::from_bytes(&bytes).is_err());
  }

  #[rstest]
  fn hybrid_roundtrip(alice_pk: EcdsaPublicKey) {
    let bytes = alice_pk.to_hybrid();
    let parsed = EcdsaPublicKey::from_bytes(&bytes).unwrap();
    assert!(!parsed.is_compressed());
    assert_eq!(parsed.to_hybrid(), bytes);
    // Hybrid and plain uncompressed are the same point but distinct wire forms,
    // so they must be unequal.
    let mut plain = alice_pk;
    plain.decompress();
    assert_ne!(parsed, plain);
    assert_eq!(parsed.to_uncompressed(), plain.to_uncompressed());
  }

  #[rstest]
  fn decompress_drops_hybrid_hint(alice_pk: EcdsaPublicKey) {
    let mut parsed = EcdsaPublicKey::from_bytes(&alice_pk.to_hybrid()).unwrap();
    assert!(parsed.is_hybrid());
    parsed.decompress();
    assert!(!parsed.is_hybrid());
    assert_eq!(EcdsaPkBytes::from(&parsed).as_bytes()[0], 0x04);
  }

  #[rstest]
  fn rejects_garbage() {
    assert!(EcdsaPublicKey::from_bytes(&[0xff; 33]).is_err());
  }

  #[rstest]
  fn recover_roundtrip(alice_pk: EcdsaPublicKey, alice_sk: EcdsaSecretKey, alice_rec_sig: EcdsaRecSignature) {
    let compact_sig = alice_sk.sign_compact(&MSG).unwrap();
    assert_eq!(EcdsaPublicKey::recover_compact(&MSG, &compact_sig).unwrap(), alice_pk);
    assert_eq!(EcdsaPublicKey::recover(&MSG, &alice_rec_sig).unwrap(), alice_pk);
  }

  #[cfg(feature = "serde")]
  #[rstest]
  fn serde_roundtrip(alice_pk: EcdsaPublicKey) {
    assert_json_rt(&alice_pk);
  }

  #[rstest]
  fn uncompressed_roundtrip(alice_pk: EcdsaPublicKey) {
    let mut pk = alice_pk;
    pk.decompress();
    let bytes = pk.to_uncompressed();
    assert_eq!(bytes.len(), 65);
    let restored = EcdsaPublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(restored, pk);
  }

  #[rstest]
  fn verify_rejects_wrong_message(alice_pk: EcdsaPublicKey, alice_sig: EcdsaSignature) {
    let mut bad = MSG;
    bad[0] ^= 0xff;
    assert!(alice_pk.verify(&bad, &alice_sig).is_err());
  }
}
