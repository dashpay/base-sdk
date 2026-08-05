//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 secret key.

use super::error::EcdsaError;
use super::public_ops::EcdsaPublicKey;
use super::secret_bytes::EcdsaSkBytes;
use super::sig_ops::EcdsaSignature;
use super::sig_rec_ops::EcdsaRecSignature;

use dash_types::type_cvrt;
use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

use core::fmt;

/// A secp256k1 secret key.
#[derive(Clone)]
pub struct EcdsaSecretKey(SigningKey);

impl EcdsaSecretKey {
  /// Parse a secret key from a 32-byte big-endian scalar.
  pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, EcdsaError> {
    SigningKey::from_bytes(bytes.into())
      .map(Self)
      .map_err(|_| EcdsaError::InvalidSecretKey)
  }

  /// Serialize to a 32-byte big-endian scalar.
  pub fn to_bytes(&self) -> [u8; 32] {
    self.0.to_bytes().into()
  }

  /// Derive the corresponding public key.
  pub fn public_key(&self) -> EcdsaPublicKey {
    EcdsaPublicKey::from_inner(*self.0.verifying_key())
  }

  /// Produce an ECDSA signature over a 32-byte prehashed message (RFC 6979,
  /// low-S normalised).
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::SigningFailed`] if the underlying library rejects
  /// the prehash.
  pub fn sign(&self, msg_hash: &[u8; 32]) -> Result<EcdsaSignature, EcdsaError> {
    self
      .0
      .sign_prehash(msg_hash)
      .map(EcdsaSignature::from_inner)
      .map_err(|_| EcdsaError::SigningFailed)
  }

  /// Sign and return a recoverable signature (RFC 6979, low-S
  /// normalised). The signer states whether the verifying key
  /// serializes compressed, which recovery embeds in the signature.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::SigningFailed`] if the underlying library
  /// rejects the prehash.
  pub fn sign_recoverable(&self, msg_hash: &[u8; 32], compressed: bool) -> Result<EcdsaRecSignature, EcdsaError> {
    self
      .0
      .sign_prehash(msg_hash)
      .map(|(sig, rid)| EcdsaRecSignature::from_inner(sig, rid, compressed.into()))
      .map_err(|_| EcdsaError::SigningFailed)
  }
}

impl fmt::Debug for EcdsaSecretKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "EcdsaSecretKey(..)")
  }
}

type_cvrt!(From<EcdsaSecretKey> for EcdsaSkBytes, |sk| {
  Self::from(sk.to_bytes())
});

type_cvrt!(TryFrom<EcdsaSkBytes> for EcdsaSecretKey, EcdsaError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::ecdsa::tests::*;
  use crate::ecdsa::{EcdsaPublicKey, EcdsaSecretKey};
  use crate::prelude::*;

  use dash_dev::{arr_from_hex, Corpus};
  use rstest::*;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct KeygenVector {
    sk: String,
    pk_compressed: String,
  }

  #[derive(Deserialize)]
  struct SignVector {
    sk: String,
    msg: String,
    sig: String,
    recovery_id: u8,
  }

  #[rstest]
  fn corpus_derive_pk() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "ecdsa_keygen");
    for v in corpus.vectors::<KeygenVector>("derive_pk") {
      let sk = EcdsaSecretKey::from_bytes(&arr_from_hex(&v.sk)).unwrap();
      assert_eq!(sk.public_key().to_bytes(), arr_from_hex::<33>(&v.pk_compressed));
    }
  }

  #[rstest]
  fn corpus_sign_recoverable() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "ecdsa_sign");
    for v in corpus.vectors::<SignVector>("sign_recoverable") {
      let sk = EcdsaSecretKey::from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let sig = sk.sign_recoverable(&arr_from_hex::<32>(&v.msg), true).unwrap();
      assert_eq!(sig.to_compact(), arr_from_hex::<64>(&v.sig));
      assert_eq!(sig.recovery_id(), v.recovery_id);
    }
  }

  #[rstest]
  fn from_bytes_roundtrip(alice_sk: EcdsaSecretKey) {
    let bytes = alice_sk.to_bytes();
    let restored = EcdsaSecretKey::from_bytes(&bytes).unwrap();
    assert_eq!(restored.public_key().to_bytes(), alice_sk.public_key().to_bytes());
  }

  #[rstest]
  fn rejects_zero() {
    assert!(EcdsaSecretKey::from_bytes(&[0u8; 32]).is_err());
  }

  #[rstest]
  fn sign_is_deterministic(alice_sk: EcdsaSecretKey) {
    let sig1 = alice_sk.sign(&MSG).unwrap();
    let sig2 = alice_sk.sign(&MSG).unwrap();
    assert_eq!(sig1, sig2);
  }

  #[rstest]
  fn sign_recoverable_roundtrip(alice_sk: EcdsaSecretKey) {
    let sig = alice_sk.sign_recoverable(&MSG, true).unwrap();
    let recovered = EcdsaPublicKey::recover(&MSG, &sig).unwrap();
    assert_eq!(recovered, alice_sk.public_key());
  }

  #[rstest]
  fn sign_verify_roundtrip(alice_sk: EcdsaSecretKey) {
    let sig = alice_sk.sign(&MSG).unwrap();
    assert!(alice_sk.public_key().verify(&MSG, &sig).is_ok());
  }

  #[rstest]
  fn verify_rejects_wrong_key(alice_sk: EcdsaSecretKey, bob_sk: EcdsaSecretKey) {
    let sig = alice_sk.sign(&MSG).unwrap();
    assert!(bob_sk.public_key().verify(&MSG, &sig).is_err());
  }
}
