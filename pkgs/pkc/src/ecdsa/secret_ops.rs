//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 secret key.

use super::error::EcdsaError;
use super::public_ops::EcdsaPublicKey;
use super::secret_bytes::{EcdsaSkBytes, ECDSA_SK_LEN};
use super::sig_ops::EcdsaSignature;
use super::sig_rec_ops::EcdsaRecSignature;
use super::{Compression, EcdsaRecSigBytes};

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_types::codec::{ensure, BaseCodec, DecodeError, EncodeBuf, Hashable};
use dash_types::{impl_stype, type_cvrt, ArrayBuf, TypeId};
use hex_conservative::hex;
use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
use k256::elliptic_curve::ops::Neg;
use k256::{elliptic_curve::sec1::ToEncodedPoint, AffinePoint};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, Zeroizing};

use core::fmt;

/// DER lengths of a private key with a compressed and an uncompressed public
/// key respectively.
const DER_SIZES: &[usize] = &[214, 279];
/// ASN.1 object identifier for a prime-field curve.
const OID_PRIME_FIELD: &[u8] = &hex!("2a8648ce3d0101");
/// secp256k1 field prime.
const PRIME: &[u8; ECDSA_SK_LEN] = &hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
/// secp256k1 group order.
pub(super) const ORDER: &[u8; ECDSA_SK_LEN] = &hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

/// Emit a DER header followed by `bytes`.
fn der_bytes(buf: &mut impl EncodeBuf, tag: u8, bytes: &[u8]) {
  der_header(buf, tag, bytes.len());
  buf.extend_from_slice(bytes); // nosemgrep: codec-no-raw-extend
}

/// Emit a DER tag and its short, one-byte, or two-byte length.
fn der_header(buf: &mut impl EncodeBuf, tag: u8, len: usize) {
  debug_assert!(len <= u16::MAX as usize, "der_header: length exceeds u16");
  let [hi, lo] = (len as u16).to_be_bytes();
  match len {
    0..=0x7f => buf.extend_from_slice(&[tag, lo]), // nosemgrep: codec-no-raw-extend
    0x80..=0xff => buf.extend_from_slice(&[tag, 0x81, lo]), // nosemgrep: codec-no-raw-extend
    _ => buf.extend_from_slice(&[tag, 0x82, hi, lo]), // nosemgrep: codec-no-raw-extend
  }
}

/// Emit a DER INTEGER, prefixing a zero byte when the high bit is set.
fn der_uint(buf: &mut impl EncodeBuf, bytes: &[u8]) {
  debug_assert!(!bytes.is_empty(), "der_uint: empty input");
  der_header(buf, 2, bytes.len() + usize::from(bytes[0] >= 0x80));
  if bytes[0] >= 0x80 {
    buf.push(0);
  }
  buf.extend_from_slice(bytes); // nosemgrep: codec-no-raw-extend
}

/// A secp256k1 secret key.
#[derive(Clone, TypeId)]
pub struct EcdsaSecretKey {
  inner: SigningKey,
  compressed: bool,
}

impl BaseCodec<EcdsaError> for EcdsaSecretKey {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError<EcdsaError>> {
    ensure(data, 4).map_err(|e| e.lift())?;
    if data[0] != 0x30 {
      return Err(DecodeError::DecError(EcdsaError::MalformedDer));
    }
    let (len, off) = match data[1] {
      0x81 => (usize::from(data[2]) + 3, 3),
      0x82 => ((usize::from(data[2]) << 8 | usize::from(data[3])) + 4, 4),
      _ => return Err(DecodeError::DecError(EcdsaError::MalformedDer)),
    };
    let compressed = len == DER_SIZES[0];
    if !DER_SIZES.contains(&len) {
      return Err(DecodeError::BadLen {
        expected: DER_SIZES.to_vec(),
        actual: len,
      });
    }
    if data.len() < len {
      return Err(DecodeError::Eof {
        needed: len,
        remaining: data.len(),
      });
    }
    if data[off..off + 5] != [2, 1, 1, 4, 32] {
      return Err(DecodeError::DecError(EcdsaError::MalformedDer));
    }
    let mut key = Zeroizing::new([0; ECDSA_SK_LEN]);
    key.copy_from_slice(&data[off + 5..off + 5 + ECDSA_SK_LEN]);
    let candidate = Self::from_bytes(&key, Compression::from(compressed)).map_err(DecodeError::DecError)?;

    // The curve OID, field prime, generator, order, and embedded public key are
    // never read back individually; instead the scalar is re-encoded and
    // compared byte-for-byte, so any tampering anywhere in the structure,
    // including a public key that does not match the scalar, gets rejected.
    let mut expected = Zeroizing::new(ArrayBuf::<{ DER_SIZES[1] }>::new());
    candidate.encode(&mut *expected);
    if expected.as_bytes() != &data[..len] {
      return Err(DecodeError::DecError(EcdsaError::MalformedDer));
    }

    *data = &data[len..];
    Ok(candidate)
  }

  /// Encodes this key's raw scalar into `buf` as DER.
  ///
  /// `buf` receives the secret scalar in plain bytes and is not zeroized by
  /// this function; callers who need the encoded form not to outlive its use
  /// must supply a zeroizing buffer (e.g. [`ArrayBuf`](dash_types::ArrayBuf))
  /// and zeroize or drop it themselves once done.
  fn encode(&self, buf: &mut impl EncodeBuf) {
    let scalar = self.to_bytes();
    let public = self.inner.verifying_key().to_encoded_point(self.compressed);
    let public = public.as_bytes();
    let generator = AffinePoint::GENERATOR.to_encoded_point(self.compressed);
    let generator = generator.as_bytes();
    let point_len = public.len();
    let params_len = point_len + 97;

    der_header(buf, 0x30, 2 * point_len + 145);
    der_uint(buf, &[1]);
    der_bytes(buf, 4, &*scalar);
    der_header(buf, 0xa0, params_len + 3);
    der_header(buf, 0x30, params_len);
    der_uint(buf, &[1]);
    der_header(buf, 0x30, 44);
    der_bytes(buf, 6, OID_PRIME_FIELD);
    der_uint(buf, PRIME);
    der_header(buf, 0x30, 6);
    der_bytes(buf, 4, &[0]);
    der_bytes(buf, 4, &[7]);
    der_bytes(buf, 4, generator);
    der_uint(buf, ORDER);
    der_uint(buf, &[1]);
    der_header(buf, 0xa1, point_len + 3);
    der_header(buf, 3, point_len + 1);
    buf.push(0);
    buf.extend_from_slice(public); // nosemgrep: codec-no-raw-extend
  }
}

impl_stype!(EcdsaSecretKey, DER_SIZES[1], EcdsaError);

impl Hashable for EcdsaSecretKey {
  type Hash = Hash256;

  fn hash(&self) -> Hash256 {
    let mut buf = Zeroizing::new(ArrayBuf::<{ DER_SIZES[1] }>::new());
    self.encode(&mut *buf);
    Hash256::from_bytes(sha256d::Hash::hash(buf.as_bytes()).to_byte_array())
  }
}

impl EcdsaSecretKey {
  /// Parse a secret key from a 32-byte big-endian scalar.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidSecretKey`] when the scalar is zero or not
  /// below the curve order.
  pub fn from_bytes(bytes: &[u8; 32], compressed: Compression) -> Result<Self, EcdsaError> {
    SigningKey::from_bytes(bytes.into())
      .map(|key| Self {
        inner: key,
        compressed: compressed.is_compressed(),
      })
      .map_err(|_| EcdsaError::InvalidSecretKey)
  }

  /// Generate a new random secret key.
  pub fn generate(rng: &mut impl CryptoRngCore, compressed: Compression) -> Self {
    Self {
      inner: SigningKey::random(rng),
      compressed: compressed.is_compressed(),
    }
  }

  /// Whether the corresponding public key should be compressed.
  pub fn is_compressed(&self) -> bool {
    self.compressed
  }

  /// Negate the secret scalar in place.
  pub fn negate(&mut self) {
    let neg = self.inner.as_nonzero_scalar().neg();
    self.inner = SigningKey::from(neg);
  }

  /// Derive the corresponding public key.
  pub fn public_key(&self) -> EcdsaPublicKey {
    EcdsaPublicKey::from_inner(*self.inner.verifying_key(), Compression::from(self.compressed))
  }

  /// Serialize to a 32-byte big-endian scalar.
  pub fn to_bytes(&self) -> Zeroizing<[u8; ECDSA_SK_LEN]> {
    let mut fb = self.inner.to_bytes();
    let out = Zeroizing::new(fb.into());
    <[u8]>::zeroize(fb.as_mut());
    out
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
      .inner
      .sign_prehash(msg_hash)
      .map(EcdsaSignature::from_inner)
      .map_err(|_| EcdsaError::SigningFailed)
  }

  /// Sign and return the compact recoverable signature bytes.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::SigningFailed`] if the underlying library rejects
  /// the prehash.
  pub fn sign_compact(&self, msg_hash: &[u8; 32]) -> Result<EcdsaRecSigBytes, EcdsaError> {
    Ok(self.sign_recoverable(msg_hash)?.into())
  }

  /// Sign and return a recoverable signature (RFC 6979, low-S normalised).
  /// Recovery embeds the key's compression flag in the signature.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::SigningFailed`] if the underlying library rejects
  /// the prehash.
  pub fn sign_recoverable(&self, msg_hash: &[u8; 32]) -> Result<EcdsaRecSignature, EcdsaError> {
    self
      .inner
      .sign_prehash(msg_hash)
      .map(|(sig, rid)| EcdsaRecSignature::from_inner(sig, rid, Compression::from(self.compressed)))
      .map_err(|_| EcdsaError::SigningFailed)
  }

  /// Verify that a public key matches this secret key.
  ///
  /// Compares only the curve point: a caller-supplied key that serializes in a
  /// different SEC1 form than this secret key's own preference still matches if
  /// it is the same point.
  pub fn verify_pubkey(&self, pubkey: &EcdsaPublicKey) -> bool {
    self.inner.verifying_key() == pubkey.as_inner()
  }
}

impl fmt::Debug for EcdsaSecretKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "EcdsaSecretKey(..)")
  }
}

impl Eq for EcdsaSecretKey {}

impl PartialEq for EcdsaSecretKey {
  fn eq(&self, other: &Self) -> bool {
    use subtle::ConstantTimeEq;
    (*self.to_bytes()).ct_eq(&*other.to_bytes()).into() && self.compressed == other.compressed
  }
}

type_cvrt!(From<EcdsaSecretKey> for EcdsaSkBytes, |sk| {
  Self::from_bytes(*sk.to_bytes(), Compression::from(sk.is_compressed()))
});

type_cvrt!(TryFrom<EcdsaSkBytes> for EcdsaSecretKey, EcdsaError, |bytes| {
  Self::from_bytes(bytes.as_bytes(), Compression::from(bytes.is_compressed()))
});

#[cfg(test)]
#[expect(clippy::ptr_arg, clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::ecdsa::tests::*;
  use crate::ecdsa::{Compression, EcdsaPublicKey, EcdsaSecretKey};
  use crate::prelude::*;

  use dash_dev::{arr_from_hex, Corpus};
  use dash_types::codec::BaseCodec;
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
  #[case::compressed(Compression::Compressed)]
  #[case::uncompressed(Compression::Uncompressed)]
  fn codec_roundtrip_preserves_compression(#[case] compressed: Compression) {
    let sk = EcdsaSecretKey::from_bytes(&ALICE_SK, compressed).unwrap();
    let mut buf = Vec::new();
    sk.encode(&mut buf);
    let decoded = EcdsaSecretKey::decode(&mut buf.as_slice()).unwrap();
    assert_eq!(*decoded.to_bytes(), *sk.to_bytes());
    assert_eq!(decoded.is_compressed(), compressed.is_compressed());
  }

  #[rstest]
  #[case::compressed(Compression::Compressed)]
  #[case::uncompressed(Compression::Uncompressed)]
  fn consensus_bridge_roundtrip(#[case] compressed: Compression) {
    use bitcoin_consensus_encoding::{encode_to_vec, Decode, Decoder};

    let sk = EcdsaSecretKey::from_bytes(&ALICE_SK, compressed).unwrap();
    let wire = encode_to_vec(&sk);

    let mut direct = Vec::new();
    sk.encode(&mut direct);
    assert_eq!(wire, direct, "bridge must match the BaseCodec image");
    assert_eq!(wire.len(), if compressed.is_compressed() { 214 } else { 279 });

    let mut dec = <EcdsaSecretKey as Decode>::decoder();
    let mut cursor = wire.as_slice();
    while dec.push_bytes(&mut cursor).unwrap() && !cursor.is_empty() {}
    let back = dec.end().unwrap();
    assert_eq!(*back.to_bytes(), *sk.to_bytes());
    assert_eq!(back.is_compressed(), compressed.is_compressed());
  }

  fn corrupt_mismatched_embedded_pubkey(buf: &mut Vec<u8>, alice: &EcdsaSecretKey, bob: &EcdsaSecretKey) {
    let point_len = alice.public_key().to_compressed().len();
    let start = buf.len() - point_len;
    buf[start..].copy_from_slice(&bob.public_key().to_compressed());
  }

  fn corrupt_tampered_curve_oid(buf: &mut Vec<u8>, _alice: &EcdsaSecretKey, _bob: &EcdsaSecretKey) {
    let pos = buf
      .windows(super::OID_PRIME_FIELD.len())
      .position(|w| w == super::OID_PRIME_FIELD)
      .unwrap();
    buf[pos] ^= 0xff;
  }

  fn corrupt_length_form_mismatch(buf: &mut Vec<u8>, _alice: &EcdsaSecretKey, _bob: &EcdsaSecretKey) {
    // Overwrite the compressed point's SEC1 prefix byte with the uncompressed
    // tag, keeping the (compressed) total length unchanged: the embedded
    // point no longer matches a re-encoding of the scalar.
    let point_start = buf.len() - 33;
    buf[point_start] = 0x04;
  }

  fn corrupt_truncated_body(buf: &mut Vec<u8>, _alice: &EcdsaSecretKey, _bob: &EcdsaSecretKey) {
    buf.truncate(buf.len() - 1);
  }

  #[rstest]
  #[case::mismatched_embedded_pubkey(corrupt_mismatched_embedded_pubkey)]
  #[case::tampered_curve_oid(corrupt_tampered_curve_oid)]
  #[case::length_form_mismatch(corrupt_length_form_mismatch)]
  #[case::truncated_body(corrupt_truncated_body)]
  fn decode_rejects_malformed_der(
    alice_sk: EcdsaSecretKey,
    bob_sk: EcdsaSecretKey,
    #[case] corrupt: fn(&mut Vec<u8>, &EcdsaSecretKey, &EcdsaSecretKey),
  ) {
    let mut buf = Vec::new();
    alice_sk.encode(&mut buf);
    corrupt(&mut buf, &alice_sk, &bob_sk);
    assert!(EcdsaSecretKey::decode(&mut buf.as_slice()).is_err());
  }

  #[rstest]
  fn corpus_derive_pk() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "ecdsa_keygen");
    for v in corpus.vectors::<KeygenVector>("derive_pk") {
      let sk = EcdsaSecretKey::from_bytes(&arr_from_hex(&v.sk), Compression::Compressed).unwrap();
      assert_eq!(sk.public_key().to_compressed(), arr_from_hex::<33>(&v.pk_compressed));
    }
  }

  #[rstest]
  fn corpus_sign_recoverable() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "ecdsa_sign");
    for v in corpus.vectors::<SignVector>("sign_recoverable") {
      let sk = EcdsaSecretKey::from_bytes(&arr_from_hex(&v.sk), Compression::Compressed).unwrap();
      let sig = sk.sign_recoverable(&arr_from_hex::<32>(&v.msg)).unwrap();
      assert_eq!(sig.to_compact(), arr_from_hex::<64>(&v.sig));
      assert_eq!(sig.recovery_id(), v.recovery_id);
    }
  }

  #[rstest]
  fn from_bytes_roundtrip(alice_sk: EcdsaSecretKey) {
    let bytes = alice_sk.to_bytes();
    let restored = EcdsaSecretKey::from_bytes(&bytes, Compression::Compressed).unwrap();
    assert_eq!(
      restored.public_key().to_compressed(),
      alice_sk.public_key().to_compressed()
    );
  }

  #[rstest]
  fn negate_changes_key(alice_sk: EcdsaSecretKey) {
    let original_bytes = alice_sk.to_bytes();
    let mut negated = alice_sk.clone();
    negated.negate();
    assert_ne!(*negated.to_bytes(), *original_bytes);
    negated.negate();
    assert_eq!(*negated.to_bytes(), *original_bytes);
  }

  #[rstest]
  fn rejects_zero() {
    assert!(EcdsaSecretKey::from_bytes(&[0u8; 32], Compression::Compressed).is_err());
  }

  #[rstest]
  fn sign_is_deterministic(alice_sk: EcdsaSecretKey) {
    let sig1 = alice_sk.sign(&MSG).unwrap();
    let sig2 = alice_sk.sign(&MSG).unwrap();
    assert_eq!(sig1, sig2);
  }

  #[rstest]
  fn sign_recoverable_roundtrip(alice_sk: EcdsaSecretKey) {
    let sig = alice_sk.sign_recoverable(&MSG).unwrap();
    let recovered = EcdsaPublicKey::recover(&MSG, &sig).unwrap();
    assert_eq!(recovered, alice_sk.public_key());
  }

  #[rstest]
  fn sign_verify_roundtrip(alice_sk: EcdsaSecretKey) {
    let sig = alice_sk.sign(&MSG).unwrap();
    assert!(alice_sk.public_key().verify(&MSG, &sig).is_ok());
  }

  #[rstest]
  fn verify_pubkey_matches(alice_sk: EcdsaSecretKey) {
    assert!(alice_sk.verify_pubkey(&alice_sk.public_key()));
  }

  #[rstest]
  fn verify_pubkey_matches_regardless_of_form(alice_sk: EcdsaSecretKey) {
    let mut uncompressed = alice_sk.public_key();
    uncompressed.decompress();
    assert!(alice_sk.verify_pubkey(&uncompressed));
  }

  #[rstest]
  fn verify_rejects_wrong_key(alice_sk: EcdsaSecretKey, bob_sk: EcdsaSecretKey) {
    assert!(!alice_sk.verify_pubkey(&bob_sk.public_key()));
    let sig = alice_sk.sign(&MSG).unwrap();
    assert!(bob_sk.public_key().verify(&MSG, &sig).is_err());
  }
}
