//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 secret key byte bag.

use super::Compression;
use crate::prelude::*;

use base58ck::{decode_check, encode_check};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use core::fmt;

/// Raw secp256k1 secret key length.
pub const ECDSA_SK_LEN: usize = 32;

/// Raw ECDSA secret key bytes.
///
/// Carries a compression flag that decides how the derived public key
/// serializes. The bytes are unvalidated: DER needs an in-range scalar, so the
/// wire codec lives in [`EcdsaSecretKey`](crate::ecdsa::EcdsaSecretKey).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaSkBytes {
  inner: [u8; ECDSA_SK_LEN],
  #[zeroize(skip)]
  compressed: bool,
}

impl EcdsaSkBytes {
  /// Borrow the raw inner bytes.
  pub const fn as_bytes(&self) -> &[u8; ECDSA_SK_LEN] {
    &self.inner
  }

  /// Wrap raw bytes with a compression flag.
  pub const fn from_bytes(bytes: [u8; ECDSA_SK_LEN], compressed: Compression) -> Self {
    Self {
      inner: bytes,
      compressed: compressed.is_compressed(),
    }
  }

  /// Whether the corresponding public key should be compressed.
  pub const fn is_compressed(&self) -> bool {
    self.compressed
  }

  /// Decode a wallet import format-encoded private key.
  ///
  /// Returns `None` on a bad checksum, an unexpected version prefix, a length
  /// outside 33 or 34 bytes, a malformed compression flag, or an all-zero
  /// scalar. Scalars at or above the curve order still pass: range checking
  /// belongs to [`EcdsaSecretKey`](crate::ecdsa::EcdsaSecretKey).
  pub fn from_wif(s: &str, prefix: u8) -> Option<Self> {
    let data = Zeroizing::new(decode_check(s).ok()?);
    let result = match data.len() {
      33 if data[0] == prefix => {
        let key: [u8; ECDSA_SK_LEN] = data[1..33].try_into().ok()?;
        Some(Self::from_bytes(key, Compression::Uncompressed))
      }
      34 if data[0] == prefix && data[33] == 0x01 => {
        let key: [u8; ECDSA_SK_LEN] = data[1..33].try_into().ok()?;
        Some(Self::from_bytes(key, Compression::Compressed))
      }
      _ => None,
    };
    result.filter(|sk| !sk.is_null())
  }

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.inner.ct_eq(&[0u8; ECDSA_SK_LEN]).into()
  }

  /// Copy out the raw inner bytes.
  pub fn to_bytes(&self) -> Zeroizing<[u8; ECDSA_SK_LEN]> {
    Zeroizing::new(self.inner)
  }

  /// Encode as a wallet import format string.
  ///
  /// Returns `None` for the all-zero scalar, which [`from_wif`](Self::from_wif)
  /// rejects. Scalars at or above the curve order still encode, as `from_wif`
  /// defers that range check too.
  pub fn to_wif(&self, prefix: u8) -> Option<Zeroizing<String>> {
    if self.is_null() {
      return None;
    }
    let mut buf = Zeroizing::new([0u8; 34]);
    buf[0] = prefix;
    buf[1..33].copy_from_slice(&self.inner);
    if self.compressed {
      buf[33] = 0x01;
      Some(Zeroizing::new(encode_check(&buf[..34])))
    } else {
      Some(Zeroizing::new(encode_check(&buf[..33])))
    }
  }
}

impl AsRef<[u8]> for EcdsaSkBytes {
  fn as_ref(&self) -> &[u8] {
    &self.inner
  }
}

impl AsRef<[u8; ECDSA_SK_LEN]> for EcdsaSkBytes {
  fn as_ref(&self) -> &[u8; ECDSA_SK_LEN] {
    &self.inner
  }
}

impl fmt::Debug for EcdsaSkBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "EcdsaSkBytes(..)")
  }
}

impl fmt::Display for EcdsaSkBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt::Debug::fmt(self, f)
  }
}

impl Eq for EcdsaSkBytes {}

impl PartialEq for EcdsaSkBytes {
  fn eq(&self, other: &Self) -> bool {
    self.inner.ct_eq(&other.inner).into() && self.compressed == other.compressed
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{Compression, EcdsaSkBytes, ECDSA_SK_LEN};
  use crate::prelude::*;

  use rstest::*;

  #[rstest]
  fn debug_redacts_inner() {
    let sk = EcdsaSkBytes::from_bytes([0xffu8; ECDSA_SK_LEN], Compression::Compressed);
    let dbg = format!("{sk:?}");
    assert_eq!(dbg, "EcdsaSkBytes(..)");
    assert!(!dbg.contains("ff"));
  }

  #[rstest]
  fn equality() {
    let a = EcdsaSkBytes::from_bytes([1u8; ECDSA_SK_LEN], Compression::Compressed);
    let b = EcdsaSkBytes::from_bytes([1u8; ECDSA_SK_LEN], Compression::Compressed);
    let c = EcdsaSkBytes::from_bytes([2u8; ECDSA_SK_LEN], Compression::Compressed);
    let d = EcdsaSkBytes::from_bytes([1u8; ECDSA_SK_LEN], Compression::Uncompressed);
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d, "same scalar but different compression");
  }

  #[rstest]
  #[case::compressed(0x42, Compression::Compressed)]
  #[case::uncompressed(0x01, Compression::Uncompressed)]
  fn roundtrip(#[case] fill: u8, #[case] compressed: Compression) {
    let bytes = [fill; ECDSA_SK_LEN];
    let sk = EcdsaSkBytes::from_bytes(bytes, compressed);
    assert_eq!(*sk.to_bytes(), bytes);
    assert_eq!(sk.as_bytes(), &bytes);
    assert_eq!(sk.is_compressed(), compressed.is_compressed());
  }

  #[rstest]
  #[case::compressed(Compression::Compressed)]
  #[case::uncompressed(Compression::Uncompressed)]
  fn wif_roundtrip(#[case] compressed: Compression) {
    let sk = EcdsaSkBytes::from_bytes([0x11u8; ECDSA_SK_LEN], compressed);
    let wif = sk.to_wif(0x80).unwrap();
    let restored = EcdsaSkBytes::from_wif(&wif, 0x80).unwrap();
    assert_eq!(restored, sk);
  }

  /// The encoder must not emit a string the decoder refuses to read back.
  #[rstest]
  #[case::compressed(Compression::Compressed)]
  #[case::uncompressed(Compression::Uncompressed)]
  fn to_wif_refuses_zero_scalar(#[case] compressed: Compression) {
    let zero = EcdsaSkBytes::from_bytes([0u8; ECDSA_SK_LEN], compressed);
    assert!(zero.to_wif(0x80).is_none());
  }

  /// A well-formed WIF carrying the zero scalar, assembled by hand because
  /// `to_wif` refuses to emit one; `from_wif` must still reject it.
  fn wif_zero_key() -> String {
    let mut payload = [0u8; 34];
    payload[0] = 0x80;
    payload[33] = 0x01;
    base58ck::encode_check(&payload)
  }

  fn wif_bad_checksum() -> String {
    let sk = EcdsaSkBytes::from_bytes([0x22u8; ECDSA_SK_LEN], Compression::Compressed);
    let mut raw = base58ck::decode(&sk.to_wif(0x80).unwrap()).unwrap();
    *raw.last_mut().unwrap() ^= 0xff;
    base58ck::encode(&raw)
  }

  fn wif_wrong_prefix() -> String {
    let sk = EcdsaSkBytes::from_bytes([0x33u8; ECDSA_SK_LEN], Compression::Compressed);
    (*sk.to_wif(0x80).unwrap()).clone()
  }

  fn wif_wrong_length() -> String {
    base58ck::encode_check(&[0x80u8; 32])
  }

  fn wif_bad_compression_byte() -> String {
    let mut payload = [0u8; 34];
    payload[0] = 0x80;
    payload[1..33].copy_from_slice(&[0x44u8; ECDSA_SK_LEN]);
    payload[33] = 0x02;
    base58ck::encode_check(&payload)
  }

  #[rstest]
  #[case::zero_key(wif_zero_key(), 0x80)]
  #[case::bad_checksum(wif_bad_checksum(), 0x80)]
  #[case::wrong_prefix(wif_wrong_prefix(), 0xef)]
  #[case::wrong_length(wif_wrong_length(), 0x80)]
  #[case::bad_compression_byte(wif_bad_compression_byte(), 0x80)]
  fn wif_rejects(#[case] wif: String, #[case] prefix: u8) {
    assert!(EcdsaSkBytes::from_wif(&wif, prefix).is_none());
  }
}
