//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 recoverable signature.

use super::error::EcdsaError;
use super::sig_ops::EcdsaSignature;
use super::Compression;

use dash_types::{enum_map, type_cvrt, Unencodable};
use k256::ecdsa::{RecoveryId, Signature};

enum_map! {
  /// Header flags for a compact recoverable ECDSA signature.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
  pub(super) enum CompactFlags, u8 {
    /// Uncompressed key, recovery id 0.
    Uncompressed0 = 27,
    /// Uncompressed key, recovery id 1.
    Uncompressed1 = 28,
    /// Uncompressed key, recovery id 2.
    Uncompressed2 = 29,
    /// Uncompressed key, recovery id 3.
    Uncompressed3 = 30,
    /// Compressed key, recovery id 0.
    Compressed0 = 31,
    /// Compressed key, recovery id 1.
    Compressed1 = 32,
    /// Compressed key, recovery id 2.
    Compressed2 = 33,
    /// Compressed key, recovery id 3.
    Compressed3 = 34,
  }
}

impl CompactFlags {
  /// Whether the signing key was compressed.
  pub const fn is_compressed(self) -> bool {
    self.to_base() >= Self::Compressed0.to_base()
  }

  /// Construct from recovery id and compression flag.
  pub const fn new(recovery_id: u8, compressed: bool) -> Option<Self> {
    if recovery_id > 3 {
      return None;
    }
    Some(Self::from_parts(recovery_id, compressed))
  }

  /// Construct from the low two bits of `recovery_id` and a compression flag.
  ///
  /// Total, unlike [`CompactFlags::new`]: the eight variants cover every
  /// combination, so a caller holding an already range-checked recovery id
  /// needs no fallible path.
  pub const fn from_parts(recovery_id: u8, compressed: bool) -> Self {
    match (recovery_id & 3, compressed) {
      (0, false) => Self::Uncompressed0,
      (1, false) => Self::Uncompressed1,
      (2, false) => Self::Uncompressed2,
      (_, false) => Self::Uncompressed3,
      (0, true) => Self::Compressed0,
      (1, true) => Self::Compressed1,
      (2, true) => Self::Compressed2,
      (_, true) => Self::Compressed3,
    }
  }

  /// Recovery ID.
  pub const fn recovery_id(self) -> u8 {
    (self.to_base() - Self::Uncompressed0.to_base()) & 3
  }
}

/// An ECDSA signature with recovery id and compression metadata.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
pub struct EcdsaRecSignature {
  sig: EcdsaSignature,
  flags: CompactFlags,
}

impl EcdsaRecSignature {
  pub(super) fn from_inner(inner: Signature, recovery_id: RecoveryId, compressed: Compression) -> Self {
    Self {
      sig: EcdsaSignature::from_inner(inner),
      flags: CompactFlags::from_parts(recovery_id.to_byte(), compressed.is_compressed()),
    }
  }

  /// Attach recovery metadata to a plain signature.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidRecoveryId`] if `recovery_id` is not in
  /// `0..=3`.
  pub fn from_parts(sig: EcdsaSignature, recovery_id: u8, compressed: Compression) -> Result<Self, EcdsaError> {
    let flags = CompactFlags::new(recovery_id, compressed.is_compressed()).ok_or(EcdsaError::InvalidRecoveryId)?;
    Ok(Self { sig, flags })
  }

  /// Whether the signing key was compressed.
  pub fn is_compressed(&self) -> bool {
    self.flags.is_compressed()
  }

  /// Return a signature with the S value normalised to the lower half of the
  /// curve order. Returns `None` if already normalised.
  pub fn normalize_s(&self) -> Option<Self> {
    // Negating S mirrors R across the X axis: X is unchanged and the Y parity
    // flips, so the recovery id toggles its low bit.
    let sig = self.sig.normalize_s()?;
    Some(Self {
      sig,
      flags: CompactFlags::from_parts(self.recovery_id() ^ 1, self.is_compressed()),
    })
  }

  /// Recovery ID.
  pub fn recovery_id(&self) -> u8 {
    self.flags.recovery_id()
  }

  /// The recovery id in the form the backend expects.
  ///
  /// Infallible, unlike [`RecoveryId::from_byte`]: `CompactFlags` encodes only
  /// ids in `0..=3`, so both bits are in range by construction.
  pub(super) const fn backend_recovery_id(&self) -> RecoveryId {
    let id = self.flags.recovery_id();
    RecoveryId::new(id & 1 == 1, id & 2 == 2)
  }

  /// The plain signature without recovery metadata.
  pub fn signature(&self) -> &EcdsaSignature {
    &self.sig
  }

  /// Serialize as 64-byte compact format (r || s).
  pub fn to_compact(&self) -> [u8; 64] {
    self.sig.to_compact()
  }
}

impl AsRef<EcdsaSignature> for EcdsaRecSignature {
  fn as_ref(&self) -> &EcdsaSignature {
    &self.sig
  }
}

type_cvrt!(From<EcdsaRecSignature> for EcdsaSignature, |rec| {
  rec.signature().clone()
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::ecdsa::tests::*;
  use crate::ecdsa::{Compression, EcdsaPublicKey, EcdsaRecSignature, EcdsaSignature};

  use rstest::*;

  /// The infallible bit-split must agree with the fallible byte parse it
  /// replaced, for every id the flags can hold.
  #[rstest]
  #[case(0)]
  #[case(1)]
  #[case(2)]
  #[case(3)]
  fn backend_recovery_id_matches_byte(#[case] id: u8, alice_sig: EcdsaSignature) {
    let rec = EcdsaRecSignature::from_parts(alice_sig, id, Compression::Compressed).unwrap();
    assert_eq!(rec.backend_recovery_id().to_byte(), id);
  }

  #[rstest]
  fn from_parts_rejects_out_of_range_id(alice_sig: EcdsaSignature) {
    assert!(EcdsaRecSignature::from_parts(alice_sig.clone(), 4, Compression::Compressed).is_err());
    assert!(EcdsaRecSignature::from_parts(alice_sig, 255, Compression::Compressed).is_err());
  }

  #[rstest]
  #[case(0)]
  #[case(1)]
  #[case(2)]
  #[case(3)]
  fn recovery_id_roundtrip(#[case] id: u8, alice_sig: EcdsaSignature) {
    let rec = EcdsaRecSignature::from_parts(alice_sig, id, Compression::Compressed).unwrap();
    assert_eq!(rec.recovery_id(), id);
  }

  #[rstest]
  fn normalize_s_flips_recovery_id(alice_rec_sig: EcdsaRecSignature) {
    // Library signs with low-S, so normalize_s returns None. To test the flip
    // we would need a high-S sig; verify the invariant instead: if normalize_s
    // returns Some, the recovery_id must differ.
    if let Some(normed) = alice_rec_sig.normalize_s() {
      assert_ne!(normed.recovery_id(), alice_rec_sig.recovery_id());
    }
  }

  #[rstest]
  fn normalize_s_flips_high_s_recoverable_signature(alice_pk: EcdsaPublicKey, alice_rec_sig: EcdsaRecSignature) {
    let compact = alice_rec_sig.to_compact();
    let mut high_bytes = [0u8; 64];
    high_bytes[..32].copy_from_slice(&compact[..32]);
    high_bytes[32..].copy_from_slice(&negate_scalar(&compact[32..]));
    let high_sig = EcdsaSignature::from_compact(&high_bytes).unwrap();

    // The curve primitive rejects high-S signatures at recovery time (see
    // `EcdsaSignature::verify`), so only the invariant that normalizing
    // restores the original signature and recovery id is checked here.
    let flipped_id = alice_rec_sig.recovery_id() ^ 1;
    let high_rec =
      EcdsaRecSignature::from_parts(high_sig, flipped_id, Compression::from(alice_rec_sig.is_compressed())).unwrap();

    let normalized = high_rec.normalize_s().unwrap();
    assert_eq!(normalized.recovery_id(), alice_rec_sig.recovery_id());
    assert_eq!(normalized, alice_rec_sig);
    assert_eq!(EcdsaPublicKey::recover(&MSG, &normalized).unwrap(), alice_pk);
  }

  #[rstest]
  fn verifies_without_downcast(alice_pk: EcdsaPublicKey, alice_rec_sig: EcdsaRecSignature) {
    assert!(alice_pk.verify(&MSG, &alice_rec_sig).is_ok());
    assert!(alice_pk.verify(&MSG, alice_rec_sig.signature()).is_ok());
  }
}
