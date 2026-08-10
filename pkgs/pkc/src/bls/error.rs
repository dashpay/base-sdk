//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Error type for BLS operations.

use core::fmt;

/// Errors produced by BLS operations.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BlsError {
  /// public key and message counts do not match
  CountMismatch,
  /// repeated message in a distinct-message aggregate
  DuplicateMessage,
  /// duplicate share id in recovery set
  DuplicateShareId,
  /// no items provided for aggregation
  EmptyAggregation,
  /// not enough shares to recover
  InsufficientShares,
  /// input keying material is too short (need >= 32 bytes)
  InvalidKeyMaterial,
  /// public key bytes are not a valid G1 point
  InvalidPublicKey,
  /// secret key bytes are not a valid scalar
  InvalidSecretKey,
  /// share id reduces to zero in the scalar field
  InvalidShareId,
  /// signature bytes are not a valid G2 point
  InvalidSignature,
  /// verification vector needs at least 2 elements
  InvalidVerificationVector,
  /// threshold is below 2 or exceeds the number of ids
  ThresholdTooLarge,
  /// signature verification failed
  VerifyFailed,
}

impl fmt::Display for BlsError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::CountMismatch => write!(f, "public key and message counts differ"),
      Self::DuplicateMessage => write!(f, "repeated message in a distinct-message aggregate"),
      Self::DuplicateShareId => write!(f, "duplicate share id in recovery set"),
      Self::EmptyAggregation => write!(f, "no items provided for aggregation"),
      Self::InsufficientShares => write!(f, "not enough shares to recover"),
      Self::InvalidKeyMaterial => write!(f, "input keying material too short"),
      Self::InvalidPublicKey => write!(f, "invalid public key bytes"),
      Self::InvalidSecretKey => write!(f, "invalid secret key bytes"),
      Self::InvalidShareId => write!(f, "share id reduces to zero in the scalar field"),
      Self::InvalidSignature => write!(f, "invalid signature bytes"),
      Self::InvalidVerificationVector => write!(f, "verification vector needs at least 2 elements"),
      Self::ThresholdTooLarge => write!(f, "threshold is below 2 or exceeds the number of ids"),
      Self::VerifyFailed => write!(f, "signature verification failed"),
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for BlsError {}
