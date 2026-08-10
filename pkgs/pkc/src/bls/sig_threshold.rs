//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold signature recovery via Lagrange interpolation.

use super::error::BlsError;
use super::scheme_ops::BlsScheme;
use super::share_ops::BlsSigShare;
use super::sig_basic::BlsSignature;
use crate::prelude::*;

use dash_num::Hash256;

impl<S: BlsScheme> BlsSignature<S> {
  /// Recover a full signature from threshold signature shares via Lagrange
  /// interpolation in G2.
  ///
  /// # Errors
  ///
  /// Returns `InsufficientShares` if fewer than 2 shares are provided,
  /// `InvalidShareId`/`DuplicateShareId` on bad ids, or `InvalidSignature`
  /// when a share fails to decode.
  pub fn recover(shares: &[&BlsSigShare<S>]) -> Result<Self, BlsError> {
    let ids: Vec<&Hash256> = shares.iter().map(|s| s.id()).collect();
    let sigs: Vec<&S::InnerSig> = shares.iter().map(|s| &s.signature().0).collect();

    S::recover_sig_shares(&ids, &sigs).map(BlsSignature::from_inner)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::bls::scheme_ops::BlsScheme;
  use crate::bls::tests::{sequential_ids, MSG_DEADBEEF, SEED_0};
  use crate::bls::{BlsError, BlsScChia, BlsScIetf, BlsSecretKey, BlsSigShare, BlsSignature};
  use crate::prelude::*;

  use rand_core::OsRng;
  use rstest::rstest;

  fn assert_threshold_split_recover<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let pk = sk.public_key();
    let ids = sequential_ids(5);

    let shares = sk.split(3, &ids, &mut OsRng).unwrap();
    assert_eq!(shares.len(), 5);

    // Any threshold-sized subset recovers the master signature. Comparing
    // against the master's own signature, not just verifying, is what pins
    // interpolation to the right point rather than to a self-consistent one.
    let msg = S::msg_ref(&MSG_DEADBEEF);
    let sig_shares: Vec<BlsSigShare<S>> = shares[..3].iter().map(|s| s.sign(msg)).collect();
    let refs: Vec<&BlsSigShare<S>> = sig_shares.iter().collect();
    let recovered = BlsSignature::<S>::recover(&refs).unwrap();
    assert!(recovered.verify(msg, &pk).is_ok());
    assert_eq!(recovered.to_bytes(), sk.sign(msg).to_bytes());

    // A different subset recovers the identical signature.
    let sig_shares2: Vec<BlsSigShare<S>> = shares[2..5].iter().map(|s| s.sign(msg)).collect();
    let refs2: Vec<&BlsSigShare<S>> = sig_shares2.iter().collect();
    let recovered2 = BlsSignature::<S>::recover(&refs2).unwrap();
    assert_eq!(recovered.to_bytes(), recovered2.to_bytes());
  }

  #[rstest]
  #[case::chia(assert_threshold_split_recover::<BlsScChia>)]
  #[case::ietf(assert_threshold_split_recover::<BlsScIetf>)]
  fn threshold_split_and_recover(#[case] assertion: fn()) {
    assertion();
  }

  /// Interpolating fewer than `threshold` shares still yields a point, so the
  /// guard against a short quorum is that the result fails verification.
  fn assert_sub_threshold_does_not_verify<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let pk = sk.public_key();
    let shares = sk.split(3, &sequential_ids(5), &mut OsRng).unwrap();
    let msg = S::msg_ref(&MSG_DEADBEEF);
    let signed: Vec<BlsSigShare<S>> = shares.iter().map(|s| s.sign(msg)).collect();

    let below = BlsSignature::<S>::recover(&[&signed[0], &signed[1]]).unwrap();
    assert!(below.verify(msg, &pk).is_err());

    let at = BlsSignature::<S>::recover(&[&signed[0], &signed[2], &signed[4]]).unwrap();
    assert!(at.verify(msg, &pk).is_ok());
  }

  #[rstest]
  #[case::chia(assert_sub_threshold_does_not_verify::<BlsScChia>)]
  #[case::ietf(assert_sub_threshold_does_not_verify::<BlsScIetf>)]
  fn sub_threshold_recovery_does_not_verify(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_insufficient_shares_rejected<S: BlsScheme>() {
    assert!(matches!(
      BlsSignature::<S>::recover(&[]),
      Err(BlsError::InsufficientShares)
    ));

    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let ids = sequential_ids(3);
    let shares = sk.split(2, &ids, &mut OsRng).unwrap();
    let one = shares[0].sign(S::msg_ref(&MSG_DEADBEEF));
    assert!(matches!(
      BlsSignature::<S>::recover(&[&one]),
      Err(BlsError::InsufficientShares)
    ));
  }

  #[rstest]
  #[case::chia(assert_insufficient_shares_rejected::<BlsScChia>)]
  #[case::ietf(assert_insufficient_shares_rejected::<BlsScIetf>)]
  fn recover_rejects_insufficient_shares(#[case] assertion: fn()) {
    assertion();
  }
}
