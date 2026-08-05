//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Proof of Possession operations for BLS keys.

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::secret_ops::BlsSecretKey;
use super::sig_basic::BlsSignature;
use super::BlsScIetf;

impl BlsSecretKey<BlsScIetf> {
  /// Produce a proof of possession by signing the serialized public key.
  ///
  /// IETF only: the legacy scheme has no proof-of-possession domain
  /// separation tag, so there is no such method to call on it.
  pub fn prove_possession(&self) -> BlsSignature<BlsScIetf> {
    let pk = self.public_key();
    BlsSignature::from_inner(BlsScIetf::prove_possession(&self.0, &pk.0))
  }
}

impl BlsPublicKey<BlsScIetf> {
  /// Verify a proof of possession against this key.
  ///
  /// IETF only, mirroring [`BlsSecretKey::prove_possession`].
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` on mismatch.
  pub fn verify_possession(&self, pop: &BlsSignature<BlsScIetf>) -> Result<(), BlsError> {
    BlsScIetf::verify_possession(&self.0, &pop.0)
  }
}

#[cfg(all(test, feature = "tests"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::{SEED_0, SEED_1};

  use rstest::rstest;

  #[rstest]
  fn ietf_proof_of_possession_roundtrip() {
    let sk = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
    let proof = sk.prove_possession();
    assert!(sk.public_key().verify_possession(&proof).is_ok());
  }

  #[rstest]
  fn ietf_proof_of_possession_rejects_wrong_key() {
    let sk0 = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
    let sk1 = BlsSecretKey::<BlsScIetf>::generate(&SEED_1).unwrap();
    let proof = sk0.prove_possession();
    assert!(sk1.public_key().verify_possession(&proof).is_err());
  }
}
