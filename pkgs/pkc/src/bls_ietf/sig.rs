//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS signature (96-byte compressed G2 point).

use super::{PublicKey, SecretKey, Signature};
use crate::bls::scheme_ietf::DST_POP_PROVE;
use crate::bls::scheme_ops::verify_ok;
use crate::bls::BlsError;

impl SecretKey {
  /// Produce a proof of possession by signing the serialized public key with
  /// the PoP DST.
  pub fn prove_possession(&self) -> Signature {
    let pk_bytes = self.public_key().to_bytes();
    Signature::from_inner(self.0.sign(&pk_bytes, DST_POP_PROVE, &[]))
  }
}

impl PublicKey {
  /// Verify a proof of possession against this key.
  ///
  /// # Errors
  ///
  /// Returns [`BlsError::VerifyFailed`] if the proof does not verify.
  pub fn verify_possession(&self, pop: &Signature) -> Result<(), BlsError> {
    let pk_bytes = self.to_bytes();
    verify_ok(pop.0.verify(true, &pk_bytes, DST_POP_PROVE, &[], &self.0, true))
  }
}
