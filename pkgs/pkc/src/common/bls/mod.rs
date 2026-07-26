//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS primitives shared between bls_ietf and bls_chia.

#[expect(dead_code, reason = "compile-time contracts, unused at runtime")]
pub(crate) mod contract;
pub(crate) mod threshold;

use crate::bls::blst_ffi::{self, Fr};
use crate::prelude::*;

use dash_num::Hash256;
use zeroize::{Zeroize, Zeroizing};

use core::fmt;

/// Sum secret key scalars (mod group order) via blst FFI.
pub(crate) fn sum_sk_scalars(key_bytes: &[[u8; 32]]) -> Result<[u8; 32], ()> {
  let mut acc = Fr::default();
  for bytes in key_bytes {
    let mut scalar = blst_ffi::scalar_from_bendian(bytes);
    let mut term = Fr::from(&scalar);
    acc = acc + term;
    term.zeroize();
    scalar.b.zeroize();
  }
  let mut out_scalar = blst::blst_scalar::from(&acc);
  let out_bytes = blst_ffi::bendian_from_scalar(&out_scalar);
  out_scalar.b.zeroize();
  acc.zeroize();
  Ok(out_bytes)
}

/// Participant id paired with its secret scalar bytes
pub(crate) struct RawShare {
  /// Participant identifier.
  pub(crate) id: Hash256,
  /// Secret scalar bytes, zeroized on drop.
  pub(crate) secret: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for RawShare {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("RawShare")
      .field("id", &self.id)
      .field("secret", &"[redacted]")
      .finish()
  }
}

/// Generate secret key shares from a polynomial with the
/// given constant term. Returns a Vec of (id, share_bytes)
/// pairs.
pub(crate) fn generate_shares(
  sk_bytes: &[u8; 32],
  threshold: usize,
  ids: &[Hash256],
  rng: &mut impl rand_core::CryptoRngCore,
) -> Result<Vec<RawShare>, ()> {
  let mut coeffs = Zeroizing::new(Vec::with_capacity(threshold));

  let mut sk_scalar = blst_ffi::scalar_from_bendian(sk_bytes);
  coeffs.push(Fr::from(&sk_scalar));
  sk_scalar.b.zeroize();

  for _ in 1..threshold {
    // Generate random 32-byte IKM from CSPRNG
    let mut ikm = zeroize::Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *ikm);
    let rand_sk = blst::min_pk::SecretKey::key_gen(ikm.as_ref(), &[]).map_err(|_| ())?;
    let mut rand_bytes = rand_sk.to_bytes();
    let mut rand_scalar = blst_ffi::scalar_from_bendian(&rand_bytes);
    coeffs.push(Fr::from(&rand_scalar));
    rand_bytes.zeroize();
    rand_scalar.b.zeroize();
  }

  let mut shares = Vec::with_capacity(ids.len());
  for id in ids {
    let x = threshold::fr_from_hash(id);
    let mut y = threshold::poly_eval(&coeffs, &x);

    let mut y_scalar = blst::blst_scalar::from(&y);
    let share = zeroize::Zeroizing::new(blst_ffi::bendian_from_scalar(&y_scalar));
    y_scalar.b.zeroize();
    y.zeroize();

    shares.push(RawShare { id: *id, secret: share });
  }

  Ok(shares)
}

/// Implement Hash via to_bytes() for a BLS type.
macro_rules! impl_hash_via_bytes {
  ($ty:ty) => {
    impl core::hash::Hash for $ty {
      fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
      }
    }
  };
}
pub(crate) use impl_hash_via_bytes;
