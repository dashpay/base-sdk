//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Ed25519 public key byte bag.

use super::EddsaPkHash;

use bitcoin_hashes::sha256::Hash as Sha256;
use dash_types::{make_bytes, Hashable};

/// Raw Ed25519 public key length.
pub const EDDSA_PK_LEN: usize = 32;

make_bytes! {
  /// Ed25519 public key bytes (32 bytes, unvalidated).
  EddsaPkBytes, EDDSA_PK_LEN, fwd, nocodec
}

impl Hashable for EddsaPkBytes {
  type Hash = EddsaPkHash;

  /// A single SHA-256 over the key, truncated to 20 bytes.
  fn hash(&self) -> Self::Hash {
    let digest = Sha256::hash(self.as_bytes()).to_byte_array();
    let mut id = [0u8; 20];
    for (out, byte) in id.iter_mut().zip(digest[..20].iter().rev()) {
      *out = *byte;
    }
    EddsaPkHash::from(id)
  }
}
