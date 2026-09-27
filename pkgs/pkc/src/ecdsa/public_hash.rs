//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Hashed representation of secp256k1 public key.

#[cfg(feature = "codec")]
use crate::prelude::*;

#[cfg(feature = "codec")]
use base58ck::Base58CkString;
use dash_num::make_hash;
#[cfg(feature = "codec")]
use dash_types::codec::{BaseCodec, EncodeBuf};
#[cfg(feature = "codec")]
use dash_types::ArrayBuf;

make_hash! {
  /// 20-byte public key hash.
  EcdsaPkHash, 20
}

#[cfg(feature = "codec")]
impl EcdsaPkHash {
  /// Encode as a Base58Check address with the given version prefix.
  pub fn to_base58c(&self, prefix: u8) -> String {
    let mut buf = ArrayBuf::<21>::new();
    buf.push(prefix);
    self.encode(&mut buf);
    String::from(Base58CkString::encode_unbounded(&buf.into_array()).as_str())
  }
}
