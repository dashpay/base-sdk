//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Hashed representation of secp256k1 public key.

use crate::prelude::*;

use base58ck::encode_check;
use dash_types::codec::{BaseCodec, EncodeBuf};
use dash_types::{make_bytes, ArrayBuf};

make_bytes! {
  /// 20-byte public key hash.
  PubKeyHash, 20
}

impl PubKeyHash {
  /// Encode as a Base58Check address with the given version prefix.
  pub fn to_base58c(&self, prefix: u8) -> String {
    let mut buf = ArrayBuf::<21>::new();
    buf.push(prefix);
    self.encode(&mut buf);
    encode_check(&buf.into_array())
  }
}
