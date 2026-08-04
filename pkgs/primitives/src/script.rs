//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Script-related types.

use crate::hash_impl;
use crate::prelude::*;

use dash_types::codec::{ArrayBuf, BaseCodec, EncodeBuf};
use dash_types::make_bytes;

make_bytes! {
  /// 20-byte public key hash (RIPEMD-160 of SHA-256).
  KeyId, 20
}

hash_impl!(KeyId);

impl KeyId {
  /// Encode as a Base58Check string with the given version prefix.
  pub fn to_base58c(&self, prefix: u8) -> String {
    let mut buf = ArrayBuf::<21>::new();
    buf.push(prefix);
    self.encode(&mut buf);
    base58ck::encode_check(&buf.into_array())
  }
}
