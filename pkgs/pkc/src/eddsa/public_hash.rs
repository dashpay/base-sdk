//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Hashed representation of an Ed25519 public key.

use dash_num::make_hash;

make_hash! {
  /// 20-byte public key hash.
  EddsaPkHash, 20
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::prelude::*;

  use dash_dev::{arr_from_hex, Corpus};
  use dash_types::codec::BaseCodec;
  use hex_conservative::DisplayHex;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct OrderVector {
    wire: String,
    display: String,
  }

  /// Wire order pinning to satisfy rust-dashcore#887
  #[rstest]
  fn corpus_wire_order() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "eddsa_node_id");

    for v in corpus.vectors::<OrderVector>("wire_order") {
      let wire = arr_from_hex::<20>(&v.wire);
      let id = EddsaPkHash::decode(&mut wire.as_slice()).unwrap();

      assert_eq!(id.to_string(), v.display);
      assert_eq!(id.as_bytes().to_lower_hex_string(), v.wire);

      let mut buf = Vec::new();
      id.encode(&mut buf);

      assert_eq!(buf.as_slice().to_lower_hex_string(), v.wire);
    }
  }
}
