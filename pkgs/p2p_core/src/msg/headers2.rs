//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compressed header messages: getheaders2, headers2, sendheaders2.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;
use crate::primitives::compressed_header::CompressionState;
use crate::primitives::protocol_version::ProtocolVersion;

use dash_primitives::BlockHash;
use dash_types::codec::{self, BaseCodec, DecodeError};

/// Maximum headers per message.
const MAX_HEADERS: usize = 2_000;

/// Requests compressed block headers starting from a locator.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetHeaders2 {
  /// Protocol version.
  pub version: ProtocolVersion,
  /// Block locator hashes (newest first).
  pub locator_hashes: Vec<BlockHash>,
  /// Stop hash (zero to get as many as possible).
  pub hash_stop: BlockHash,
}

codec_p2p!(GetHeaders2 {
  version,
  locator_hashes,
  hash_stop
});

/// Response carrying DIP-0025 delta-compressed block headers.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Headers2 {
  /// Fully resolved block headers (decompressed).
  pub headers: Vec<dash_primitives::BlockHeader>,
}

impl_p2p!(Headers2);

impl BaseCodec for Headers2 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let count = codec::read_compact_size(data, MAX_HEADERS)?;
    let mut state = CompressionState::new();
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
      headers.push(state.decode_header(data)?);
    }
    Ok(Self { headers })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    codec::write_compact_size(self.headers.len(), buf);
    let mut state = CompressionState::new();
    for h in &self.headers {
      state.encode_header(h, buf);
    }
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, load_corpus_file, read_corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_getheaders2() {
    let text = load_corpus_file(env!("CARGO_MANIFEST_DIR"), "headers2");
    let items = read_corpus::<GetHeaders2>(&text, "getheaders2", check_wire);
    assert_serde_rt("getheaders2", &items);
  }

  #[rstest]
  fn corpus_headers2() {
    let text = load_corpus_file(env!("CARGO_MANIFEST_DIR"), "headers2");
    let items = read_corpus::<Headers2>(&text, "headers2", check_wire);
    assert_serde_rt("headers2", &items);
  }
}
