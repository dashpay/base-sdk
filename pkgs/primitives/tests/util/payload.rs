//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Payload-specific corpus test utilities.

use super::{load_section, CorpusEntry};

use dash_primitives::payload::{
  AssetLock, AssetUnlock, CoinbaseCommitment, FinalCommitment, MnHardFork, ProRegTx, ProUpRegTx, ProUpRevTx,
  ProUpServTx,
};
use dash_types::codec::BaseCodec;
use serde::de::DeserializeOwned;

use std::collections::BTreeMap;

/// Wire-decode and encode a special transaction payload.
pub trait PayloadCodec: Sized {
  /// Decodes from raw bytes, panicking on failure.
  fn decode_payload(data: &[u8]) -> Self;
  /// Encodes into a byte buffer.
  fn encode_payload(&self) -> Vec<u8>;
}

macro_rules! impl_payload_codec {
  ($($ty:ty),* $(,)?) => {
    $(
      impl PayloadCodec for $ty {
        fn decode_payload(data: &[u8]) -> Self {
          Self::decode(&mut &data[..]).unwrap()
        }
        fn encode_payload(&self) -> Vec<u8> {
          let mut buf = Vec::new();
          self.encode(&mut buf);
          buf
        }
      }
    )*
  };
}

impl_payload_codec!(
  ProRegTx,
  ProUpServTx,
  ProUpRegTx,
  ProUpRevTx,
  CoinbaseCommitment,
  MnHardFork,
  FinalCommitment,
  AssetLock,
  AssetUnlock,
);

/// Verifies that wire-decoded and deserialized payload forms
/// agree for every entry in a corpus section, then serde,
/// binary, and payload encode round-trips.
pub fn check<T>(file: &str, section: &str)
where
  T: PartialEq + core::fmt::Debug + DeserializeOwned + PayloadCodec + serde::Serialize,
{
  let corpus: BTreeMap<String, CorpusEntry<T>> = load_section(file, section);
  assert!(!corpus.is_empty());
  for (label, entry) in &corpus {
    super::assert_txid(&entry.raw, label);
    let tx = super::decode_tx(&entry.raw);
    let lhs = T::decode_payload(&tx.extra_payload);
    let rhs = &entry.details;
    assert_eq!(lhs, *rhs, "{file}/{section}/{label}");
    let json = serde_json::to_string(&lhs).unwrap();
    let round_tripped: T = serde_json::from_str(&json).unwrap();
    assert_eq!(lhs, round_tripped, "serde round-trip: {file}/{section}/{label}");
    let encoded = lhs.encode_payload();
    assert_eq!(encoded, tx.extra_payload, "encode round-trip: {file}/{section}/{label}");
    super::assert_round_trip(&entry.raw, &tx, label);
  }
}
