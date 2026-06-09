//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared test helpers for P2P corpus tests.

use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec};
use hex_conservative::FromHex;
use serde::Deserialize;

use std::collections::BTreeMap;

/// A single corpus entry: raw wire hex and expected deserialized value.
#[derive(Debug, Deserialize)]
pub struct CorpusEntry<T> {
  pub raw: String,
  #[allow(dead_code, reason = "reserved for structural-match tests")]
  pub details: T,
}

/// Loads a named section from a corpus JSON5 file.
///
/// Corpus files live in `corpus/<file>.json5` and contain one or more
/// top-level keys (sections). Each section maps semantic hashes to
/// `{ raw, details }` entries.
#[expect(clippy::panic, reason = "test helper")]
pub fn load_section<T: serde::de::DeserializeOwned>(file: &str, section: &str) -> BTreeMap<String, CorpusEntry<T>> {
  let path = format!("{}/corpus/{file}.json5", env!("CARGO_MANIFEST_DIR"));
  let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
  // Parse the whole file as untyped JSON first, then extract and
  // deserialize only the requested section. This allows a single
  // corpus file to contain sections with different `details` types.
  let mut outer: BTreeMap<String, serde_json::Value> = json5::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
  let section_val = outer
    .remove(section)
    .unwrap_or_else(|| panic!("{path}: section \"{section}\" not found"));
  serde_json::from_value(section_val).unwrap_or_else(|e| panic!("{path}/{section}: {e}"))
}

/// Verifies every entry in a corpus section:
///
/// 1. The raw hex decodes to `T` via wire encoding.
/// 2. The wire-decoded value equals the `details` from the corpus.
/// 3. Re-encoding produces the original bytes (round-trip).
#[allow(dead_code, reason = "reserved for structural-match tests")]
#[expect(clippy::panic, reason = "test helper")]
pub fn check_corpus<T>(file: &str, section: &str)
where
  T: bitcoin_consensus_encoding::Encodable
    + bitcoin_consensus_encoding::Decodable
    + serde::de::DeserializeOwned
    + PartialEq
    + std::fmt::Debug,
  <T::Decoder as bitcoin_consensus_encoding::Decoder>::Error: std::fmt::Display,
{
  let corpus: BTreeMap<String, CorpusEntry<T>> = load_section(file, section);
  assert!(!corpus.is_empty(), "{file}/{section}: corpus is empty");

  for (label, entry) in &corpus {
    // 1. Wire decode.
    let bytes = Vec::<u8>::from_hex(&entry.raw).unwrap_or_else(|e| panic!("{file}/{section}/{label}: bad hex: {e}"));
    let decoded: T =
      decode_from_slice(&bytes).unwrap_or_else(|e| panic!("{file}/{section}/{label}: decode failed: {e}"));

    // 2. Structural match.
    assert_eq!(decoded, entry.details, "{file}/{section}/{label}: decoded != details");

    // 3. Round-trip.
    let encoded = encode_to_vec(&decoded);
    assert_eq!(encoded, bytes, "{file}/{section}/{label}: round-trip mismatch");
  }
}
