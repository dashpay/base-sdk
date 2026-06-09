//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance-specific corpus test utilities.

use dash_primitives::gov::{GovObject, GovObjectType};
use dash_primitives::outpoint::OutPoint;
use dash_primitives::TxHash;
use dash_types::codec::BaseCodec;
use hex_conservative::FromHex;
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

/// Corpus representation of a governance object.
///
/// Mirrors [`GovObject`] but decodes the inner `data` payload as
/// structured JSON instead of storing it as a hex blob.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovCorpusDetails {
  pub hash_parent: TxHash,
  pub revision: i32,
  pub collateral_hash: TxHash,
  pub object_type: GovObjectType,
  pub time: i64,
  pub masternode_outpoint: OutPoint,
  #[serde(with = "dash_types::serialize::hex")]
  pub sig: Vec<u8>,
  pub data: serde_json::Value,
}

impl GovCorpusDetails {
  /// Builds a corpus representation from a wire-decoded object,
  /// parsing the inner `data` bytes as JSON.
  pub fn from_wire(obj: &GovObject) -> Self {
    Self {
      hash_parent: obj.hash_parent,
      revision: obj.revision,
      time: obj.time,
      collateral_hash: obj.collateral_hash,
      data: serde_json::from_slice(&obj.data).unwrap(),
      object_type: obj.object_type,
      masternode_outpoint: obj.masternode_outpoint,
      sig: obj.sig.clone(),
    }
  }

  /// Asserts that every non-data field matches the wire-decoded
  /// object, and that the inner data payload matches.
  fn assert_matches(&self, obj: &GovObject, label: &str) {
    assert_eq!(self.hash_parent, obj.hash_parent, "hash_parent: {label}");
    assert_eq!(self.revision, obj.revision, "revision: {label}");
    assert_eq!(self.time, obj.time, "time: {label}");
    assert_eq!(self.collateral_hash, obj.collateral_hash, "collateral_hash: {label}");
    assert_eq!(self.object_type, obj.object_type, "object_type: {label}");
    assert_eq!(
      self.masternode_outpoint, obj.masternode_outpoint,
      "masternode_outpoint: {label}"
    );
    assert_eq!(self.sig, obj.sig, "sig: {label}");

    let wire_data: serde_json::Value = serde_json::from_slice(&obj.data).unwrap();
    assert_eq!(self.data, wire_data, "data: {label}");
  }
}

/// Corpus entry with raw hex and decoded governance details.
#[derive(Debug, Deserialize)]
pub struct GovCorpusEntry {
  pub raw: String,
  pub details: GovCorpusDetails,
}

fn load_gov_section(section: &str) -> BTreeMap<String, GovCorpusEntry> {
  let path = format!("{}/corpus/{section}.json5", env!("CARGO_MANIFEST_DIR"));
  let text = std::fs::read_to_string(&path).unwrap();
  let mut outer: BTreeMap<String, BTreeMap<String, GovCorpusEntry>> = json5::from_str(&text).unwrap();
  outer.remove(section).unwrap()
}

pub fn check(section: &str) {
  let corpus = load_gov_section(section);
  assert!(!corpus.is_empty());
  for (obj_hash_hex, entry) in &corpus {
    let raw = Vec::<u8>::from_hex(&entry.raw).unwrap();
    let obj = GovObject::decode(&mut &raw[..]).unwrap();

    // Compare wire-decoded object against corpus details.
    entry.details.assert_matches(&obj, &format!("{section}/{obj_hash_hex}"));

    // Encode round-trip: re-encode and verify identical bytes.
    let mut encoded = Vec::new();
    obj.encode(&mut encoded);
    assert_eq!(encoded, raw, "encode round-trip: {section}/{obj_hash_hex}");

    // Serde round-trip the corpus representation.
    let json = serde_json::to_string(&entry.details).unwrap();
    let round_tripped: GovCorpusDetails = serde_json::from_str(&json).unwrap();
    round_tripped.assert_matches(&obj, &format!("serde round-trip: {section}/{obj_hash_hex}"));

    let computed_hash = obj.hash();
    let expected_hash = TxHash::from_hex(obj_hash_hex).unwrap();
    assert_eq!(computed_hash, expected_hash, "gov hash: {section}/{obj_hash_hex}");
  }
}
