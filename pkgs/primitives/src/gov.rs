//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance object and vote types as defined by the Dash protocol.

use crate::codec_type;
use crate::outpoint::OutPoint;
use crate::prelude::*;
use crate::TxHash;

use bitcoin_hashes::sha256d;
use bitcoin_units::Amount;
use dash_types::codec::{self, BaseCodec, Checkable, NumCodec};
use dash_types::impl_num;
use hex_conservative::DisplayHex;

use core::fmt;

/// Maximum allowed name length for governance proposals.
const MAX_PROPOSAL_NAME_LEN: usize = 40;

/// Minimum URL length for governance proposals.
const MIN_URL_LEN: usize = 4;

/// Allowed characters in governance proposal names.
const PROPOSAL_NAME_CHARS: &[u8] = b"-_abcdefghijklmnopqrstuvwxyz0123456789";

/// Governance object type codes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GovObjectType {
  /// Unknown or unrecognized type.
  Unknown,
  /// Budget proposal.
  Proposal,
  /// Superblock trigger.
  Trigger,
}

impl NumCodec<i32> for GovObjectType {
  fn from_base(v: i32) -> Self {
    match v {
      1 => Self::Proposal,
      2 => Self::Trigger,
      _ => Self::Unknown,
    }
  }

  fn to_base(&self) -> i32 {
    match self {
      Self::Unknown => 0,
      Self::Proposal => 1,
      Self::Trigger => 2,
    }
  }
}

impl_num!(GovObjectType, i32);

impl fmt::Display for GovObjectType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Unknown => write!(f, "unknown"),
      Self::Proposal => write!(f, "proposal"),
      Self::Trigger => write!(f, "trigger"),
    }
  }
}

/// A governance proposal payload (type 1 JSON).
///
/// ```json
/// {
///   "type": 1,
///   "name": "proposal-name",
///   "url": "https://example.com/proposal",
///   "payment_address": "XaddressHere",
///   "payment_amount": "10.5",
///   "start_epoch": 1700000000,
///   "end_epoch": 1703000000
/// }
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Proposal {
  /// Short name (max 40 chars, lowercase alphanum + `-_`).
  pub name: String,
  /// Proposal URL.
  pub url: String,
  /// Dash address receiving payment.
  pub payment_address: String,
  /// Payment amount.
  #[cfg_attr(feature = "serde", serde(with = "crate::serialize::amount"))]
  pub payment_amount: Amount,
  /// Unix timestamp when payments begin.
  pub start_epoch: i64,
  /// Unix timestamp when payments end.
  pub end_epoch: i64,
}

/// A superblock trigger payload (type 2 JSON).
///
/// ```json
/// {
///   "type": 2,
///   "event_block_height": 123456,
///   "payment_addresses": "addr1|addr2",
///   "payment_amounts": "10.5|20.0",
///   "proposal_hashes": "hash1|hash2"
/// }
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Trigger {
  /// Block height at which payments occur.
  pub event_block_height: i32,
  /// Pipe-delimited payment addresses.
  pub payment_addresses: String,
  /// Pipe-delimited payment amounts.
  pub payment_amounts: String,
  /// Pipe-delimited proposal hashes.
  pub proposal_hashes: String,
}

/// Decoded governance object data payload.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum GovData {
  /// Budget proposal.
  Proposal(Proposal),
  /// Superblock trigger.
  Trigger(Trigger),
  /// Opaque data for unknown types.
  Unknown(Vec<u8>),
}

/// A governance object as serialized on the wire.
///
/// ```text
/// hash_parent(32) || revision(i32) || time(i64)
/// || collateral_hash(32) || data(CompactSize + bytes)
/// || type(i32) || masternode_outpoint(36)
/// || sig(CompactSize + bytes)
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct GovObject {
  /// Parent object hash (zero for root).
  pub hash_parent: TxHash,
  /// Object revision.
  pub revision: i32,
  /// Creation timestamp.
  pub time: i64,
  /// Collateral transaction hash.
  pub collateral_hash: TxHash,
  /// Raw data bytes (JSON when decoded as string).
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub data: Vec<u8>,
  /// Object type code.
  pub object_type: GovObjectType,
  /// Signing masternode outpoint.
  pub masternode_outpoint: OutPoint,
  /// BLS or ECDSA signature.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub sig: Vec<u8>,
}

codec_type!(GovObject {
  hash_parent,
  revision,
  time,
  collateral_hash,
  data,
  object_type,
  masternode_outpoint,
  sig,
});

impl GovObject {
  /// Computes the canonical governance object hash.
  ///
  /// The hash input differs from the wire format: `collateral_hash` and
  /// `object_type` are excluded, and `data` is hex-encoded as ASCII bytes
  /// before hashing.
  pub fn hash(&self) -> TxHash {
    let data_hex = self.data.to_lower_hex_string();

    let mut buf = Vec::new();
    buf.extend_from_slice(self.hash_parent.as_bytes());
    buf.extend_from_slice(&self.revision.to_le_bytes());
    buf.extend_from_slice(&self.time.to_le_bytes());
    // data hex is serialized as a string (CompactSize + bytes)
    codec::write_compact_size(data_hex.len(), &mut buf);
    buf.extend_from_slice(data_hex.as_bytes());
    // outpoint + dummy padding for legacy hash compat
    buf.extend_from_slice(self.masternode_outpoint.hash.as_bytes());
    buf.extend_from_slice(&self.masternode_outpoint.index.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    self.sig.encode(&mut buf);

    TxHash::from_bytes(sha256d::Hash::hash(&buf).to_byte_array())
  }

  /// Returns the data as a UTF-8 string, if valid.
  pub fn data_as_string(&self) -> Option<&str> {
    core::str::from_utf8(&self.data).ok()
  }

  /// Returns the data as a hex string.
  pub fn data_as_hex(&self) -> String {
    self.data.to_lower_hex_string()
  }
}

/// Governance vote outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoteOutcome {
  /// No vote cast.
  None,
  /// Vote in favour.
  Yes,
  /// Vote against.
  No,
  /// Abstention.
  Abstain,
  /// Unrecognised outcome.
  Unknown(u32),
}

impl NumCodec<u32> for VoteOutcome {
  fn from_base(v: u32) -> Self {
    match v {
      0 => Self::None,
      1 => Self::Yes,
      2 => Self::No,
      3 => Self::Abstain,
      other => Self::Unknown(other),
    }
  }

  fn to_base(&self) -> u32 {
    match self {
      Self::None => 0,
      Self::Yes => 1,
      Self::No => 2,
      Self::Abstain => 3,
      Self::Unknown(v) => *v,
    }
  }
}

impl_num!(VoteOutcome, u32);

impl fmt::Display for VoteOutcome {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::None => f.write_str("none"),
      Self::Yes => f.write_str("yes"),
      Self::No => f.write_str("no"),
      Self::Abstain => f.write_str("abstain"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

/// Governance vote signal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoteSignal {
  /// No signal.
  None,
  /// Fund this object.
  Funding,
  /// Object checks out.
  Valid,
  /// Object should be deleted.
  Delete,
  /// Officially endorsed.
  Endorsed,
  /// Unrecognised signal.
  Unknown(u32),
}

impl NumCodec<u32> for VoteSignal {
  fn from_base(v: u32) -> Self {
    match v {
      0 => Self::None,
      1 => Self::Funding,
      2 => Self::Valid,
      3 => Self::Delete,
      4 => Self::Endorsed,
      other => Self::Unknown(other),
    }
  }

  fn to_base(&self) -> u32 {
    match self {
      Self::None => 0,
      Self::Funding => 1,
      Self::Valid => 2,
      Self::Delete => 3,
      Self::Endorsed => 4,
      Self::Unknown(v) => *v,
    }
  }
}

impl_num!(VoteSignal, u32);

impl fmt::Display for VoteSignal {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::None => f.write_str("none"),
      Self::Funding => f.write_str("funding"),
      Self::Valid => f.write_str("valid"),
      Self::Delete => f.write_str("delete"),
      Self::Endorsed => f.write_str("endorsed"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

/// A governance vote.
///
/// ```text
/// masternode_outpoint(36) || parent_hash(32)
/// || outcome(u32) || signal(u32) || time(i64)
/// || sig(CompactSize + bytes)
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct GovVote {
  /// Voting masternode outpoint.
  pub masternode_outpoint: OutPoint,
  /// Hash of the governance object being voted on.
  pub parent_hash: TxHash,
  /// Vote outcome.
  pub outcome: VoteOutcome,
  /// Vote signal type.
  pub signal: VoteSignal,
  /// Vote timestamp.
  pub time: i64,
  /// Signature bytes.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub sig: Vec<u8>,
}

codec_type!(GovVote {
  masternode_outpoint,
  parent_hash,
  outcome,
  signal,
  time,
  sig,
});

impl GovVote {
  /// Computes the canonical vote hash, including dummy padding after the
  /// outpoint for legacy compatibility.
  pub fn hash(&self) -> TxHash {
    let mut buf = Vec::new();
    // outpoint + dummy padding for legacy hash compat
    buf.extend_from_slice(self.masternode_outpoint.hash.as_bytes());
    buf.extend_from_slice(&self.masternode_outpoint.index.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    buf.extend_from_slice(self.parent_hash.as_bytes());
    buf.extend_from_slice(&self.signal.to_base().to_le_bytes());
    buf.extend_from_slice(&self.outcome.to_base().to_le_bytes());
    buf.extend_from_slice(&self.time.to_le_bytes());

    TxHash::from_bytes(sha256d::Hash::hash(&buf).to_byte_array())
  }
}

/// Governance proposal validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProposalInvalid {
  /// Name is empty.
  NameEmpty,
  /// Name exceeds maximum length.
  NameTooLong { len: usize },
  /// Name contains invalid characters.
  NameInvalidChars,
  /// `end_epoch` is not after `start_epoch`.
  BadEpochRange,
  /// Payment amount is not positive.
  BadPaymentAmount,
  /// URL is too short.
  UrlTooShort { len: usize },
  /// URL contains whitespace.
  UrlWhitespace,
}

impl fmt::Display for ProposalInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::NameEmpty => write!(f, "invalid name: empty"),
      Self::NameTooLong { len } => write!(f, "invalid name: {len} chars exceeds {MAX_PROPOSAL_NAME_LEN}"),
      Self::NameInvalidChars => write!(f, "invalid name: disallowed characters"),
      Self::BadEpochRange => write!(f, "invalid start:end range"),
      Self::BadPaymentAmount => write!(f, "invalid payment amount"),
      Self::UrlTooShort { len } => write!(f, "url too short: {len} chars"),
      Self::UrlWhitespace => write!(f, "url has whitespace"),
    }
  }
}

impl Checkable for Proposal {
  type Error = ProposalInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.name.is_empty() {
      return Some(ProposalInvalid::NameEmpty);
    }
    if self.name.len() > MAX_PROPOSAL_NAME_LEN {
      return Some(ProposalInvalid::NameTooLong { len: self.name.len() });
    }
    if !self
      .name
      .bytes()
      .all(|b| PROPOSAL_NAME_CHARS.contains(&b.to_ascii_lowercase()))
    {
      return Some(ProposalInvalid::NameInvalidChars);
    }

    if self.end_epoch <= self.start_epoch {
      return Some(ProposalInvalid::BadEpochRange);
    }

    if self.payment_amount == Amount::ZERO {
      return Some(ProposalInvalid::BadPaymentAmount);
    }

    if self.url.len() < MIN_URL_LEN {
      return Some(ProposalInvalid::UrlTooShort { len: self.url.len() });
    }
    if self.url.bytes().any(|b| b.is_ascii_whitespace()) {
      return Some(ProposalInvalid::UrlWhitespace);
    }

    None
  }
}
