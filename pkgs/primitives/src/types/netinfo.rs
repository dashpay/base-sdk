//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Extended network info types for v3+ provider transactions.

use super::ServiceV1;
use crate::prelude::*;

use dash_types::codec::{self, BaseCodec, DecodeError, NumCodec};
use dash_types::{impl_num, impl_type};

use core::fmt;

/// Maximum entries per purpose.
const MAX_ENTRIES: usize = 8;
/// Maximum number of purpose groups.
const MAX_PURPOSES: usize = 8;

/// Purpose tag for an extended network info entry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NIPurpose {
  /// Core P2P port.
  CoreP2p,
  /// Platform P2P port.
  PlatformP2p,
  /// Platform HTTPS port.
  PlatformHttps,
  /// Unrecognized purpose code.
  Unknown(u8),
}

impl NumCodec<u8> for NIPurpose {
  fn from_base(val: u8) -> Self {
    match val {
      0 => Self::CoreP2p,
      1 => Self::PlatformP2p,
      2 => Self::PlatformHttps,
      other => Self::Unknown(other),
    }
  }

  fn to_base(&self) -> u8 {
    match self {
      Self::CoreP2p => 0,
      Self::PlatformP2p => 1,
      Self::PlatformHttps => 2,
      Self::Unknown(v) => *v,
    }
  }
}

impl_num!(NIPurpose, u8);

impl fmt::Display for NIPurpose {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::CoreP2p => write!(f, "core_p2p"),
      Self::PlatformP2p => write!(f, "platform_p2p"),
      Self::PlatformHttps => write!(f, "platform_https"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

/// A single network info entry within a purpose group.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum NIEntry {
  /// ADDRv1-style IP + port.
  Service(ServiceV1),
  /// Domain name + port.
  Domain {
    /// The domain name as raw bytes.
    #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::utf8"))]
    name: Vec<u8>,
    /// Network port (big-endian on wire).
    port: u16,
  },
  /// Invalid / placeholder entry.
  Invalid,
}

impl fmt::Display for NIEntry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Service(svc) => write!(f, "{svc}"),
      Self::Domain { name, port } => {
        let s = core::str::from_utf8(name).unwrap_or("<invalid utf-8>");
        write!(f, "{s}:{port}")
      }
      Self::Invalid => f.write_str("<invalid>"),
    }
  }
}

/// Extended network info for v3+ ProRegTx / ProUpServTx.
///
/// Contains a versioned list of purpose-grouped network entries (core P2P,
/// platform P2P, platform HTTPS).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct NetInfoV2 {
  /// Format version.
  pub version: u8,
  /// Purpose-grouped entries.
  pub entries: Vec<(NIPurpose, Vec<NIEntry>)>,
}

impl_type!(NetInfoV2);

impl BaseCodec for NetInfoV2 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u8::decode(data)?;
    let purpose_count = codec::read_compact_size(data, MAX_PURPOSES)?;
    let mut entries = Vec::with_capacity(purpose_count);
    for _ in 0..purpose_count {
      let purpose = NIPurpose::from_base(u8::decode(data)?);
      let entry_count = codec::read_compact_size(data, MAX_ENTRIES)?;
      let mut group = Vec::with_capacity(entry_count);
      for _ in 0..entry_count {
        let entry_type = u8::decode(data)?;
        let entry = match entry_type {
          0x01 => NIEntry::Service(ServiceV1::decode(data)?),
          0x02 => {
            let name: Vec<u8> = Vec::decode(data)?;
            let port = codec::read_u16_be(data)?;
            NIEntry::Domain { name, port }
          }
          _ => NIEntry::Invalid,
        };
        group.push(entry);
      }
      entries.push((purpose, group));
    }
    Ok(Self { version, entries })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    codec::write_compact_size(self.entries.len(), buf);
    for (purpose, group) in &self.entries {
      purpose.to_base().encode(buf);
      let valid_count = group.iter().filter(|e| !matches!(e, NIEntry::Invalid)).count();
      codec::write_compact_size(valid_count, buf);
      for entry in group {
        match entry {
          NIEntry::Service(svc) => {
            0x01u8.encode(buf);
            svc.encode(buf);
          }
          NIEntry::Domain { name, port } => {
            0x02u8.encode(buf);
            name.encode(buf);
            buf.extend_from_slice(&port.to_be_bytes());
          }
          NIEntry::Invalid => {}
        }
      }
    }
  }
}

impl fmt::Display for NetInfoV2 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if self.entries.is_empty() {
      return f.write_str("NetInfoV2()");
    }
    f.write_str("NetInfoV2(")?;
    for (i, (purpose, group)) in self.entries.iter().enumerate() {
      if i > 0 {
        f.write_str(", ")?;
      }
      write!(f, "{purpose}=[")?;
      for (j, entry) in group.iter().enumerate() {
        if j > 0 {
          f.write_str(", ")?;
        }
        write!(f, "{entry}")?;
      }
      f.write_str("]")?;
    }
    f.write_str(")")
  }
}

/// Masternode network info: legacy ServiceV1 or structured extended format.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum NetInfo {
  /// ADDRv1 ServiceV1 (18 bytes).
  Legacy(ServiceV1),
  /// Extended format (v3+) with purpose-grouped entries.
  Extended(NetInfoV2),
}
