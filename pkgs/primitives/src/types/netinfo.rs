//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network information types and trait.

use super::{ServiceV1, ServiceV2};
use crate::prelude::*;

use dash_types::codec::{self, BaseCodec, DecodeError, NumCodec};
use dash_types::{impl_num, impl_type};

use core::fmt;

/// Maximum entries per purpose.
#[expect(unused, reason = "consensus constant")]
const MAX_ENTRIES: usize = 4;

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
  /// BIP155 address + port.
  Service(ServiceV2),
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

/// Interface for network information types.
pub trait NITrait: fmt::Display {
  /// Returns entries, optionally filtered by purpose.
  fn entries(&self, purpose: Option<NIPurpose>) -> impl Iterator<Item = NIEntry> + '_;

  /// Returns the primary service if available.
  fn primary(&self) -> Option<ServiceV2>;

  /// Returns `true` when this value carries no addresses.
  fn is_empty(&self) -> bool;

  /// Returns `true` if entries exist for the given purpose.
  fn has_entries(&self, purpose: NIPurpose) -> bool;

  /// Returns `true` when this type can carry platform addresses.
  fn stores_platform(&self) -> bool;
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
    let purpose_count = codec::read_compact_size(data, data.len())?;
    let mut entries = Vec::with_capacity(purpose_count);
    for _ in 0..purpose_count {
      let purpose = NIPurpose::from_base(u8::decode(data)?);
      let entry_count = codec::read_compact_size(data, data.len())?;
      let mut group = Vec::with_capacity(entry_count);
      for _ in 0..entry_count {
        let entry_type = u8::decode(data)?;
        let entry = match entry_type {
          0x01 => NIEntry::Service(ServiceV2::decode(data)?),
          0x02 => {
            let name_len = codec::read_compact_size(data, data.len())?;
            let name = codec::read_bytes(data, name_len)?.to_vec();
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
      let valid = group.iter().filter(|e| !matches!(e, NIEntry::Invalid));
      codec::write_compact_size(valid.clone().count(), buf);
      for entry in valid {
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

impl NITrait for NetInfoV2 {
  fn entries(&self, purpose: Option<NIPurpose>) -> impl Iterator<Item = NIEntry> + '_ {
    self
      .entries
      .iter()
      .filter(move |(pp, _)| purpose.is_none() || purpose == Some(*pp))
      .flat_map(|(_, group)| group.iter().cloned())
  }

  fn primary(&self) -> Option<ServiceV2> {
    self
      .entries
      .iter()
      .find(|(p, e)| *p == NIPurpose::CoreP2p && !e.is_empty())
      .and_then(|(_, entries)| {
        entries.iter().find_map(|e| match e {
          NIEntry::Service(svc) => Some(svc.clone()),
          _ => None,
        })
      })
  }

  fn is_empty(&self) -> bool {
    self.entries.iter().all(|(_, group)| group.is_empty())
  }

  fn has_entries(&self, purpose: NIPurpose) -> bool {
    self.entries.iter().any(|(p, e)| *p == purpose && !e.is_empty())
  }

  fn stores_platform(&self) -> bool {
    true
  }
}

/// Legacy network information wrapper.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct NetInfoV1(pub ServiceV1);

impl_type!(NetInfoV1);

impl BaseCodec for NetInfoV1 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self(ServiceV1::decode(data)?))
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.0.encode(buf);
  }
}

impl fmt::Display for NetInfoV1 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if self.0.addr.is_null() && self.0.port == 0 {
      return f.write_str("NetInfoV1()");
    }
    write!(f, "NetInfoV1({})", self.0)
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
