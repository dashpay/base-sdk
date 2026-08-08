//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Version and capability handshake.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;
use crate::version::ProtocolVersion;

use cfg_if::cfg_if;
use dash_num::Hash256;
use dash_primitives::{hash_impl, ServiceV1};
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::{make_num, CompactSize, TypeId, Unencodable};

use core::fmt;
use core::ops::{BitAnd, BitOr, BitOrAssign};

/// Maximum user agent (subversion) length in bytes.
const MAX_USER_AGENT: usize = 256;

make_num! {
  /// Bitfield advertised in `version` messages describing node capabilities.
  ServiceFlags, u64, 8
}

hash_impl!(ServiceFlags);

impl ServiceFlags {
  /// No services.
  pub const NONE: Self = Self(0);
  /// Full blockchain data.
  pub const NODE_NETWORK: Self = Self(1 << 0);
  /// BIP37 bloom filters.
  pub const NODE_BLOOM: Self = Self(1 << 2);
  /// BIP157 compact block filters.
  pub const NODE_COMPACT_FILTERS: Self = Self(1 << 6);
  /// Last 288 blocks only.
  pub const NODE_NETWORK_LIMITED: Self = Self(1 << 10);
  /// Dash compressed headers (headers2).
  pub const NODE_HEADERS_COMPRESSED: Self = Self(1 << 11);
  /// BIP324 v2 transport.
  pub const NODE_P2P_V2: Self = Self(1 << 12);

  /// Returns `true` if all bits in `flag` are set.
  pub const fn has(self, flag: Self) -> bool {
    self.0 & flag.0 == flag.0
  }
}

impl BitAnd for ServiceFlags {
  type Output = Self;
  fn bitand(self, rhs: Self) -> Self {
    Self(self.0 & rhs.0)
  }
}

impl BitOr for ServiceFlags {
  type Output = Self;
  fn bitor(self, rhs: Self) -> Self {
    Self(self.0 | rhs.0)
  }
}

impl BitOrAssign for ServiceFlags {
  fn bitor_assign(&mut self, rhs: Self) {
    self.0 |= rhs.0;
  }
}

/// The user agent exceeds the 256-byte limit.
#[derive(Debug, Clone, PartialEq, Eq, Unencodable)]
pub struct UserAgentTooLong {
  /// Actual length in bytes.
  pub len: usize,
}

impl fmt::Display for UserAgentTooLong {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "user agent too long: {} bytes, max {MAX_USER_AGENT}", self.len)
  }
}

/// CompactSize-prefixed user agent bytestring.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
pub struct UserAgent(Vec<u8>);

impl_p2p!(UserAgent);

impl BaseCodec for UserAgent {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let len = CompactSize::decode(data)?.into_len(MAX_USER_AGENT)?;
    let raw = codec::read_bytes(data, len)?;
    Ok(Self(raw.to_vec()))
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.0.encode(buf);
  }
}

hash_impl!(UserAgent);

impl UserAgent {
  /// Creates a new user agent from raw bytes.
  ///
  /// # Errors
  ///
  /// Returns `UserAgentTooLong` if `bytes` exceeds 256 bytes.
  pub fn new(bytes: Vec<u8>) -> Result<Self, UserAgentTooLong> {
    if bytes.len() > MAX_USER_AGENT {
      return Err(UserAgentTooLong { len: bytes.len() });
    }
    Ok(Self(bytes))
  }

  /// Returns the user agent bytes as a str, if valid UTF-8.
  pub fn as_str(&self) -> Option<&str> {
    core::str::from_utf8(&self.0).ok()
  }

  /// Returns the raw bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }

  /// Returns the length in bytes.
  pub fn len(&self) -> usize {
    self.0.len()
  }

  /// Returns `true` if the user agent is empty.
  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }
}

impl fmt::Display for UserAgent {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self.as_str() {
      Some(s) => f.write_str(s),
      None => write!(f, "<{} bytes>", self.0.len()),
    }
  }
}

cfg_if! {
  if #[cfg(feature = "serde")] {
    use serde::{Serializer, Deserializer, ser::Error as SerError, de::Error as DeError};

    impl ::serde::Serialize for UserAgent {
      fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.as_str() {
          Some(text) => s.serialize_str(text),
          None => Err(SerError::custom("user agent contains non-utf8 data")),
        }
      }
    }

    impl<'de> ::serde::Deserialize<'de> for UserAgent {
      fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = <String as ::serde::Deserialize>::deserialize(d)?;
        Self::new(text.into_bytes()).map_err(DeError::custom)
      }
    }
  }
}

/// Network address with service flags (used inside the version message).
///
/// Wire format: `u64 services` + `[u8; 16] addr` + `u16 BE port`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct VersionAddr {
  /// Advertised services.
  pub services: ServiceFlags,
  /// IPv4-mapped IPv6 address + port.
  pub addr: ServiceV1,
}

codec_p2p!(VersionAddr { services, addr });

impl fmt::Display for VersionAddr {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?} ({})", self.addr, self.services)
  }
}

/// The `version` message initiates the P2P handshake.
///
/// Dash extends the Bitcoin version message with two additional
/// fields for masternode authentication.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Version {
  /// Sender's protocol version.
  pub protocol_version: ProtocolVersion,
  /// Sender's advertised services.
  pub services: ServiceFlags,
  /// Unix timestamp of the sender.
  pub timestamp: i64,
  /// Receiver's address as seen by the sender.
  pub addr_recv: VersionAddr,
  /// Sender's own address.
  pub addr_send: VersionAddr,
  /// Random nonce for connection deduplication.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  pub nonce: u64,
  /// User agent string.
  pub user_agent: UserAgent,
  /// Sender's best block height.
  pub start_height: i32,
  /// Whether the sender wants transaction relay.
  pub relay: bool,
  /// Dash: masternode authentication challenge.
  pub mnauth_challenge: Hash256,
  /// Dash: whether the sender identifies as a masternode.
  pub mn_connection: bool,
}

codec_p2p!(Version {
  protocol_version,
  services,
  timestamp,
  addr_recv,
  addr_send,
  nonce,
  user_agent,
  start_height,
  relay,
  mnauth_challenge,
  mn_connection,
});

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_version() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "version");
    let items = corpus.entries::<Version>("version", check_wire);
    assert_serde_rt("version", &items);
  }
}
