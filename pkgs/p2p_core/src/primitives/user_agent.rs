//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! User agent string exchanged in version messages.

use crate::codec::impl_p2p;
use crate::prelude::*;

use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};

use core::fmt;

/// Maximum user agent (subversion) length in bytes.
const MAX_USER_AGENT: usize = 256;

/// CompactSize-prefixed user agent bytestring.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UserAgent(Vec<u8>);

impl_p2p!(UserAgent);

/// The user agent exceeds the 256-byte limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAgentTooLong {
  /// Actual length in bytes.
  pub len: usize,
}

impl fmt::Display for UserAgentTooLong {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "user agent too long: {} bytes, max {MAX_USER_AGENT}", self.len)
  }
}

impl BaseCodec for UserAgent {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let len = codec::read_compact_size(data, MAX_USER_AGENT)?;
    let raw = codec::read_bytes(data, len)?;
    Ok(Self(raw.to_vec()))
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.0.encode(buf);
  }
}

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

#[cfg(feature = "serde")]
impl ::serde::Serialize for UserAgent {
  fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
    match self.as_str() {
      Some(text) => s.serialize_str(text),
      None => Err(::serde::ser::Error::custom("user agent contains non-utf8 data")),
    }
  }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for UserAgent {
  fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
    let text = <String as ::serde::Deserialize>::deserialize(d)?;
    Self::new(text.into_bytes()).map_err(::serde::de::Error::custom)
  }
}
