//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP155 network address types (ADDRv2).

use crate::prelude::*;

use dash_types::codec::{self, BaseCodec, DecodeError, NumCodec};
use dash_types::{impl_num, impl_type};

use core::fmt;

/// Maximum raw address length for any known BIP155 network type.
const MAX_ADDR_LEN: usize = 512;

/// Network address type (BIP155).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetworkType {
  /// IPv4.
  Ipv4,
  /// IPv6.
  Ipv6,
  /// Tor v3 hidden service.
  TorV3,
  /// I2P.
  I2P,
  /// CJDNS.
  Cjdns,
  /// Unknown network type.
  Unknown(u8),
}

impl NumCodec<u8> for NetworkType {
  fn from_base(val: u8) -> Self {
    match val {
      1 => Self::Ipv4,
      2 => Self::Ipv6,
      4 => Self::TorV3,
      5 => Self::I2P,
      6 => Self::Cjdns,
      other => Self::Unknown(other),
    }
  }

  fn to_base(&self) -> u8 {
    match self {
      Self::Ipv4 => 1,
      Self::Ipv6 => 2,
      Self::TorV3 => 4,
      Self::I2P => 5,
      Self::Cjdns => 6,
      Self::Unknown(v) => *v,
    }
  }
}

impl_num!(NetworkType, u8);

impl NetworkType {
  /// Expected byte length for a known network type, or `None` for unknown.
  pub const fn expected_len(self) -> Option<usize> {
    match self {
      Self::Ipv4 => Some(4),
      Self::Ipv6 => Some(16),
      Self::TorV3 => Some(32),
      Self::I2P => Some(32),
      Self::Cjdns => Some(16),
      Self::Unknown(_) => None,
    }
  }
}

impl fmt::Display for NetworkType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Ipv4 => f.write_str("ipv4"),
      Self::Ipv6 => f.write_str("ipv6"),
      Self::TorV3 => f.write_str("torv3"),
      Self::I2P => f.write_str("i2p"),
      Self::Cjdns => f.write_str("cjdns"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

/// BIP155 network address.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AddrV2 {
  /// Network transport type.
  pub network: NetworkType,
  /// Raw address bytes (length depends on network type).
  pub addr: Vec<u8>,
}

impl_type!(AddrV2);

impl BaseCodec for AddrV2 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let net_byte = u8::decode(data)?;
    let network = NetworkType::from_base(net_byte);
    let len = codec::read_compact_size(data, MAX_ADDR_LEN)?;
    if let Some(expected) = network.expected_len() {
      if len != expected {
        return Err(DecodeError::InvalidValue {
          expected: expected as u64,
          actual: len as u64,
        });
      }
    }
    let addr = codec::read_bytes(data, len)?.to_vec();
    Ok(Self { network, addr })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.network.to_base().encode(buf);
    self.addr.encode(buf);
  }
}

impl fmt::Display for AddrV2 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.network)
  }
}

/// BIP155 network service (address + port).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ServiceV2 {
  /// Typed network address.
  pub addr: AddrV2,
  /// Network port (big-endian on the wire).
  pub port: u16,
}

impl_type!(ServiceV2);

impl BaseCodec for ServiceV2 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let addr = AddrV2::decode(data)?;
    let port = codec::read_u16_be(data)?;
    Ok(Self { addr, port })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.addr.encode(buf);
    buf.extend_from_slice(&self.port.to_be_bytes());
  }
}

impl fmt::Display for ServiceV2 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.addr, self.port)
  }
}
