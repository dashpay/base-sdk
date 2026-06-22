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
  I2p,
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
      5 => Self::I2p,
      6 => Self::Cjdns,
      other => Self::Unknown(other),
    }
  }

  fn to_base(&self) -> u8 {
    match self {
      Self::Ipv4 => 1,
      Self::Ipv6 => 2,
      Self::TorV3 => 4,
      Self::I2p => 5,
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
      Self::I2p => Some(32),
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
      Self::I2p => f.write_str("i2p"),
      Self::Cjdns => f.write_str("cjdns"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

/// BIP155 network address.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum AddrV2 {
  /// IPv4 address (4 bytes).
  Ipv4([u8; 4]),
  /// IPv6 address (16 bytes).
  Ipv6([u8; 16]),
  /// Onion hidden service (32 bytes).
  TorV3([u8; 32]),
  /// I2P address (32 bytes).
  I2p([u8; 32]),
  /// CJDNS address (16 bytes).
  Cjdns([u8; 16]),
  /// Unknown network type with raw address bytes.
  Unknown {
    /// Wire network ID.
    network: u8,
    /// Raw address bytes.
    addr: Vec<u8>,
  },
}

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
    let raw = codec::read_bytes(data, len)?;
    match network {
      NetworkType::Ipv4 => {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(raw);
        Ok(Self::Ipv4(buf))
      }
      NetworkType::Ipv6 => {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(raw);
        // BIP155: fc00::/8 is CJDNS, not generic IPv6.
        if buf[0] == 0xfc {
          Ok(Self::Cjdns(buf))
        } else {
          Ok(Self::Ipv6(buf))
        }
      }
      NetworkType::TorV3 => {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(raw);
        Ok(Self::TorV3(buf))
      }
      NetworkType::I2p => {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(raw);
        Ok(Self::I2p(buf))
      }
      NetworkType::Cjdns => {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(raw);
        Ok(Self::Cjdns(buf))
      }
      NetworkType::Unknown(n) => Ok(Self::Unknown {
        network: n,
        addr: raw.to_vec(),
      }),
    }
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.network().to_base().encode(buf);
    let bytes = self.bytes();
    codec::write_compact_size(bytes.len(), buf);
    buf.extend_from_slice(bytes);
  }
}

impl_type!(AddrV2);

impl AddrV2 {
  /// Returns the BIP155 network type for this address.
  pub fn network(&self) -> NetworkType {
    match self {
      Self::Ipv4(_) => NetworkType::Ipv4,
      Self::Ipv6(_) => NetworkType::Ipv6,
      Self::TorV3(_) => NetworkType::TorV3,
      Self::I2p(_) => NetworkType::I2p,
      Self::Cjdns(_) => NetworkType::Cjdns,
      Self::Unknown { network, .. } => NetworkType::Unknown(*network),
    }
  }

  /// Raw address bytes.
  pub fn bytes(&self) -> &[u8] {
    match self {
      Self::Ipv4(b) => b,
      Self::Ipv6(b) => b,
      Self::TorV3(b) => b,
      Self::I2p(b) => b,
      Self::Cjdns(b) => b,
      Self::Unknown { addr, .. } => addr,
    }
  }
}

impl fmt::Display for AddrV2 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.network())
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
