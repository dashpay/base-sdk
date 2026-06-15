//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network address types for P2P messages.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;
use crate::primitives::ServiceFlags;

use dash_primitives::NetworkType;
use dash_primitives::ServiceV1;
use dash_types::codec::{self, BaseCodec, DecodeError, NumCodec};

use core::fmt;

/// Network address with service flags (used inside the version message).
///
/// Wire format: `u64 services` + `[u8; 16] addr` + `u16 BE port`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct NetAddr {
  /// Advertised services.
  pub services: ServiceFlags,
  /// IPv4-mapped IPv6 address + port.
  pub addr: ServiceV1,
}

codec_p2p!(NetAddr { services, addr });

impl fmt::Display for NetAddr {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?} ({})", self.addr, self.services)
  }
}

/// Timestamped v1 address entry used in `addr` messages.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct TimestampedAddr {
  /// Seconds since Unix epoch.
  pub time: u32,
  /// Advertised services.
  pub services: ServiceFlags,
  /// IPv4-mapped IPv6 address + port.
  pub addr: ServiceV1,
}

codec_p2p!(TimestampedAddr { time, services, addr });

/// Maximum serialized address size in ADDRv2 (BIP155).
const MAX_ADDRV2_SIZE: usize = 512;

/// BIP155 v2 network address supporting multiple transport types.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AddrV2 {
  /// Network transport type.
  pub network: NetworkType,
  /// Raw address bytes (length depends on network type).
  pub addr: Vec<u8>,
}

impl_p2p!(AddrV2);

impl BaseCodec for AddrV2 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let net_byte = u8::decode(data)?;
    let network = NetworkType::from_base(net_byte);
    let len = codec::read_compact_size(data, MAX_ADDRV2_SIZE)?;
    if let Some(expected) = Self::expected_len(network) {
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

impl AddrV2 {
  /// Expected byte length for a given network type, if known.
  const fn expected_len(net: NetworkType) -> Option<usize> {
    match net {
      NetworkType::Ipv4 => Some(4),
      NetworkType::Ipv6 => Some(16),
      NetworkType::TorV3 => Some(32),
      NetworkType::I2P => Some(32),
      NetworkType::Cjdns => Some(16),
      NetworkType::Unknown(_) => None,
    }
  }
}

/// BIP155 timestamped v2 address entry used in `addrv2` messages.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AddrV2Entry {
  /// Seconds since Unix epoch.
  pub time: u32,
  /// Advertised services (CompactSize-encoded on wire).
  pub services: ServiceFlags,
  /// Network address.
  pub addr: AddrV2,
  /// Port number (big-endian on wire).
  pub port: u16,
}

impl_p2p!(AddrV2Entry);

impl BaseCodec for AddrV2Entry {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let time = u32::decode(data)?;
    let services = ServiceFlags(codec::read_compact_u64(data)?);
    let net_byte = u8::decode(data)?;
    let network = NetworkType::from_base(net_byte);
    let len = codec::read_compact_size(data, MAX_ADDRV2_SIZE)?;
    if let Some(expected) = AddrV2::expected_len(network) {
      if len != expected {
        return Err(DecodeError::InvalidValue {
          expected: expected as u64,
          actual: len as u64,
        });
      }
    }
    let addr = codec::read_bytes(data, len)?.to_vec();
    let port = codec::read_u16_be(data)?;
    Ok(Self {
      time,
      services,
      addr: AddrV2 { network, addr },
      port,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.time.encode(buf);
    codec::write_compact_size(self.services.0 as usize, buf);
    self.addr.network.to_base().encode(buf);
    self.addr.addr.encode(buf);
    buf.extend_from_slice(&self.port.to_be_bytes());
  }
}

impl fmt::Display for AddrV2Entry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?}:{}", self.addr.network, self.port)
  }
}
