//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network address types for P2P messages.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;
use crate::primitives::ServiceFlags;

use dash_primitives::{AddrV2, ServiceV1};
use dash_types::codec::{self, BaseCodec, DecodeError};

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
    let addr = AddrV2::decode(data)?;
    let port = codec::read_u16_be(data)?;
    Ok(Self {
      time,
      services,
      addr,
      port,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.time.encode(buf);
    codec::write_compact_size(self.services.0 as usize, buf);
    self.addr.encode(buf);
    buf.extend_from_slice(&self.port.to_be_bytes());
  }
}

impl fmt::Display for AddrV2Entry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?}:{}", self.addr.network, self.port)
  }
}
