//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy ADDRv1 address and service types.

use super::netaddr::{NetAddr, NetworkType};
use crate::prelude::*;

use dash_types::codec::{self, BaseCodec, DecodeError};
use dash_types::impl_type;

/// IPv4-mapped IPv6 prefix (::ffff:0:0/96).
const IPV4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

dash_types::make_bytes! {
  /// ADDRv1 IPv4-mapped IPv6 address (16 bytes).
  AddrV1, 16
}

impl AddrV1 {
  /// Returns `true` when this is an IPv4-mapped IPv6 address.
  pub fn is_ipv4(&self) -> bool {
    self.0[..12] == IPV4_MAPPED_PREFIX
  }
}

impl NetAddr for AddrV1 {
  fn bytes(&self) -> &[u8] {
    if self.is_ipv4() {
      &self.0[12..]
    } else {
      &self.0
    }
  }

  fn network(&self) -> NetworkType {
    if self.is_ipv4() {
      NetworkType::Ipv4
    } else {
      NetworkType::Ipv6
    }
  }

  fn is_ipv4(&self) -> bool {
    self.is_ipv4()
  }

  fn is_ipv6(&self) -> bool {
    !self.is_ipv4()
  }

  fn is_null(&self) -> bool {
    self.is_null()
  }
}

/// Legacy network address (ADDRv1 format, 18 bytes).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ServiceV1 {
  /// 16-byte address (IPv4-mapped IPv6 or native IPv6).
  pub addr: AddrV1,
  /// Network port (big-endian on the wire).
  pub port: u16,
}

impl_type!(ServiceV1);

impl BaseCodec for ServiceV1 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      addr: AddrV1::decode(data)?,
      port: codec::read_u16_be(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.addr.encode(buf);
    buf.extend_from_slice(&self.port.to_be_bytes());
  }
}
