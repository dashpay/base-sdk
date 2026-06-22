//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy ADDRv1 address and service types.

use super::addrv2::{AddrV2, ServiceV2};
use super::netaddr::{NetAddr, NetAddrError, NetworkType};
use crate::prelude::*;

use dash_types::codec::{self, BaseCodec, DecodeError};
use dash_types::{impl_bytes, impl_type, type_cvrt};

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

/// First 12 bytes of an IPv4-mapped IPv6 address.
const IPV4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

/// ADDRv1 IPv4-mapped IPv6 address (16 bytes).
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct AddrV1(pub [u8; 16]);

impl_bytes!(16, AddrV1);

impl AddrV1 {
  /// Returns the inner byte array.
  pub const fn to_bytes(self) -> [u8; 16] {
    self.0
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; 16] {
    &self.0
  }

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.0.iter().all(|&b| b == 0)
  }

  /// Returns `true` if the address is IPv4-mapped.
  pub fn is_ipv4(&self) -> bool {
    self.0[..12] == IPV4_MAPPED_PREFIX
  }
}

impl From<AddrV1> for [u8; 16] {
  fn from(val: AddrV1) -> Self {
    val.0
  }
}

impl AsRef<[u8]> for AddrV1 {
  fn as_ref(&self) -> &[u8] {
    &self.0
  }
}

impl AsRef<[u8; 16]> for AddrV1 {
  fn as_ref(&self) -> &[u8; 16] {
    &self.0
  }
}

impl fmt::Debug for AddrV1 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "AddrV1(")?;
    for byte in &self.0 {
      write!(f, "{byte:02x}")?;
    }
    write!(f, ")")
  }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for AddrV1 {
  fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
    use dash_types::__private::hex_conservative::DisplayHex;
    serializer.serialize_str(&self.0.to_lower_hex_string())
  }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for AddrV1 {
  fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    let s = <alloc::string::String as ::serde::Deserialize>::deserialize(deserializer)?;
    <[u8; 16] as dash_types::__private::hex_conservative::FromHex>::from_hex(&s)
      .map(Self)
      .map_err(::serde::de::Error::custom)
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

impl fmt::Display for AddrV1 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if self.is_ipv4() {
      let ip = Ipv4Addr::new(self.0[12], self.0[13], self.0[14], self.0[15]);
      write!(f, "{ip}")
    } else {
      let ip = Ipv6Addr::from(self.0);
      write!(f, "[{ip}]")
    }
  }
}

type_cvrt!(TryFrom<AddrV2> for AddrV1, NetAddrError, |addr| {
  match addr {
    AddrV2::Ipv4(b) => {
      let mut arr = [0u8; 16];
      arr[..12].copy_from_slice(&IPV4_MAPPED_PREFIX);
      arr[12..].copy_from_slice(b);
      Ok(Self(arr))
    }
    AddrV2::Ipv6(b) => Ok(Self(*b)),
    other => Err(NetAddrError::AddrTooNew {
      network: other.network(),
    }),
  }
});

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

impl fmt::Display for ServiceV1 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.addr, self.port)
  }
}

type_cvrt!(TryFrom<ServiceV2> for ServiceV1, NetAddrError, |v2| {
  Ok(Self {
    addr: AddrV1::try_from(&v2.addr)?,
    port: v2.port,
  })
});

/// Splits a service string into `(addr, port)`.
///
/// Handles both bracketed (`[addr]:port`) and plain (`addr:port`) forms. The
/// unbracketed path uses `rfind(':')`, so callers must never pass bare IPv6
/// addresses without brackets.
///
/// # Errors
///
/// Returns `BadEncode` when the input cannot be split into a
/// valid address and port pair.
pub(super) fn split_service_str(s: &str) -> Result<(&str, u16), NetAddrError> {
  if s.starts_with('[') {
    let close = s.rfind(']').ok_or(NetAddrError::BadEncode { pos: 0 })?;
    let addr_str = &s[..=close];
    let rest = &s[close + 1..];
    let port_str = rest.strip_prefix(':').ok_or(NetAddrError::BadEncode { pos: 0 })?;
    let port: u16 = port_str.parse().map_err(|_| NetAddrError::BadEncode { pos: 0 })?;
    return Ok((addr_str, port));
  }
  let colon = s.rfind(':').ok_or(NetAddrError::BadEncode { pos: 0 })?;
  let addr_str = &s[..colon];
  let port_str = &s[colon + 1..];
  let port: u16 = port_str.parse().map_err(|_| NetAddrError::BadEncode { pos: 0 })?;
  Ok((addr_str, port))
}
