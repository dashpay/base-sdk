//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network address types and classification.

use dash_types::codec::NumCodec;
use dash_types::impl_num;

use core::fmt;

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
  /// Expected byte length for a known network type, or `None`
  /// for unknown.
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
