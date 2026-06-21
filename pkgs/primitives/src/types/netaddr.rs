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

/// Network address validation error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetAddrError {
  /// Address type not representable in target format.
  AddrTooNew {
    /// The incompatible network type.
    network: NetworkType,
  },
}

impl fmt::Display for NetAddrError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::AddrTooNew { network } => {
        write!(f, "{network} address type not supported")
      }
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for NetAddrError {}

/// Shared classification interface for network addresses.
///
/// Both legacy (`AddrV1`) and modern (`AddrV2`) address types
/// implement this trait, providing uniform RFC classification.
pub trait NetAddr {
  /// Raw address bytes (4 for IPv4, 16 for IPv6, etc.).
  fn bytes(&self) -> &[u8];

  /// BIP155 network type.
  fn network(&self) -> NetworkType;

  /// Returns `true` for IPv4 addresses.
  fn is_ipv4(&self) -> bool;

  /// Returns `true` for IPv6 addresses.
  fn is_ipv6(&self) -> bool;

  /// Returns `true` when every address byte is zero.
  fn is_null(&self) -> bool;

  /// Returns `true` for Tor v3 addresses.
  fn is_tor(&self) -> bool {
    false
  }

  /// Returns `true` for I2P addresses.
  fn is_i2p(&self) -> bool {
    false
  }

  /// Returns `true` for CJDNS addresses.
  fn is_cjdns(&self) -> bool {
    false
  }

  /// Returns `true` for privacy networks (Tor, I2P, CJDNS).
  fn is_privacy_net(&self) -> bool {
    self.is_tor() || self.is_i2p() || self.is_cjdns()
  }

  /// Returns `true` when the address fits in an ADDRv1 message.
  fn is_v1_compatible(&self) -> bool {
    self.is_ipv4() || self.is_ipv6()
  }

  /// Returns `true` for loopback and link-local addresses.
  fn is_local(&self) -> bool {
    let b = self.bytes();
    if self.is_ipv4() && b.len() == 4 {
      // 127.0.0.0/8
      if b[0] == 127 {
        return true;
      }
      // RFC 3927 link-local 169.254.0.0/16
      if b[0] == 169 && b[1] == 254 {
        return true;
      }
      return false;
    }
    if self.is_ipv6() && b.len() == 16 {
      // ::1
      if b[..15] == [0; 15] && b[15] == 1 {
        return true;
      }
      // fe80::/10 link-local
      if b[0] == 0xfe && (b[1] & 0xc0) == 0x80 {
        return true;
      }
      return false;
    }
    false
  }

  /// RFC 1918: private IPv4 (10/8, 172.16/12, 192.168/16).
  fn is_rfc1918(&self) -> bool {
    if !self.is_ipv4() {
      return false;
    }
    let b = self.bytes();
    if b.len() != 4 {
      return false;
    }
    // 10.0.0.0/8
    if b[0] == 10 {
      return true;
    }
    // 172.16.0.0/12
    if b[0] == 172 && (b[1] & 0xf0) == 16 {
      return true;
    }
    // 192.168.0.0/16
    b[0] == 192 && b[1] == 168
  }

  /// RFC 2544: benchmarking (198.18.0.0/15).
  fn is_rfc2544(&self) -> bool {
    if !self.is_ipv4() {
      return false;
    }
    let b = self.bytes();
    b.len() == 4 && b[0] == 198 && (b[1] == 18 || b[1] == 19)
  }

  /// RFC 3849: documentation IPv6 (2001:db8::/32).
  fn is_rfc3849(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8
  }

  /// RFC 3927: link-local IPv4 (169.254.0.0/16).
  fn is_rfc3927(&self) -> bool {
    if !self.is_ipv4() {
      return false;
    }
    let b = self.bytes();
    b.len() == 4 && b[0] == 169 && b[1] == 254
  }

  /// RFC 4193: unique-local IPv6 (fc00::/7).
  fn is_rfc4193(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && (b[0] & 0xfe) == 0xfc
  }

  /// RFC 4843: ORCHID IPv6 (2001:10::/28).
  fn is_rfc4843(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && (b[3] & 0xf0) == 0x10
  }

  /// RFC 6052: well-known prefix (64:ff9b::/96).
  fn is_rfc6052(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b[4..12] == [0; 8]
  }

  /// RFC 6145: IPv6 translation (::ffff:0:0:0/96).
  fn is_rfc6145(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && b[0..8] == [0; 8] && b[8] == 0xff && b[9] == 0xff && b[10] == 0x00 && b[11] == 0x00
  }

  /// RFC 6598: carrier-grade NAT (100.64.0.0/10).
  fn is_rfc6598(&self) -> bool {
    if !self.is_ipv4() {
      return false;
    }
    let b = self.bytes();
    b.len() == 4 && b[0] == 100 && (b[1] & 0xc0) == 64
  }

  /// Returns `true` when the address is globally routable.
  fn is_routable(&self) -> bool {
    if self.is_null() {
      return false;
    }
    if self.is_local() {
      return false;
    }
    if self.is_privacy_net() {
      return true;
    }
    if self.is_ipv4() {
      let b = self.bytes();
      if b.len() == 4 && (b[0] == 0 || b[0] >= 224) {
        return false;
      }
      return !self.is_rfc1918() && !self.is_rfc2544() && !self.is_rfc3927() && !self.is_rfc6598();
    }
    if self.is_ipv6() {
      let b = self.bytes();
      // ff00::/8 multicast
      if b.len() == 16 && b[0] == 0xff {
        return false;
      }
      return !self.is_rfc3849()
        && !self.is_rfc4193()
        && !self.is_rfc4843()
        && !self.is_rfc6052()
        && !self.is_rfc6145();
    }
    false
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use rstest::rstest;

  /// Minimal test adapter: 4-byte IPv4 address.
  struct Ipv4([u8; 4]);

  impl NetAddr for Ipv4 {
    fn bytes(&self) -> &[u8] {
      &self.0
    }
    fn network(&self) -> NetworkType {
      NetworkType::Ipv4
    }
    fn is_ipv4(&self) -> bool {
      true
    }
    fn is_ipv6(&self) -> bool {
      false
    }
    fn is_null(&self) -> bool {
      self.0 == [0; 4]
    }
  }

  /// Minimal test adapter: 16-byte IPv6 address.
  struct Ipv6([u8; 16]);

  impl NetAddr for Ipv6 {
    fn bytes(&self) -> &[u8] {
      &self.0
    }
    fn network(&self) -> NetworkType {
      NetworkType::Ipv6
    }
    fn is_ipv4(&self) -> bool {
      false
    }
    fn is_ipv6(&self) -> bool {
      true
    }
    fn is_null(&self) -> bool {
      self.0 == [0; 16]
    }
  }

  fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4 {
    Ipv4([a, b, c, d])
  }

  fn v6(bytes: [u8; 16]) -> Ipv6 {
    Ipv6(bytes)
  }

  #[rstest]
  #[case::rfc1918_10(v4(10, 0, 0, 1), true)]
  #[case::rfc1918_172(v4(172, 31, 255, 255), true)]
  #[case::rfc1918_192(v4(192, 168, 1, 1), true)]
  #[case::rfc1918_public(v4(8, 8, 8, 8), false)]
  fn rfc1918(#[case] addr: Ipv4, #[case] expected: bool) {
    assert_eq!(addr.is_rfc1918(), expected);
  }

  #[rstest]
  #[case::rfc2544_lo(v4(198, 18, 0, 0), true)]
  #[case::rfc2544_hi(v4(198, 19, 255, 255), true)]
  #[case::rfc2544_below(v4(198, 17, 0, 0), false)]
  fn rfc2544(#[case] addr: Ipv4, #[case] expected: bool) {
    assert_eq!(addr.is_rfc2544(), expected);
  }

  #[rstest]
  fn rfc3849() {
    let mut b = [0u8; 16];
    b[0] = 0x20;
    b[1] = 0x01;
    b[2] = 0x0d;
    b[3] = 0xb8;
    assert!(v6(b).is_rfc3849());
  }

  #[rstest]
  #[case::rfc3927_yes(v4(169, 254, 1, 1), true)]
  #[case::rfc3927_no(v4(169, 253, 1, 1), false)]
  fn rfc3927(#[case] addr: Ipv4, #[case] expected: bool) {
    assert_eq!(addr.is_rfc3927(), expected);
  }

  #[rstest]
  fn rfc4193() {
    let mut b = [0u8; 16];
    b[0] = 0xfc;
    assert!(v6(b).is_rfc4193());
    b[0] = 0xfd;
    assert!(v6(b).is_rfc4193());
    b[0] = 0xfe;
    assert!(!v6(b).is_rfc4193());
  }

  #[rstest]
  fn rfc4843() {
    let mut b = [0u8; 16];
    b[0] = 0x20;
    b[1] = 0x01;
    b[2] = 0x00;
    b[3] = 0x10;
    assert!(v6(b).is_rfc4843());
    b[3] = 0x1f;
    assert!(v6(b).is_rfc4843());
    b[3] = 0x20;
    assert!(!v6(b).is_rfc4843());
  }

  #[rstest]
  fn rfc6052() {
    let mut b = [0u8; 16];
    b[0] = 0x00;
    b[1] = 0x64;
    b[2] = 0xff;
    b[3] = 0x9b;
    assert!(v6(b).is_rfc6052());
    b[4] = 1;
    assert!(!v6(b).is_rfc6052());
  }

  #[rstest]
  fn rfc6145() {
    let mut b = [0u8; 16];
    b[8] = 0xff;
    b[9] = 0xff;
    assert!(v6(b).is_rfc6145());
    b[0] = 1;
    assert!(!v6(b).is_rfc6145());
  }

  #[rstest]
  #[case::rfc6598_lo(v4(100, 64, 0, 0), true)]
  #[case::rfc6598_hi(v4(100, 127, 255, 255), true)]
  #[case::rfc6598_below(v4(100, 63, 0, 0), false)]
  fn rfc6598(#[case] addr: Ipv4, #[case] expected: bool) {
    assert_eq!(addr.is_rfc6598(), expected);
  }

  #[rstest]
  #[case::local_v4(v4(127, 0, 0, 1), true)]
  #[case::local_link(v4(169, 254, 0, 1), true)]
  #[case::local_public(v4(8, 8, 8, 8), false)]
  fn local_v4(#[case] addr: Ipv4, #[case] expected: bool) {
    assert_eq!(addr.is_local(), expected);
  }

  #[rstest]
  fn local_v6() {
    let mut loopback = [0u8; 16];
    loopback[15] = 1;
    assert!(v6(loopback).is_local());

    let mut link_local = [0u8; 16];
    link_local[0] = 0xfe;
    link_local[1] = 0x80;
    assert!(v6(link_local).is_local());

    let mut global = [0u8; 16];
    global[0] = 0x20;
    global[1] = 0x01;
    global[15] = 1;
    assert!(!v6(global).is_local());
  }

  #[rstest]
  #[case::routable_v4(v4(8, 8, 8, 8), true)]
  #[case::not_routable_loopback(v4(127, 0, 0, 1), false)]
  #[case::not_routable_private(v4(10, 0, 0, 1), false)]
  #[case::not_routable_null(v4(0, 0, 0, 0), false)]
  #[case::not_routable_multicast(v4(224, 0, 0, 1), false)]
  #[case::not_routable_multicast_hi(v4(239, 255, 255, 255), false)]
  fn routable_v4(#[case] addr: Ipv4, #[case] expected: bool) {
    assert_eq!(addr.is_routable(), expected);
  }

  #[rstest]
  fn routable_v6() {
    let mut global = [0u8; 16];
    global[0] = 0x20;
    global[1] = 0x01;
    global[15] = 1;
    assert!(v6(global).is_routable());

    let mut doc = [0u8; 16];
    doc[0] = 0x20;
    doc[1] = 0x01;
    doc[2] = 0x0d;
    doc[3] = 0xb8;
    doc[15] = 1;
    assert!(!v6(doc).is_routable());

    let mut mcast = [0u8; 16];
    mcast[0] = 0xff;
    mcast[1] = 0x02;
    mcast[15] = 1;
    assert!(!v6(mcast).is_routable());
  }

  #[rstest]
  fn null() {
    assert!(v4(0, 0, 0, 0).is_null());
    assert!(!v4(1, 2, 3, 4).is_null());
    assert!(v6([0; 16]).is_null());
    let mut nonzero = [0u8; 16];
    nonzero[15] = 1;
    assert!(!v6(nonzero).is_null());
  }

  #[rstest]
  fn invariant_rfc1918_implies_ipv4() {
    let addr = v4(10, 0, 0, 1);
    if addr.is_rfc1918() {
      assert!(addr.is_ipv4());
    }
  }

  #[rstest]
  fn invariant_rfc3849_implies_ipv6() {
    let mut b = [0u8; 16];
    b[0] = 0x20;
    b[1] = 0x01;
    b[2] = 0x0d;
    b[3] = 0xb8;
    let addr = v6(b);
    if addr.is_rfc3849() {
      assert!(addr.is_ipv6());
    }
  }

  #[rstest]
  fn invariant_rfc4193_implies_ipv6() {
    let mut b = [0u8; 16];
    b[0] = 0xfc;
    let addr = v6(b);
    if addr.is_rfc4193() {
      assert!(addr.is_ipv6());
    }
  }

  #[rstest]
  fn invariant_local_implies_not_routable() {
    let addr = v4(127, 0, 0, 1);
    if addr.is_local() {
      assert!(!addr.is_routable());
    }
  }
}
