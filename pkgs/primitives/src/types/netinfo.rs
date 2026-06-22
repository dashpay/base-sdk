//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network information types and trait.

use super::netaddr::{is_bad_port, NetAddr};
use super::{NetAddrError, ServiceV1, ServiceV2};
use crate::prelude::*;

use dash_types::codec::{self, BaseCodec, Checkable, DecodeError, NumCodec};
use dash_types::{impl_num, impl_type};

use core::fmt;

/// Maximum entries per purpose.
#[expect(unused, reason = "consensus constant")]
const MAX_ENTRIES: usize = 4;
/// Maximum label length per RFC 1035.
const DOMAIN_LABEL_MAX: usize = 63;
/// Maximum FQDN length.
const DOMAIN_MAX: usize = 253;
/// Minimum FQDN length.
const DOMAIN_MIN: usize = 3;

/// Reserved and privacy TLDs that must be rejected.
const TLDS_BAD: &[&str] = &[
  // ICANN resolution 2018.02.04.12
  ".mail",
  // Infrastructure TLD
  ".arpa",
  // RFC 6761
  ".example",
  ".invalid",
  ".localhost",
  ".test",
  // RFC 6762
  ".local",
  // RFC 6762, appendix G
  ".corp",
  ".home",
  ".internal",
  ".intranet",
  ".lan",
  ".private",
];
/// Privacy-network TLDs that must be rejected.
const TLDS_PRIVACY: &[&str] = &[".i2p", ".onion"];

/// Purpose tag for an extended network info entry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NIPurpose {
  /// Core P2P port.
  CoreP2p,
  /// Platform P2P port.
  PlatformP2p,
  /// Platform HTTPS port.
  PlatformHttps,
  /// Unrecognized purpose code.
  Unknown(u8),
}

impl NumCodec<u8> for NIPurpose {
  fn from_base(val: u8) -> Self {
    match val {
      0 => Self::CoreP2p,
      1 => Self::PlatformP2p,
      2 => Self::PlatformHttps,
      other => Self::Unknown(other),
    }
  }

  fn to_base(&self) -> u8 {
    match self {
      Self::CoreP2p => 0,
      Self::PlatformP2p => 1,
      Self::PlatformHttps => 2,
      Self::Unknown(v) => *v,
    }
  }
}

impl_num!(NIPurpose, u8);

impl fmt::Display for NIPurpose {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::CoreP2p => write!(f, "core_p2p"),
      Self::PlatformP2p => write!(f, "platform_p2p"),
      Self::PlatformHttps => write!(f, "platform_https"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

/// Type tag for an extended network info entry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NIEntryCode {
  /// BIP155 address + port.
  Service,
  /// Domain name + port.
  Domain,
  /// Unrecognized entry type code.
  Unknown(u8),
}

impl NumCodec<u8> for NIEntryCode {
  fn from_base(val: u8) -> Self {
    match val {
      0x01 => Self::Service,
      0x02 => Self::Domain,
      other => Self::Unknown(other),
    }
  }

  fn to_base(&self) -> u8 {
    match self {
      Self::Service => 0x01,
      Self::Domain => 0x02,
      Self::Unknown(v) => *v,
    }
  }
}

impl_num!(NIEntryCode, u8);

impl fmt::Display for NIEntryCode {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Service => write!(f, "service"),
      Self::Domain => write!(f, "domain"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

/// Network info validation error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NIError {
  /// Address failed validation.
  BadAddr {
    /// The underlying address error.
    error: NetAddrError,
  },
  /// Port is zero or invalid for context.
  BadPort {
    /// The invalid port value.
    port: u16,
  },
  /// Structural integrity violation.
  Malformed,
}

impl fmt::Display for NIError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::BadAddr { error } => write!(f, "invalid address: {error}"),
      Self::BadPort { port } => write!(f, "invalid port {port}"),
      Self::Malformed => f.write_str("malformed structure"),
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for NIError {}

/// A single network info entry within a purpose group.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum NIEntry {
  /// BIP155 address + port.
  Service(ServiceV2),
  /// Domain name + port.
  Domain {
    /// The domain name as raw bytes.
    #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::utf8"))]
    name: Vec<u8>,
    /// Network port (big-endian on wire).
    port: u16,
  },
}

impl BaseCodec for NIEntry {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    match NIEntryCode::from_base(u8::decode(data)?) {
      NIEntryCode::Service => Ok(Self::Service(ServiceV2::decode(data)?)),
      NIEntryCode::Domain => {
        let name_len = codec::read_compact_size(data, data.len())?;
        let name = codec::read_bytes(data, name_len)?.to_vec();
        let port = codec::read_u16_be(data)?;
        Ok(Self::Domain { name, port })
      }
      NIEntryCode::Unknown(t) => Err(DecodeError::InvalidValue {
        expected: NIEntryCode::Service.to_base() as u64,
        actual: u64::from(t),
      }),
    }
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    match self {
      Self::Service(svc) => {
        NIEntryCode::Service.to_base().encode(buf);
        svc.encode(buf);
      }
      Self::Domain { name, port } => {
        NIEntryCode::Domain.to_base().encode(buf);
        name.encode(buf);
        buf.extend_from_slice(&port.to_be_bytes());
      }
    }
  }
}

/// Validates a domain name per RFC 1035 consensus rules.
fn check_domain(name: &[u8]) -> Option<NIError> {
  let s = match core::str::from_utf8(name) {
    Ok(s) => s,
    Err(_) => return Some(NIError::Malformed),
  };
  if s.len() < DOMAIN_MIN || s.len() > DOMAIN_MAX {
    return Some(NIError::Malformed);
  }
  if s.bytes().any(|b| b.is_ascii_uppercase()) {
    return Some(NIError::Malformed);
  }
  if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
    return Some(NIError::Malformed);
  }
  if s.as_bytes()[0] == b'.' || s.as_bytes()[s.len() - 1] == b'.' {
    return Some(NIError::Malformed);
  }
  let mut label_count = 0usize;
  for label in s.split('.') {
    if label.is_empty() || label.len() > DOMAIN_LABEL_MAX {
      return Some(NIError::Malformed);
    }
    if label.as_bytes()[0] == b'-' || label.as_bytes()[label.len() - 1] == b'-' {
      return Some(NIError::Malformed);
    }
    label_count += 1;
  }
  if label_count < 2 {
    return Some(NIError::Malformed);
  }
  // Reject reserved and privacy TLDs.
  if TLDS_BAD.iter().chain(TLDS_PRIVACY.iter()).any(|tld| s.ends_with(tld)) {
    return Some(NIError::Malformed);
  }
  // TLD must be purely alphabetic (ICANN guideline).
  let last_label = s.rsplit('.').next().unwrap_or("");
  if !last_label.bytes().all(|b| b.is_ascii_lowercase()) {
    return Some(NIError::Malformed);
  }
  None
}

impl Checkable for NIEntry {
  type Error = NIError;

  fn check(&self) -> Option<Self::Error> {
    match self {
      Self::Service(svc) => {
        if let Some(error) = svc.check() {
          return Some(NIError::BadAddr { error });
        }
        if !svc.addr.is_i2p() && is_bad_port(svc.port) {
          return Some(NIError::BadPort { port: svc.port });
        }
        None
      }
      Self::Domain { name, port } => {
        if *port == 0 || (is_bad_port(*port) && *port != 443) {
          return Some(NIError::BadPort { port: *port });
        }
        check_domain(name)
      }
    }
  }
}

impl fmt::Display for NIEntry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Service(svc) => write!(f, "{svc}"),
      Self::Domain { name, port } => {
        let s = core::str::from_utf8(name).unwrap_or("<invalid utf-8>");
        write!(f, "{s}:{port}")
      }
    }
  }
}

/// Interface for network information types.
pub trait NITrait: fmt::Display {
  /// Returns entries, optionally filtered by purpose.
  fn entries(&self, purpose: Option<NIPurpose>) -> impl Iterator<Item = NIEntry> + '_;

  /// Returns the primary service if available.
  fn primary(&self) -> Option<ServiceV2>;

  /// Returns `true` when this value carries no addresses.
  fn is_empty(&self) -> bool;

  /// Returns `true` if entries exist for the given purpose.
  fn has_entries(&self, purpose: NIPurpose) -> bool;

  /// Returns `true` when this type can carry platform addresses.
  fn stores_platform(&self) -> bool;
}

/// Extended network info for v3+ ProRegTx / ProUpServTx.
///
/// Contains a versioned list of purpose-grouped network entries (core P2P,
/// platform P2P, platform HTTPS).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct NetInfoV2 {
  /// Format version.
  pub version: u8,
  /// Purpose-grouped entries.
  pub entries: Vec<(NIPurpose, Vec<NIEntry>)>,
}

impl_type!(NetInfoV2);

impl BaseCodec for NetInfoV2 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u8::decode(data)?;
    let purpose_count = codec::read_compact_size(data, data.len())?;
    let mut entries = Vec::with_capacity(purpose_count);
    for _ in 0..purpose_count {
      let purpose = NIPurpose::from_base(u8::decode(data)?);
      let entry_count = codec::read_compact_size(data, data.len())?;
      let mut group = Vec::with_capacity(entry_count);
      for _ in 0..entry_count {
        group.push(NIEntry::decode(data)?);
      }
      entries.push((purpose, group));
    }
    Ok(Self { version, entries })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    codec::write_compact_size(self.entries.len(), buf);
    for (purpose, group) in &self.entries {
      purpose.to_base().encode(buf);
      codec::write_compact_size(group.len(), buf);
      for entry in group {
        entry.encode(buf);
      }
    }
  }
}

impl fmt::Display for NetInfoV2 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if self.entries.is_empty() {
      return f.write_str("NetInfoV2()");
    }
    f.write_str("NetInfoV2(")?;
    for (i, (purpose, group)) in self.entries.iter().enumerate() {
      if i > 0 {
        f.write_str(", ")?;
      }
      write!(f, "{purpose}=[")?;
      for (j, entry) in group.iter().enumerate() {
        if j > 0 {
          f.write_str(", ")?;
        }
        write!(f, "{entry}")?;
      }
      f.write_str("]")?;
    }
    f.write_str(")")
  }
}

impl NITrait for NetInfoV2 {
  fn entries(&self, purpose: Option<NIPurpose>) -> impl Iterator<Item = NIEntry> + '_ {
    self
      .entries
      .iter()
      .filter(move |(pp, _)| purpose.is_none() || purpose == Some(*pp))
      .flat_map(|(_, group)| group.iter().cloned())
  }

  fn primary(&self) -> Option<ServiceV2> {
    self
      .entries
      .iter()
      .find(|(p, e)| *p == NIPurpose::CoreP2p && !e.is_empty())
      .and_then(|(_, entries)| {
        entries.iter().find_map(|e| match e {
          NIEntry::Service(svc) => Some(svc.clone()),
          _ => None,
        })
      })
  }

  fn is_empty(&self) -> bool {
    self.entries.iter().all(|(_, group)| group.is_empty())
  }

  fn has_entries(&self, purpose: NIPurpose) -> bool {
    self.entries.iter().any(|(p, e)| *p == purpose && !e.is_empty())
  }

  fn stores_platform(&self) -> bool {
    true
  }
}

/// Legacy network information wrapper.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct NetInfoV1(pub ServiceV1);

impl_type!(NetInfoV1);

impl BaseCodec for NetInfoV1 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self(ServiceV1::decode(data)?))
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.0.encode(buf);
  }
}

impl Checkable for NetInfoV1 {
  type Error = NIError;

  fn check(&self) -> Option<Self::Error> {
    if let Some(error) = self.0.check() {
      return Some(NIError::BadAddr { error });
    }
    None
  }
}

impl fmt::Display for NetInfoV1 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if self.0.addr.is_null() && self.0.port == 0 {
      return f.write_str("NetInfoV1()");
    }
    write!(f, "NetInfoV1({})", self.0)
  }
}

impl NITrait for NetInfoV1 {
  fn entries(&self, purpose: Option<NIPurpose>) -> impl Iterator<Item = NIEntry> + '_ {
    let entry = if self.is_empty() {
      None
    } else {
      match purpose {
        None | Some(NIPurpose::CoreP2p) => Some(NIEntry::Service(ServiceV2::from(&self.0))),
        Some(_) => None,
      }
    };
    entry.into_iter()
  }

  fn primary(&self) -> Option<ServiceV2> {
    if self.is_empty() {
      return None;
    }
    Some(ServiceV2::from(&self.0))
  }

  fn is_empty(&self) -> bool {
    self.0.addr.is_null() && self.0.port == 0
  }

  fn has_entries(&self, purpose: NIPurpose) -> bool {
    purpose == NIPurpose::CoreP2p && !self.is_empty()
  }

  fn stores_platform(&self) -> bool {
    false
  }
}

/// Masternode network info: legacy ServiceV1 or structured extended format.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum NetInfo {
  /// ADDRv1 service (18 bytes).
  Legacy(NetInfoV1),
  /// Extended format (v3+) with purpose-grouped entries.
  Extended(NetInfoV2),
}

impl fmt::Display for NetInfo {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Legacy(v1) => v1.fmt(f),
      Self::Extended(v2) => v2.fmt(f),
    }
  }
}

impl NITrait for NetInfo {
  fn entries(&self, purpose: Option<NIPurpose>) -> impl Iterator<Item = NIEntry> + '_ {
    let (a, b) = match self {
      Self::Legacy(v1) => (Some(v1.entries(purpose)), None),
      Self::Extended(v2) => (None, Some(v2.entries(purpose))),
    };
    a.into_iter().flatten().chain(b.into_iter().flatten())
  }

  fn primary(&self) -> Option<ServiceV2> {
    match self {
      Self::Legacy(v1) => v1.primary(),
      Self::Extended(v2) => v2.primary(),
    }
  }

  fn is_empty(&self) -> bool {
    match self {
      Self::Legacy(v1) => v1.is_empty(),
      Self::Extended(v2) => v2.is_empty(),
    }
  }

  fn has_entries(&self, purpose: NIPurpose) -> bool {
    match self {
      Self::Legacy(v1) => v1.has_entries(purpose),
      Self::Extended(v2) => v2.has_entries(purpose),
    }
  }

  fn stores_platform(&self) -> bool {
    match self {
      Self::Legacy(v1) => v1.stores_platform(),
      Self::Extended(v2) => v2.stores_platform(),
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::types::AddrV2;

  use dash_types::codec::{BaseCodec, Checkable};
  use hex_literal::hex;
  use rstest::rstest;

  #[rstest]
  #[case::ipv4(
    &hex!(
      "01"       // entry_type=Service
      "01"       // network=ipv4
      "04"       // addr_len=4
      "01020304" // addr 1.2.3.4
      "270f"     // port=9999
    ),
    NIEntry::Service(ServiceV2 { addr: AddrV2::Ipv4([1, 2, 3, 4]), port: 9999 }),
  )]
  #[case::ipv6(
    &hex!(
      "01"                               // entry_type=Service
      "02"                               // network=ipv6
      "10"                               // addr_len=16
      "00000000000000000000000000000001" // addr ::1
      "270f"                             // port=9999
    ),
    NIEntry::Service(ServiceV2 { addr: AddrV2::Ipv6([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), port: 9999 }),
  )]
  #[case::domain(
    &hex!(
      "02"                     // entry_type=Domain
      "0b"                     // name_len=11
      "6578616d706c652e636f6d" // "example.com"
      "01bb"                   // port=443
    ),
    NIEntry::Domain { name: b"example.com".to_vec(), port: 443 },
  )]
  fn nientry_roundtrip(#[case] wire: &[u8], #[case] expected: NIEntry) {
    let decoded = NIEntry::decode(&mut &wire[..]).unwrap();
    assert_eq!(decoded, expected);
    let mut buf = Vec::new();
    decoded.encode(&mut buf);
    assert_eq!(buf, wire);
  }

  #[rstest]
  fn nientry_unknown_type_fails() {
    let wire = hex!("ff");
    assert!(NIEntry::decode(&mut &wire[..]).is_err());
  }

  #[rstest]
  #[case::ipv4_valid(AddrV2::Ipv4([1, 2, 3, 4]), 9999, None)]
  #[case::ipv4_port_zero(
    AddrV2::Ipv4([1, 2, 3, 4]), 0,
    Some(NIError::BadAddr { error: NetAddrError::BadPort { port: 0 } }),
  )]
  #[case::ipv4_port_privileged(AddrV2::Ipv4([1, 2, 3, 4]), 22, Some(NIError::BadPort { port: 22 }))]
  #[case::ipv4_port_named_bad(AddrV2::Ipv4([1, 2, 3, 4]), 8333, Some(NIError::BadPort { port: 8333 }))]
  #[case::i2p_port_zero(AddrV2::I2p([1; 32]), 0, None)]
  #[case::i2p_port_nonzero(
    AddrV2::I2p([1; 32]), 9998,
    Some(NIError::BadAddr { error: NetAddrError::BadPort { port: 9998 } }),
  )]
  #[case::tor_port_zero(
    AddrV2::TorV3([1; 32]), 0,
    Some(NIError::BadAddr { error: NetAddrError::BadPort { port: 0 } }),
  )]
  #[case::tor_port_valid(AddrV2::TorV3([1; 32]), 9998, None)]
  #[case::cjdns_valid(AddrV2::Cjdns(hex!("fc000000000000000000000000000001")), 9998, None)]
  fn check_entry_service(#[case] addr: AddrV2, #[case] port: u16, #[case] expected: Option<NIError>) {
    let entry = NIEntry::Service(ServiceV2 { addr, port });
    assert_eq!(entry.check(), expected);
  }

  #[rstest]
  // Port rules
  #[case::valid(b"example.com", 443, None)]
  #[case::bad_port_zero(b"example.com", 0, Some(NIError::BadPort { port: 0 }))]
  #[case::bad_port_privileged(b"example.com", 80, Some(NIError::BadPort { port: 80 }))]
  #[case::port_443_exception(b"example.com", 443, None)]
  #[case::port_above_threshold(b"example.com", 9999, None)]
  // RFC 1035 syntax
  #[case::small_label(b"r.server-1.ab.cd", 443, None)]
  #[case::numeric_label_rfc1123(b"9998.9example7.ab", 443, None)]
  #[case::uppercase(b"Example.com", 443, Some(NIError::Malformed))]
  #[case::too_short(b"ab", 443, Some(NIError::Malformed))]
  #[case::dotless(b"localhost", 443, Some(NIError::Malformed))]
  #[case::leading_dot(b".abc.com", 443, Some(NIError::Malformed))]
  #[case::trailing_dot(b"abc.com.", 443, Some(NIError::Malformed))]
  #[case::empty_label(b"a..b.com", 443, Some(NIError::Malformed))]
  #[case::leading_hyphen(b"-example.com", 443, Some(NIError::Malformed))]
  #[case::trailing_hyphen(b"a-.bc.de", 443, Some(NIError::Malformed))]
  #[case::bad_char_apostrophe(b"it's.example.com", 443, Some(NIError::Malformed))]
  #[case::bad_char_space(b"some host.example.com", 443, Some(NIError::Malformed))]
  // TLD rules
  #[case::tld_local(b"host.local", 443, Some(NIError::Malformed))]
  #[case::tld_onion(b"hidden.onion", 443, Some(NIError::Malformed))]
  #[case::tld_test(b"host.test", 443, Some(NIError::Malformed))]
  #[case::tld_i2p(b"host.i2p", 443, Some(NIError::Malformed))]
  #[case::tld_arpa(b"host.arpa", 443, Some(NIError::Malformed))]
  #[case::tld_numeric(b"example.123", 443, Some(NIError::Malformed))]
  fn check_entry_domain(#[case] name: &[u8], #[case] port: u16, #[case] expected: Option<NIError>) {
    let entry = NIEntry::Domain {
      name: name.to_vec(),
      port,
    };
    assert_eq!(entry.check(), expected);
  }

  #[rstest]
  fn check_domain_length_limits() {
    // 63-char label is valid
    let label63 = "a".repeat(63);
    let valid_long_label = format!("{label63}.com");
    assert_eq!(check_domain(valid_long_label.as_bytes()), None,);
    // 64-char label exceeds per-label maximum
    let label64 = "a".repeat(64);
    let bad_label = format!("{label64}.com");
    assert_eq!(check_domain(bad_label.as_bytes()), Some(NIError::Malformed),);
    // 253-char FQDN is at the maximum limit
    let fqdn253 = format!(
      "{}.{}.{}.{}.ab",
      "a".repeat(63),
      "b".repeat(63),
      "c".repeat(63),
      "d".repeat(58),
    );
    assert_eq!(fqdn253.len(), 253);
    assert_eq!(check_domain(fqdn253.as_bytes()), None);
    // 254-char FQDN exceeds maximum
    let fqdn254 = format!(
      "{}.{}.{}.{}.abc",
      "a".repeat(63),
      "b".repeat(63),
      "c".repeat(63),
      "d".repeat(58),
    );
    assert_eq!(fqdn254.len(), 254);
    assert_eq!(check_domain(fqdn254.as_bytes()), Some(NIError::Malformed),);
  }
}
