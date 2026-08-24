//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared macro definitions.

use core::fmt;

/// Emits its body only when *this* crate has the `serde` feature.
///
/// `#[cfg(feature = "serde")]` written inside an exported macro resolves
/// against the invoking crate, which doesn't need have a `serde` feature at
/// all. This marker is compiled here, so it tracks `dash-types` instead.
///
/// The two arms must stay plain `#[cfg]` items. Wrapping them in `cfg_if!`
/// makes the definition macro-expanded, and a macro-expanded `#[macro_export]`
/// macro cannot be reached by `$crate::` from its own crate (rust#52234).
#[cfg(feature = "serde")]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_serde {
  ($($item:tt)*) => { $($item)* };
}

#[cfg(not(feature = "serde"))]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_serde {
  ($($item:tt)*) => {};
}

/// Writes [`type_name`](core::any::type_name) output to `f` with its module
/// qualifiers dropped.
pub fn qtypestr(f: &mut fmt::Formatter<'_>, path: &str) -> fmt::Result {
  let bytes = path.as_bytes();
  let (mut seg, mut i) = (0, 0);
  while i < bytes.len() {
    match bytes[i] {
      // A qualifier: discard everything emitted since the last segment.
      b':' if bytes.get(i + 1) == Some(&b':') => {
        i += 2;
        seg = i;
      }
      delim @ (b'<' | b'>' | b',') => {
        f.write_str(&path[seg..i])?;
        f.write_str(match delim {
          b'<' => "<",
          b'>' => ">",
          _ => ", ",
        })?;
        i += 1;
        while bytes.get(i) == Some(&b' ') {
          i += 1;
        }
        seg = i;
      }
      _ => i += 1,
    }
  }
  f.write_str(&path[seg..])
}

/// Maps enum variants to integer constants and display strings.
///
/// Generates the enum definition, integer mapping (via `NumCodec` or inherent
/// `const fn`), and `impl Display` from a single table.
///
/// # Syntax
///
/// Each variant uses one of two forms:
///
/// - `Variant = VALUE` -- display string is `stringify!(Variant)`
/// - `Variant = VALUE => "label"` -- display string is `"label"`
///
/// All variants within one invocation must use the same form.
///
/// ## Infallible
///
/// Generates the enum with a catch-all variant, `impl NumCodec<T>`, `new`,
/// `is_canonical`, `variants`, and `impl Display`. The catch-all displays as
/// `unknown({v})`; build values with `new` so it never shadows a named
/// variant.
///
/// ```ignore
/// enum_map! {
///   #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
///   pub enum NIPurpose, u8, Unknown {
///     /// Core P2P port.
///     CoreP2p = 0 => "core_p2p",
///     /// Platform P2P port.
///     PlatformP2p = 1 => "platform_p2p",
///   }
/// }
/// ```
///
/// ## Fallible
///
/// Generates the enum (closed), inherent `const fn from_base` / `to_base`
/// methods, and `impl Display`.
///
/// ```ignore
/// enum_map! {
///   #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
///   pub enum Sec1Byte, u8 {
///     /// Compressed, even Y coordinate.
///     CompEven = 0x02,
///     /// Compressed, odd Y coordinate.
///     CompOdd  = 0x03,
///   }
/// }
/// ```
#[macro_export]
macro_rules! enum_map {
  // Infallible + manual display strings.
  (
    $(#[$enum_attr:meta])*
    $vis:vis enum $enum:ident, $base:ty, $catch_all:ident {
      $(
        $(#[$var_attr:meta])*
        $variant:ident = $value:literal => $display:expr
      ),+ $(,)?
    }
  ) => {
    $crate::enum_map!(@enum $(#[$enum_attr])* $vis $enum, $base, $catch_all {
      $($(#[$var_attr])* $variant,)+
    });
    $crate::enum_map!(@infallible $enum, $base, $catch_all { $($variant = $value),+ });
    $crate::enum_map!(@display_catch_all $enum, $catch_all { $($variant = $display),+ });
  };

  // Infallible + auto-stringize.
  (
    $(#[$enum_attr:meta])*
    $vis:vis enum $enum:ident, $base:ty, $catch_all:ident {
      $(
        $(#[$var_attr:meta])*
        $variant:ident = $value:literal
      ),+ $(,)?
    }
  ) => {
    $crate::enum_map!(@enum $(#[$enum_attr])* $vis $enum, $base, $catch_all {
      $($(#[$var_attr])* $variant,)+
    });
    $crate::enum_map!(@infallible $enum, $base, $catch_all { $($variant = $value),+ });
    $crate::enum_map!(@display_catch_all $enum, $catch_all { $($variant = stringify!($variant)),+ });
  };

  // Fallible + manual display strings.
  (
    $(#[$enum_attr:meta])*
    $vis:vis enum $enum:ident, $base:ty {
      $(
        $(#[$var_attr:meta])*
        $variant:ident = $value:literal => $display:expr
      ),+ $(,)?
    }
  ) => {
    $crate::enum_map!(@enum_closed $(#[$enum_attr])* $vis $enum {
      $($(#[$var_attr])* $variant,)+
    });
    $crate::enum_map!(@fallible $enum, $base { $($variant = $value),+ });
    $crate::enum_map!(@display $enum { $($variant = $display),+ });
  };

  // Fallible + auto-stringize.
  (
    $(#[$enum_attr:meta])*
    $vis:vis enum $enum:ident, $base:ty {
      $(
        $(#[$var_attr:meta])*
        $variant:ident = $value:literal
      ),+ $(,)?
    }
  ) => {
    $crate::enum_map!(@enum_closed $(#[$enum_attr])* $vis $enum {
      $($(#[$var_attr])* $variant,)+
    });
    $crate::enum_map!(@fallible $enum, $base { $($variant = $value),+ });
    $crate::enum_map!(@display $enum { $($variant = stringify!($variant)),+ });
  };

  (@enum $(#[$enum_attr:meta])* $vis:vis $enum:ident, $base:ty, $catch_all:ident {
    $($(#[$var_attr:meta])* $variant:ident,)+
  }) => {
    $(#[$enum_attr])*
    $vis enum $enum {
      $(
        $(#[$var_attr])*
        $variant,
      )+
      /// Unrecognized value, construct through [`new`](Self::new) rather than directly
      $catch_all($base),
    }
  };

  (@enum_closed $(#[$enum_attr:meta])* $vis:vis $enum:ident {
    $($(#[$var_attr:meta])* $variant:ident,)+
  }) => {
    $(#[$enum_attr])*
    $vis enum $enum {
      $(
        $(#[$var_attr])*
        $variant,
      )+
    }
  };

  (@infallible $enum:ident, $base:ty, $catch_all:ident {
    $($variant:ident = $value:literal),+
  }) => {
    impl $crate::codec::NumCodec<$base> for $enum {
      fn from_base(val: $base) -> Self {
        match val {
          $($value => Self::$variant,)+
          other => Self::$catch_all(other),
        }
      }

      fn to_base(&self) -> $base {
        match self {
          $(Self::$variant => $value,)+
          Self::$catch_all(v) => *v,
        }
      }
    }

    impl $enum {
      /// Canonical constructor.
      ///
      /// Routes through `from_base`, so a value a named variant covers yields
      /// that variant instead of a catch-all holding the same number. Decoded
      /// values already take this path.
      pub fn new(val: $base) -> Self {
        <Self as $crate::codec::NumCodec<$base>>::from_base(val)
      }

      /// Whether this value is in canonical form.
      ///
      /// False only for a catch-all holding a value that a named variant
      /// already covers.
      pub fn is_canonical(&self) -> bool {
        !matches!(self, Self::$catch_all(v) if matches!(
          <Self as $crate::codec::NumCodec<$base>>::from_base(*v),
          $(Self::$variant)|+
        ))
      }

      /// Named variants.
      pub const fn variants() -> &'static [Self] {
        &[$(Self::$variant),+]
      }
    }
  };

  (@fallible $enum:ident, $base:ty {
    $($variant:ident = $value:literal),+
  }) => {
    impl $enum {
      /// Constructs from the base integer value.
      pub const fn from_base(v: $base) -> Option<Self> {
        match v {
          $($value => Some(Self::$variant),)+
          _ => None,
        }
      }

      /// Returns the base integer value.
      pub const fn to_base(self) -> $base {
        match self {
          $(Self::$variant => $value,)+
        }
      }

      /// All variants.
      pub const fn variants() -> &'static [Self] {
        &[$(Self::$variant),+]
      }
    }
  };

  (@display_catch_all $enum:ident, $catch_all:ident {
    $($variant:ident = $display:expr),+
  }) => {
    impl ::core::fmt::Display for $enum {
      fn fmt(
        &self, f: &mut ::core::fmt::Formatter<'_>,
      ) -> ::core::fmt::Result {
        match self {
          $(Self::$variant => f.write_str($display),)+
          Self::$catch_all(v) => write!(f, "unknown({v})"),
        }
      }
    }
  };

  (@display $enum:ident {
    $($variant:ident = $display:expr),+
  }) => {
    impl ::core::fmt::Display for $enum {
      fn fmt(
        &self, f: &mut ::core::fmt::Formatter<'_>,
      ) -> ::core::fmt::Result {
        match self {
          $(Self::$variant => f.write_str($display),)+
        }
      }
    }
  };
}

/// The standard trait set for a fixed-size byte newtype, expressed only
/// through `from_bytes` / `as_bytes`.
///
/// Emits `Clone`, `Copy`, `Default`, `Eq`, `PartialEq`, `Ord`, `PartialOrd`,
/// `Hash`, `is_null`, `AsRef<[u8]>`, `AsRef<[u8; N]>`, `From<Self> for
/// [u8; N]`, a hex `Debug`/`Display`, and the hex `serde` pair.
///
/// A trailing `rev` renders the hex in reverse storage order, the default `fwd`
/// renders storage order.
///
/// For a newtype holding secrets use [`derive_sbytes!`](crate::derive_sbytes),
/// which withholds everything that would read or copy out the plaintext.
#[macro_export]
macro_rules! derive_bytes {
  (@parse [$($g:tt)*] $ty:ty, $n:expr, $rev:expr) => {
    impl<$($g)*> ::core::clone::Clone for $ty {
      fn clone(&self) -> Self { *self }
    }

    impl<$($g)*> ::core::marker::Copy for $ty {}

    impl<$($g)*> ::core::default::Default for $ty {
      fn default() -> Self { Self::from_bytes([0u8; $n]) }
    }

    impl<$($g)*> ::core::cmp::Eq for $ty {}

    impl<$($g)*> ::core::cmp::PartialEq for $ty {
      fn eq(&self, other: &Self) -> bool { self.as_bytes() == other.as_bytes() }
    }

    impl<$($g)*> ::core::cmp::Ord for $ty {
      fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
      }
    }

    impl<$($g)*> ::core::cmp::PartialOrd for $ty {
      fn partial_cmp(&self, other: &Self) -> ::core::option::Option<::core::cmp::Ordering> {
        ::core::option::Option::Some(::core::cmp::Ord::cmp(self, other))
      }
    }

    impl<$($g)*> ::core::hash::Hash for $ty {
      fn hash<H: ::core::hash::Hasher>(&self, state: &mut H) {
        ::core::hash::Hash::hash(self.as_bytes(), state);
      }
    }

    impl<$($g)*> ::core::convert::AsRef<[u8]> for $ty {
      fn as_ref(&self) -> &[u8] { self.as_bytes() }
    }

    impl<$($g)*> ::core::convert::AsRef<[u8; $n]> for $ty {
      fn as_ref(&self) -> &[u8; $n] { self.as_bytes() }
    }

    impl<$($g)*> ::core::convert::From<$ty> for [u8; $n] {
      fn from(val: $ty) -> Self { *val.as_bytes() }
    }

    impl<$($g)*> $ty {
      /// Returns `true` when every byte is zero.
      pub fn is_null(&self) -> bool { self.as_bytes().iter().all(|&b| b == 0) }
    }

    impl<$($g)*> ::core::fmt::Debug for $ty {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        $crate::qtypestr(f, ::core::any::type_name::<Self>())?;
        f.write_str("(")?;
        ::core::fmt::Display::fmt(self, f)?;
        f.write_str(")")
      }
    }

    $crate::derive_bytes!(@hex [$($g)*] $ty, $n, $rev);
  };
  (@order [$($g:tt)*] $ty:ty, $n:expr, fwd) => {
    $crate::derive_bytes!(@parse [$($g)*] $ty, $n, false);
  };
  (@order [$($g:tt)*] $ty:ty, $n:expr, rev) => {
    $crate::derive_bytes!(@parse [$($g)*] $ty, $n, true);
  };
  (@hex [$($g:tt)*] $ty:ty, $n:expr, $rev:expr) => {
    impl<$($g)*> ::core::fmt::Display for $ty {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        let bytes = self.as_bytes();
        for i in 0..$n {
          let byte = if $rev { bytes[$n - 1 - i] } else { bytes[i] };
          ::core::write!(f, "{byte:02x}")?;
        }
        ::core::result::Result::Ok(())
      }
    }

    $crate::cfg_serde! {
      impl<$($g)*> $crate::__private::serde::Serialize for $ty {
        fn serialize<Z>(&self, serializer: Z) -> Result<Z::Ok, Z::Error>
        where
          Z: $crate::__private::serde::Serializer,
        {
          serializer.serialize_str(&::alloc::format!("{self}"))
        }
      }

      impl<'de, $($g)*> $crate::__private::serde::Deserialize<'de> for $ty {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
          D: $crate::__private::serde::Deserializer<'de>,
        {
          use $crate::__private::serde::de::Error as _;
          let s = <::alloc::string::String as $crate::__private::serde::Deserialize>::deserialize(deserializer)?;
          let mut bytes = <[u8; $n] as $crate::__private::hex_conservative::FromHex>::from_hex(&s)
            .map_err(D::Error::custom)?;
          if $rev {
            bytes.reverse();
          }
          ::core::result::Result::Ok(Self::from_bytes(bytes))
        }
      }
    }
  };
  (for[$($generic:tt)*] $ty:ty, $n:expr, $order:tt) => {
    $crate::derive_bytes!(@order [$($generic)*] $ty, $n, $order);
  };
  (for[$($generic:tt)*] $ty:ty, $n:expr) => {
    $crate::derive_bytes!(@order [$($generic)*] $ty, $n, fwd);
  };
  ($ty:ty, $n:expr, $order:tt) => {
    $crate::derive_bytes!(@order [] $ty, $n, $order);
  };
  ($ty:ty, $n:expr) => {
    $crate::derive_bytes!(@order [] $ty, $n, fwd);
  };
}

/// The secret counterpart to [`derive_bytes!`](crate::derive_bytes), for a
/// fixed-size byte newtype holding key material.
///
/// Emits `Drop`, `ZeroizeOnDrop`, `is_null`, the `AsRef` pair, and a redacting
/// `Debug`/`Display`. `Zeroize`, `Clone` and `Eq`/`PartialEq` are left to the
/// type: only it knows which fields are secret, and equality must be
/// constant-time.
///
/// Withholds `Copy`, `Default`, `Ord`/`PartialOrd`/`Hash`, `From<Self> for
/// [u8; N]` and the hex `serde` pair, each because it either escapes the wipe
/// or reads the plaintext. Do *not* implement them.
#[macro_export]
macro_rules! derive_sbytes {
  (@parse [$($g:tt)*] $ty:ty, $n:expr) => {
    impl<$($g)*> ::core::ops::Drop for $ty {
      fn drop(&mut self) {
        <Self as $crate::__private::zeroize::Zeroize>::zeroize(self);
      }
    }

    impl<$($g)*> $crate::__private::zeroize::ZeroizeOnDrop for $ty {}

    impl<$($g)*> $ty {
      /// Returns `true` when every byte is zero.
      pub fn is_null(&self) -> bool {
        use $crate::__private::subtle::ConstantTimeEq as _;
        self.as_bytes().ct_eq(&[0u8; $n]).into()
      }
    }

    impl<$($g)*> ::core::fmt::Debug for $ty {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        // `type_name` rather than `stringify!`, which cannot see the generics
        $crate::qtypestr(f, ::core::any::type_name::<Self>())?;
        f.write_str("(..)")
      }
    }

    impl<$($g)*> ::core::fmt::Display for $ty {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        ::core::fmt::Debug::fmt(self, f)
      }
    }

    impl<$($g)*> ::core::convert::AsRef<[u8]> for $ty {
      fn as_ref(&self) -> &[u8] { self.as_bytes() }
    }

    impl<$($g)*> ::core::convert::AsRef<[u8; $n]> for $ty {
      fn as_ref(&self) -> &[u8; $n] { self.as_bytes() }
    }
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::derive_sbytes!(@parse [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::derive_sbytes!(@parse [] $($args)*);
  };
}

/// Generates `From<T>` + `From<&T>` (or `TryFrom` equivalents). The closure
/// body receives `&$src`; the owned impl delegates.
#[macro_export]
macro_rules! type_cvrt {
  (@parse [$($impl_generics:tt)*] From<$src:ty> for $dst:ty, |$v:ident| $body:expr) => {
    impl<$($impl_generics)*> ::core::convert::From<&$src> for $dst {
      fn from($v: &$src) -> Self {
        $body
      }
    }
    impl<$($impl_generics)*> ::core::convert::From<$src> for $dst {
      fn from(v: $src) -> Self {
        Self::from(&v)
      }
    }
  };
  (@parse [$($impl_generics:tt)*] TryFrom<$src:ty> for $dst:ty, $err:ty, |$v:ident| $body:expr) => {
    impl<$($impl_generics)*> ::core::convert::TryFrom<&$src> for $dst {
      type Error = $err;
      fn try_from($v: &$src) -> Result<Self, Self::Error> {
        $body
      }
    }
    impl<$($impl_generics)*> ::core::convert::TryFrom<$src> for $dst {
      type Error = $err;
      fn try_from(v: $src) -> Result<Self, Self::Error> {
        Self::try_from(&v)
      }
    }
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::type_cvrt!(@parse [$($generic)*] $($args)*);
  };
  (enum $enum:ident { $($variant:ident($inner:ty)),* $(,)? }) => { $(
    impl ::core::convert::From<$inner> for $enum {
      fn from(v: $inner) -> Self {
        Self::$variant(v)
      }
    }
    impl ::core::convert::TryFrom<$enum> for $inner {
      type Error = $enum;
      fn try_from(v: $enum) -> Result<Self, $enum> {
        match v {
          $enum::$variant(inner) => Ok(inner),
          other => Err(other),
        }
      }
    }
  )* };
  ($($args:tt)*) => {
    $crate::type_cvrt!(@parse [] $($args)*);
  };
}

#[cfg(test)]
mod tests {
  use super::qtypestr;
  use crate::codec::NumCodec;
  use crate::prelude::*;

  use rstest::*;

  use core::fmt;

  enum_map! {
    /// Open enum: unrecognized codes survive a round trip.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub enum Open, u8, Unknown {
      /// First.
      One = 1 => "one",
      /// Second.
      Two = 2 => "two",
    }
  }

  enum_map! {
    /// Closed enum: only the listed codes are representable.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub enum Closed, u16 {
      /// Low.
      Lo = 0x0100,
      /// High.
      Hi = 0x0200,
    }
  }

  enum_map! {
    /// Auto-stringized display labels.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub enum Auto, u8, Other {
      /// Alpha.
      Alpha = 7,
    }
  }

  #[rstest]
  #[case::named_low(1, Open::One)]
  #[case::named_high(2, Open::Two)]
  #[case::unknown(9, Open::Unknown(9))]
  fn open_maps_both_ways(#[case] raw: u8, #[case] expected: Open) {
    assert_eq!(Open::from_base(raw), expected);
    assert_eq!(expected.to_base(), raw);
  }

  #[rstest]
  fn new_canonicalizes_a_shadowing_catch_all() {
    let shadow = Open::Unknown(1);
    assert_eq!(shadow.to_base(), Open::One.to_base());
    assert_ne!(shadow, Open::One);
    assert!(!shadow.is_canonical());

    assert_eq!(Open::new(1), Open::One);
    assert!(Open::new(1).is_canonical());
    assert!(Open::new(9).is_canonical());
  }

  #[rstest]
  fn open_display_and_variants() {
    assert_eq!(Open::One.to_string(), "one");
    assert_eq!(Open::Unknown(9).to_string(), "unknown(9)");
    assert_eq!(Open::variants(), &[Open::One, Open::Two]);
  }

  #[rstest]
  fn auto_stringize_uses_the_variant_name() {
    assert_eq!(Auto::Alpha.to_string(), "Alpha");
    assert_eq!(Auto::Other(3).to_string(), "unknown(3)");
    assert_eq!(Auto::variants(), &[Auto::Alpha]);
    assert_eq!(Auto::new(7), Auto::Alpha);
    assert!(!Auto::Other(7).is_canonical());
  }

  #[rstest]
  #[case::lo(0x0100, Some(Closed::Lo))]
  #[case::hi(0x0200, Some(Closed::Hi))]
  #[case::unmapped(0x0300, None)]
  #[case::zero(0, None)]
  fn closed_rejects_unmapped(#[case] raw: u16, #[case] expected: Option<Closed>) {
    assert_eq!(Closed::from_base(raw), expected);
  }

  #[rstest]
  fn closed_roundtrips_every_variant() {
    for v in Closed::variants() {
      assert_eq!(Closed::from_base(v.to_base()), Some(*v));
    }
  }

  #[rstest]
  fn closed_display() {
    assert_eq!(Closed::Lo.to_string(), "Lo");
  }

  struct Qtype<'a>(&'a str);

  impl fmt::Display for Qtype<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      qtypestr(f, self.0)
    }
  }

  #[rstest]
  #[case::plain("a::b::Foo", "Foo")]
  #[case::unqualified("Foo", "Foo")]
  #[case::one_arg("a::Foo<b::Bar>", "Foo<Bar>")]
  #[case::two_args("a::Foo<b::Bar, c::Baz>", "Foo<Bar, Baz>")]
  #[case::nested("a::Foo<b::Bar<c::Baz>>", "Foo<Bar<Baz>>")]
  #[case::nested_pair("a::Foo<b::Bar<c::Baz>, d::Qux>", "Foo<Bar<Baz>, Qux>")]
  fn qtypestr_drops_module_paths(#[case] path: &str, #[case] expect: &str) {
    assert_eq!(Qtype(path).to_string(), expect);
  }
}
