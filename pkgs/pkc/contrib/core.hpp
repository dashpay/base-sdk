//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// Helpers for the writers that link the release's own BLS wrapper and
// hashing sources.

#ifndef PKC_CONTRIB_CORE_HPP
#define PKC_CONTRIB_CORE_HPP

#include "common.hpp"

#include <bls/bls.h>

namespace corpus {

// Sets which layout the release's wrapper writes, as its global flag does.
inline void UseLegacy(bool legacy) { bls::bls_legacy_scheme.store(legacy); }

// Reads a wrapper object from bytes, through the setter the release has.
template <typename T> T FromBytes(const Bytes& bytes, bool legacy)
{
  T obj;
  if constexpr (requires { obj.SetBytes(Span<const uint8_t>(bytes), legacy); }) {
    obj.SetBytes(Span<const uint8_t>(bytes), legacy);
  } else {
    obj.SetByteVector(Span<const uint8_t>(bytes), legacy);
  }
  if (!obj.IsValid()) throw std::invalid_argument("bytes the release does not read");
  return obj;
}

template <typename T> std::string WrapperHex(const T& obj, bool legacy) { return Hex(obj.ToByteVector(legacy)); }

} // namespace corpus

#endif // PKC_CONTRIB_CORE_HPP
