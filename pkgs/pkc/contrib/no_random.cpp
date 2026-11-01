//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// The release's BLS wrapper links its strong random source. No program draws
// from it, so it aborts.

#include <random.h>

#include <cstdlib>

void GetStrongRandBytes(Span<unsigned char>) noexcept { std::abort(); }
