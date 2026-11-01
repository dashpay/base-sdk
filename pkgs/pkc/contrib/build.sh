#!/bin/sh
#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#
# Builds the BLS library of a reference implementation release and links the
# corpus programs against it, with a few of the release's own sources.
#
# Run as build.sh <dash checkout> <tag> <commit> <output dir>. The tag must
# resolve to <commit>. The library build is kept in <output dir> and reused
# when <output dir>/release names the same tag and commit. The programs and
# the release objects they link are compiled again on every run.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$1 tag=$2 commit=$3 out=$4
found=$(git -C "$repo" rev-parse --verify "$tag^{commit}")
if [ "$found" != "$commit" ]; then
  echo "build.sh: $tag is $found in $repo, expected $commit" >&2
  exit 1
fi
mkdir -p "$out"
out=$(cd "$out" && pwd)
bls="$out/src/dashbls"

if [ -e "$out/release" ]; then
  if [ "$(cat "$out/release")" != "$tag $commit" ]; then
    echo "build.sh: $out holds $(cat "$out/release"), not $tag $commit" >&2
    exit 1
  fi
elif [ -e "$out/src" ]; then
  echo "build.sh: $out holds an unfinished build, remove it and run again" >&2
  exit 1
else
  git -C "$repo" archive "$commit" src | tar -x -C "$out"
  if ! (
    cd "$bls" &&
      ./autogen.sh &&
      ./configure --disable-shared --with-pic --disable-tests --disable-bench &&
      make -j"${JOBS:-4}" libdashbls.la
  ) >"$out/build.log" 2>&1; then
    echo "build.sh: the library build failed, see $out/build.log" >&2
    echo "build.sh: remove $out before running again" >&2
    exit 1
  fi
  # The release's sources expect a generated config header. None of the code
  # compiled here reads it.
  mkdir -p "$out/gen/config"
  : >"$out/gen/config/bitcoin-config.h"
  # The release's commitment hash function, compiled as it is.
  sed -n '/^uint256 BuildCommitmentHash(/,/^}/p' "$out/src/llmq/commitment.cpp" >"$out/gen/commitment_hash.inc"
  if [ ! -s "$out/gen/commitment_hash.inc" ]; then
    echo "build.sh: no commitment hash function in $tag" >&2
    exit 1
  fi
  printf '%s %s\n' "$tag" "$commit" >"$out/release"
fi

# The GMP paths configure found, such as Homebrew's on macOS.
gmp_cppflags=$(sed -n 's/^GMP_CPPFLAGS = //p' "$bls/Makefile")
gmp_ldflags=$(sed -n 's/^GMP_LDFLAGS = //p' "$bls/Makefile")
cxx() {
  # shellcheck disable=SC2086 # the flag variables hold lists
  ${CXX:-c++} -std=c++20 -O2 ${CPPFLAGS:-} ${CXXFLAGS:-} $gmp_cppflags \
    -I"$here" -I"$out/gen" -I"$out/src" \
    -I"$bls/include" -I"$bls/include/dashbls" -I"$bls/depends/relic/include" -I"$bls/src" "$@"
}
mkdir -p "$out/obj" "$out/bin"
rm -f "$out"/obj/*.o "$out"/bin/gen_*
for src in bls/bls.cpp crypto/sha256.cpp crypto/sha256_sse4.cpp uint256.cpp support/cleanse.cpp \
  support/lockedpool.cpp util/strencodings.cpp; do
  cxx -c "$out/src/$src" -o "$out/obj/$(echo "$src" | tr / _).o"
done
cxx -c "$here/no_random.cpp" -o "$out/obj/no_random.o"
for prog in "$here"/gen_*.cpp; do
  name=$(basename "$prog" .cpp)
  # shellcheck disable=SC2086 # the flag variables hold lists
  cxx "$prog" -o "$out/bin/$name" ${LDFLAGS:-} $gmp_ldflags "$out"/obj/*.o \
    "$bls/.libs/libdashbls.a" "$bls/.libs/librelic.a" "$bls/.libs/libmimalloc-secure.a" -lgmp -lpthread
done
