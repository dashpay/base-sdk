#!/bin/sh
#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#
# Builds the corpus programs against two releases and writes the BLS corpora.
# Nothing is written unless both releases write the same bytes.
#
# Run as regen.sh <dash checkout> <build dir> <corpus dir>. Each release's
# library build under <build dir> is reused, and the programs are compiled
# again on every run.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$1 builds=$2 corpus=$3
mkdir -p "$builds" "$corpus"
builds=$(cd "$builds" && pwd)
corpus=$(cd "$corpus" && pwd)

# Each release as tag=commit.
releases="v24.0.0-rc.5=8163290aa0307ed4bc2fc0ba15b78c20d61dfa88 v23.1.8=728f5055836c6d29806412fc7223ac8fe05af991"
corpora="aggregate hash ies keygen llmq_100 read secure_aggregate serialize sign threshold"

tags=
for pair in $releases; do
  tag=${pair%%=*}
  "$here/build.sh" "$repo" "$tag" "${pair#*=}" "$builds/$tag"
  tags="$tags $tag"
done
first=${releases%%=*}

stage=$(mktemp -d "${TMPDIR:-/tmp}/regen.XXXXXX")
trap 'rm -rf "$stage"' EXIT
for name in $corpora; do
  for tag in $tags; do
    "$builds/$tag/bin/gen_$name" >"$stage/bls_$name.$tag"
    if ! cmp -s "$stage/bls_$name.$tag" "$stage/bls_$name.$first"; then
      echo "regen.sh: bls_$name differs between releases" >&2
      exit 1
    fi
  done
done
for name in $corpora; do
  cp "$stage/bls_$name.$first" "$corpus/bls_$name.json5"
done
