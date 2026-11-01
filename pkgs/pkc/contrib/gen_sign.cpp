//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// Writes bls_sign.json5, signatures over digests and over messages under each
// scheme.

#include "common.hpp"

using namespace corpus;

namespace {

void Row(Json& rows, const bls::PrivateKey& sk, const Bytes& msg, const bls::G2Element& sig, bool legacy)
{
  Json& row = rows.Push(Json::Object());
  row.Set("sk", Json::Str(SkHex(sk)));
  row.Set("msg", Json::Str(Hex(msg)));
  row.Set("sig", Json::Str(SigHex(sig, legacy)));
}

} // namespace

int main()
{
  Json root = Json::Object();
  for (const auto& scheme : kSchemes) {
    Json& arm = root.Set(scheme.name, Json::Object());
    Json& sign = arm.Set("sign", Json::List());
    for (uint8_t k = 1; k <= 5; ++k) {
      for (const auto& digest : kDigests) {
        Row(sign, SkOf(k), digest, SignDigest(SkOf(k), digest, scheme.legacy), scheme.legacy);
      }
    }

    Json& msgs = arm.Set("sign_message", Json::List());
    const char* const* keys;
    const char* const* texts;
    size_t count;
    if (scheme.legacy) {
      msgs.Note("Sourced from the pre-1.0 Chia bls-signatures \"Test vectors 1\"");
      msgs.Note("https://github.com/Chia-Network/bls-signatures/blob/0.1.15/src/test.cpp#L31-L62");
      static const char* const sks[] = {
          "022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e",
          "502c5661f5af46ed48ddc3b5332e21b93cc7d0a84df46c4b9c7fe8f25ef48d66",
      };
      static const char* const ms[] = {"070809", "070809"};
      keys = sks, texts = ms, count = 2;
    } else {
      msgs.Note("Sourced from dashbls \"Pyecc vector\", a py_ecc basic scheme signature.");
      msgs.Note("https://github.com/dashpay/bls-signatures/blob/1.3.5/src/test.cpp#L320-L331");
      static const char* const sks[] = {
          "0101010101010101010101010101010101010101010101010101010101010101",
          "4a353be3dac091a0a7e640620372f5e1e2e4401717c1e79cac6ffba8f6905604",
          "6fc9d9a2b05fd1f0e51bc91041a03be8657081f272ec281aff731624f0d1c220",
      };
      static const char* const ms[] = {"030104010509", "070809", "0a0b0c"};
      keys = sks, texts = ms, count = 3;
    }
    for (size_t i = 0; i < count; ++i) {
      const auto sk = Sk(Unhex(keys[i]));
      const auto msg = Unhex(texts[i]);
      Row(msgs, sk, msg, SignMessage(sk, msg, scheme.legacy), scheme.legacy);
    }
    if (!scheme.legacy) {
      msgs.Item(1).Note(
          "Sourced from the dashbls basic scheme KAT, whose second key derives from 32 bytes of 0x01 and is "
          "pinned upstream only by fingerprint b839add1.");
      msgs.Item(1).Note("https://github.com/dashpay/bls-signatures/blob/1.3.5/src/test.cpp#L336-L402");
    }
  }
  return Print(root);
}
