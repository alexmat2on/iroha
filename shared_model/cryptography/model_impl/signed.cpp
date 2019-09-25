/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/signed.hpp"
#include "common/byteutils.hpp"
#include "multihash/hash_type.hpp"

namespace shared_model {
  namespace crypto {

    Signed::Signed(const std::string &blob)
        : MultiBase(libp2p::multi::HashType::ed25519sigsha3, blob) {}

    Signed::Signed(const Blob::Bytes &blob)
        : MultiBase(libp2p::multi::HashType::ed25519sigsha3, blob) {}

    Signed::Signed(const Blob &blob)
        : MultiBase(libp2p::multi::HashType::ed25519sigsha3, blob) {}

    Signed Signed::fromHexString(const std::string &hex) {
      using iroha::operator|;
      Signed b("");
      iroha::hexstringToBytestring(hex) | [&](auto &&s) { b = Signed(s); };
      return b;
      // return Signed(iroha::hexstringToBytestring(hex).value());
    }

    std::string Signed::toString() const {
      return detail::PrettyStringBuilder()
          .init("Signed")
          .append(libp2p::multi::Multihash::toHex())
          .finalize();
    }

  }  // namespace crypto
}  // namespace shared_model
