/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/public_key.hpp"
#include "common/byteutils.hpp"
#include "multihash/hash_type.hpp"

namespace shared_model {
  namespace crypto {

    PublicKey::PublicKey(const std::string &public_key)
        : MultiBase(libp2p::multi::HashType::ed25519pubsha3, public_key) {}

    PublicKey::PublicKey(const Blob::Bytes &blob)
        : MultiBase(libp2p::multi::HashType::ed25519pubsha3, blob) {}

    PublicKey::PublicKey(const Blob &blob)
        : MultiBase(libp2p::multi::HashType::ed25519pubsha3, blob) {}

    PublicKey PublicKey::fromHexString(const std::string &hex) {
      using iroha::operator|;
      PublicKey b("");
      iroha::hexstringToBytestring(hex) | [&](auto &&s) { b = PublicKey(s); };
      return b;
    }

    std::string PublicKey::toString() const {
      return detail::PrettyStringBuilder()
          .init("PublicKey")
          .append(libp2p::multi::Multihash::toHex())
          .finalize();
    }

  }  // namespace crypto
}  // namespace shared_model
