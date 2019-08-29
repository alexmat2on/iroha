/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multihash/hash_type.hpp"
#include "cryptography/private_key.hpp"
#include "common/byteutils.hpp"

namespace shared_model {
  namespace crypto {

    PrivateKey::PrivateKey(const std::string &private_key)
        : libp2p::multi::Multihash(libp2p::multi::Multihash::create(libp2p::multi::HashType::ed25519privsha3, kagome::common::Buffer{std::vector<uint8_t>{private_key.begin(), private_key.end()}}).value()) {}

    PrivateKey::PrivateKey(const Blob &blob) : libp2p::multi::Multihash(libp2p::multi::Multihash::create(libp2p::multi::HashType::ed25519privsha3, kagome::common::Buffer{blob.blob()}).value()) {}

    std::string PrivateKey::toString() const {
      return detail::PrettyStringBuilder()
          .init("PrivateKey")
          .append("<Data is hidden>")
          .finalize();
    }

    PrivateKey PrivateKey::fromHexString(const std::string &hex) {
      using iroha::operator|;
      PrivateKey b("");
      iroha::hexstringToBytestring(hex) | [&](auto &&s) { b = PrivateKey(s); };
      return b;
    }

    std::string PrivateKey::hex() const {
      return getHash().toHex();
    }

    const Blob::Bytes &PrivateKey::blob() const {
      return getHash().toVector();
    }

    size_t PrivateKey::size() const {
      return getHash().size();
    }

  }  // namespace crypto
}  // namespace shared_model
