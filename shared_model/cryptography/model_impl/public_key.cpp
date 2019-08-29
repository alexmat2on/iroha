/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multihash/hash_type.hpp"
#include "cryptography/public_key.hpp"
#include "common/byteutils.hpp"


#include "utils/string_builder.hpp"

namespace shared_model {
  namespace crypto {

    PublicKey::PublicKey(const std::string &public_key) : libp2p::multi::Multihash(libp2p::multi::Multihash::create(libp2p::multi::HashType::ed25519pubsha3, kagome::common::Buffer{std::vector<uint8_t>{public_key.begin(), public_key.end()}}).value()) {}

    PublicKey::PublicKey(const Blob &blob) : libp2p::multi::Multihash(libp2p::multi::Multihash::create(libp2p::multi::HashType::ed25519pubsha3, kagome::common::Buffer{blob.blob()}).value()) {}

    std::string PublicKey::toString() const {
      return detail::PrettyStringBuilder()
          .init("PublicKey")
          .append(libp2p::multi::Multihash::toHex())
          .finalize();
    }

    PublicKey PublicKey::fromHexString(const std::string &hex) {
      using iroha::operator|;
      PublicKey b("");
      iroha::hexstringToBytestring(hex) | [&](auto &&s) { b = PublicKey(s); };
      return b;
    }

    std::string PublicKey::hex() const {
      return getHash().toHex();
    }

    const Blob::Bytes &PublicKey::blob() const {
      return getHash().toVector();
    }

    size_t PublicKey::size() const {
      return getHash().size();
    }


  }  // namespace crypto
}  // namespace shared_model
