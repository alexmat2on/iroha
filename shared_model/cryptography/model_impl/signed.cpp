/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multihash/hash_type.hpp"
#include "cryptography/signed.hpp"
#include "common/byteutils.hpp"

#include "utils/string_builder.hpp"

namespace shared_model {
  namespace crypto {

    std::string Signed::toString() const {
      return detail::PrettyStringBuilder()
          .init("Signed")
          .append(libp2p::multi::Multihash::toHex())
          .finalize();
    }

    Signed::Signed(const std::string &blob) : libp2p::multi::Multihash(libp2p::multi::Multihash::create(libp2p::multi::HashType::ed25519sigsha3, kagome::common::Buffer{std::vector<uint8_t>{blob.begin(), blob.end()}}).value()) {}

    Signed::Signed(const Blob::Bytes &blob) : libp2p::multi::Multihash(libp2p::multi::Multihash::create(libp2p::multi::HashType::ed25519privsha3, kagome::common::Buffer{blob}).value()) {}

    Signed::Signed(const Blob &blob) : libp2p::multi::Multihash(libp2p::multi::Multihash::create(libp2p::multi::HashType::ed25519privsha3, kagome::common::Buffer{blob.blob()}).value()) {}

    Signed Signed::fromHexString(const std::string &hex) {
      using iroha::operator|;
      Signed b("");
      iroha::hexstringToBytestring(hex) | [&](auto &&s) { b = Signed(s); };
      return b;
    }

    std::string Signed::hex() const {
      return getHash().toHex();
    }

    const Blob::Bytes &Signed::blob() const {
      return getHash().toVector();
    }

    size_t Signed::size() const {
      return getHash().size();
    }

  }  // namespace crypto
}  // namespace shared_model
