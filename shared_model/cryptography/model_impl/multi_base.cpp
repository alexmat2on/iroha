/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include "cryptography/multi_base.hpp"
#include "common/byteutils.hpp"
#include "multihash/hash_type.hpp"
#include <boost/algorithm/string.hpp>

namespace shared_model {
  namespace crypto {

    MultiBase::MultiBase(libp2p::multi::HashType hash_type, const std::string &multi_blob)
        : MultiBase(hash_type, Blob::Bytes{multi_blob.begin(), multi_blob.end()}) {}

    MultiBase::MultiBase(libp2p::multi::HashType hash_type, const Blob::Bytes &multi_blob)
        : libp2p::multi::Multihash([&]{

          if (!((hash_type == libp2p::multi::HashType::ed25519pubsha3 && multi_blob.size() == shared_model::crypto::CryptoProviderEd25519Sha3::kPublicKeyLength) ||
          (hash_type == libp2p::multi::HashType::ed25519sigsha3 && multi_blob.size() == shared_model::crypto::CryptoProviderEd25519Sha3::kSignatureLength))) {
            auto result = libp2p::multi::Multihash::createFromBuffer(kagome::common::Buffer{multi_blob});
            if (result) {
              return result.value();
            }
          }

          return libp2p::multi::Multihash::create(
                                       hash_type,
                                       kagome::common::Buffer{multi_blob})
                                       .value();
        }()),
                                       hex_([this]{
                                         auto hex_str = toHex();
                                         boost::to_lower(hex_str);

                                         return hex_str;
                                       }()) {}

    MultiBase::MultiBase(libp2p::multi::HashType hash_type, const Blob &multi_blob)
        : MultiBase(hash_type, multi_blob.blob()) {}

    MultiBase MultiBase::fromHexString(libp2p::multi::HashType hash_type, const std::string &hex) {
      using iroha::operator|;
      MultiBase b(hash_type, "");
      iroha::hexstringToBytestring(hex) | [&](auto &&s) { b = MultiBase(hash_type, s); };
      return b;
    }

    const std::string &MultiBase::hex() const {
      return hex_;
    }

    const Blob::Bytes &MultiBase::blob() const {
      return getHash().toVector();
    }

    size_t MultiBase::size() const {
      return getHash().size();
    }

  }  // namespace crypto
}  // namespace shared_model
