/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PRIVATE_KEY_HPP
#define IROHA_SHARED_MODEL_PRIVATE_KEY_HPP

#include "multihash/multihash.hpp"
#include "cryptography/blob.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * A special class for storing private keys.
     */
    class PrivateKey : public libp2p::multi::Multihash {
     public:
      explicit PrivateKey(const std::string &private_key);

      explicit PrivateKey(const Blob &blob);

      std::string toString() const;

      static PrivateKey fromHexString(const std::string &hex);
      std::string hex() const;
      const Blob::Bytes &blob() const;
      size_t size() const;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PRIVATE_KEY_HPP
