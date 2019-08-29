/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_SIGNED_HPP
#define IROHA_SHARED_MODEL_SIGNED_HPP

#include "multihash/multihash.hpp"
#include "cryptography/blob.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * Class for storing signed data. It could be used not only for storing
     * signed hashes but for other signed objects too.
     */
    class Signed : public libp2p::multi::Multihash {
     public:
      explicit Signed(const std::string &blob);

      explicit Signed(const Blob::Bytes &blob);

      explicit Signed(const Blob &blob);

      std::string toString() const;

      static Signed fromHexString(const std::string &hex);
      std::string hex() const;
      const Blob::Bytes &blob() const;
      size_t size() const;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_SIGNED_HPP
