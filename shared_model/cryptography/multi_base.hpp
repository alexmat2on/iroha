/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_MULTIBASE_HPP
#define IROHA_SHARED_MODEL_MULTIBASE_HPP

#include <string>
#include <vector>

#include "cryptography/blob.hpp"
#include "multihash/multihash.hpp"

namespace shared_model {
  namespace crypto {

    class MultiBase : public libp2p::multi::Multihash {
     public:
      MultiBase(libp2p::multi::HashType hash_type,
                const std::string &private_key);

      MultiBase(libp2p::multi::HashType hash_type, const Blob::Bytes &blob);

      MultiBase(libp2p::multi::HashType hash_type, const Blob &blob);

      static MultiBase fromHexString(libp2p::multi::HashType hash_type,
                                     const std::string &hex);
      const std::string &hex() const;
      const Blob::Bytes &blob() const;
      size_t size() const;

     protected:
      std::string hex_;
    };

  }  // namespace crypto
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_MULTIBASE_HPP
