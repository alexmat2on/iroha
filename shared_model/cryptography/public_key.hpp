/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PUBLIC_KEY_HPP
#define IROHA_SHARED_MODEL_PUBLIC_KEY_HPP

#include "cryptography/multi_base.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * A special class for storing public keys.
     */
    class PublicKey : public MultiBase {
     public:
      explicit PublicKey(const std::string &public_key);

      explicit PublicKey(const Blob::Bytes &blob);

      explicit PublicKey(const Blob &blob);

      static PublicKey fromHexString(const std::string &hex);

      std::string toString() const;

    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PUBLIC_KEY_HPP
