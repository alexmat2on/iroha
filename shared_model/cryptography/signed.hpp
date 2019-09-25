/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_SIGNED_HPP
#define IROHA_SHARED_MODEL_SIGNED_HPP

#include "cryptography/multi_base.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * Class for storing signed data. It could be used not only for storing
     * signed hashes but for other signed objects too.
     */
    class Signed : public MultiBase {
     public:
      explicit Signed(const std::string &blob);

      explicit Signed(const Blob::Bytes &blob);

      explicit Signed(const Blob &blob);

      static Signed fromHexString(const std::string &hex);

      std::string toString() const;

    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_SIGNED_HPP
