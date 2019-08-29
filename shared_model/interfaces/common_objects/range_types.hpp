/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_RANGE_TYPES_HPP
#define IROHA_SHARED_MODEL_RANGE_TYPES_HPP

#include <boost/range/any_range.hpp>
#include <boost/functional/hash.hpp>
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    class Signature;
    class Transaction;
    class AccountAsset;

    namespace types {
      struct MultihashSignature {
        libp2p::multi::Multihash signature;
        libp2p::multi::Multihash public_key;

        std::string toString() const {
          return signature.toString() + public_key.toString();
        }

        bool operator==(const MultihashSignature &other) const {
          return this->signature == other.signature && this->public_key == other.public_key;
        }

        bool operator!=(const MultihashSignature &other) const {
          return !(*this == other);
        }
      };



      /// Type of signature range, which returns when signatures are invoked
      using MultihashRangeType = boost::any_range<MultihashSignature,
                                                  boost::forward_traversal_tag,
                                                  const MultihashSignature &>;

      /// Type of signature range, which returns when signatures are invoked
      using SignatureRangeType = boost::any_range<Signature,
                                                  boost::forward_traversal_tag,
                                                  const Signature &>;
      /// Type of transactions' collection
      using TransactionsCollectionType =
          boost::any_range<Transaction,
                           boost::random_access_traversal_tag,
                           const Transaction &>;
      using AccountAssetCollectionType =
          boost::any_range<AccountAsset,
                           boost::random_access_traversal_tag,
                           const AccountAsset &>;
      /// Type of hash collection
      using HashCollectionType = boost::
          any_range<HashType, boost::forward_traversal_tag, const HashType &>;

    }  // namespace types
  }    // namespace interface
}  // namespace shared_model

namespace std {
  template <>
  struct hash<shared_model::interface::types::MultihashSignature> {
    size_t operator()(const shared_model::interface::types::MultihashSignature &x) const {
      using boost::hash_combine;
      using boost::hash_value;

      std::size_t seed = 0;
      hash_combine(seed, std::hash<libp2p::multi::Multihash>{}(x.signature));
      hash_combine(seed, std::hash<libp2p::multi::Multihash>{}(x.public_key));

      return seed;
    }
  };
}  // namespace std

#endif  // IROHA_SHARED_MODEL_RANGE_TYPES_HPP
