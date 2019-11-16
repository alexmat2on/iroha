/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_VERIFIER_HPP
#define IROHA_CRYPTO_VERIFIER_HPP

#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include "cryptography/ed25519_ursa_impl/crypto_provider.hpp"

namespace shared_model {
  namespace crypto {

    class Signed;
    class Blob;
    class PublicKey;

    /**
     * CryptoVerifier - adapter for generalization verification of cryptographic
     * signatures
     * @tparam Algorithm - cryptographic algorithm for verification
     */
    class CryptoVerifier {
     public:
      /**
       * Verify signature attached to source data
       * @param signedData - cryptographic signature
       * @param source - data that was signed
       * @param pubKey - public key of signatory
       * @return true if signature correct
       */
      static bool verify(const Signed &signedData,
                         const Blob &source,
                         const PublicKey &pubKey) {
        if (pubKey.blob().size()
            == shared_model::crypto::CryptoProviderEd25519Sha3::
                   kPublicKeyLength) {
          return CryptoProviderEd25519Sha3::verify(signedData, source, pubKey);
        } else if (auto opt_multihash = iroha::expected::resultToOptionalValue(
                       libp2p::multi::Multihash::createFromBuffer(
                           kagome::common::Buffer{pubKey.blob()}))) {
          if (opt_multihash->getType()
              == libp2p::multi::HashType::ed25519pubsha2) {
            return CryptoProviderEd25519Ursa::verify(
                signedData, source, pubKey);
          }
        }

        return false;
      }

      /// close constructor for forbidding instantiation
      CryptoVerifier() = delete;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_CRYPTO_VERIFIER_HPP
