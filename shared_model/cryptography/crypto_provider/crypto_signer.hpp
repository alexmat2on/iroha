/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_SIGNER_HPP
#define IROHA_CRYPTO_SIGNER_HPP

#include "cryptography/blob.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include "cryptography/ed25519_ursa_impl/crypto_provider.hpp"
#include "cryptography/keypair.hpp"
#include "cryptography/signed.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * CryptoSigner - wrapper for generalization signing for different
     * cryptographic algorithms
     * @tparam Algorithm - cryptographic algorithm for singing
     */
    template <typename Algorithm = DefaultCryptoAlgorithmType>
    class CryptoSigner {
     public:
      /**
       * Generate signature for target data
       * @param blob - data for signing
       * @param keypair - (public, private) keys for signing
       * @return signature's blob
       */
      static Signed sign(const Blob &blob, const Keypair &keypair) {
        const auto pub_key_type = keypair.publicKey().getType();

        if (
          pub_key_type == libp2p::multi::HashType::ed25519pubsha3) {
          return CryptoProviderEd25519Sha3::sign(blob, keypair);
        } else if (
          pub_key_type == libp2p::multi::HashType::ed25519pubsha2) {
          return CryptoProviderEd25519Ursa::sign(blob, keypair);
        }
        else {
          return Signed{""};
        }
      }

      /// close constructor for forbidding instantiation
      CryptoSigner() = delete;
    };
  }  // namespace crypto
}  // namespace shared_model
#endif  // IROHA_CRYPTO_SIGNER_HPP
