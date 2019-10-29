/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_KEYS_MANAGER_IMPL_HPP
#define IROHA_KEYS_MANAGER_IMPL_HPP

#include "crypto/keys_manager.hpp"

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include "cryptography/keypair.hpp"
#include "logger/logger_fwd.hpp"

// Includes from the cpp
#include <fstream>

#include "common/byteutils.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "logger/logger.hpp"

using namespace shared_model::crypto;

using iroha::operator|;

namespace iroha {
  /**
   * Function for the key encryption via XOR
   * @tparam is a key type
   * @param privkey is a private key
   * @param pass_phrase is a key for encryption
   * @return encrypted string
   */
  template <typename T>
  static std::string encrypt(const T &key, const std::string &pass_phrase) {
    std::string ciphertext(key.size(), '\0');
    const size_t min_pass_size = 1;
    // pass_size will always be > 0
    const auto pass_size = std::max(min_pass_size, pass_phrase.size());
    // When pass_phrase is empty it, pass_phrase[0] is "\0", so no out_of_range
    // exception is possible
    for (size_t i = 0; i < key.size(); i++) {
      ciphertext[i] = key[i] ^ pass_phrase[i % pass_size];
    }
    return ciphertext;
  }

  /**
   * Function for XOR decryption
   */
  static constexpr auto decrypt = encrypt<Blob::Bytes>;

  template <typename T>
  class KeysManagerImpl : public KeysManager {
   public:
    /**
     * Initialize key manager for a specific account
     * @param account_id - fully qualified account id, e.g. admin@test
     * @param path_to_keypair - path to directory that contains priv and pub key
     * of an account
     * @param log to print progress
     */
    KeysManagerImpl(const std::string &account_id,
                    const boost::filesystem::path &path_to_keypair,
                    logger::LoggerPtr log)
                    : path_to_keypair_(path_to_keypair),
                      account_id_(account_id),
                      log_(std::move(log)) {}

    /**
     * Initialize key manager for a specific account
     * @param account_id - fully qualified account id, e.g. admin@test
     * @param log to print progress
     */
    KeysManagerImpl(const std::string account_id, logger::LoggerPtr log)
    : KeysManagerImpl(account_id, "", std::move(log)) {}

    bool createKeys() override {
      return createKeys("");
    }

    bool createKeys(const std::string &pass_phrase) override {
      Keypair keypair = T::generateKeypair();

      auto pub = keypair.publicKey().hex();
      auto priv = bytestringToHexstring(
          encrypt(keypair.privateKey().blob(), pass_phrase));
      return store(pub, priv);
    }

    boost::optional<shared_model::crypto::Keypair> loadKeys() override {
      return loadKeys("");
    }

    boost::optional<shared_model::crypto::Keypair> loadKeys(
        const std::string &pass_phrase) override {
      auto public_key =
          loadFile(path_to_keypair_ / (account_id_ + kPublicKeyExtension));
      auto private_key =
          loadFile(path_to_keypair_ / (account_id_ + kPrivateKeyExtension));

      if (not public_key or not private_key) {
        return boost::none;
      }

      Keypair keypair = Keypair(
          PublicKey(Blob::fromHexString(public_key.get())),
          PrivateKey(decrypt(Blob::fromHexString(private_key.get()).blob(),
                             pass_phrase)));

      if (keypair.publicKey().size()
              != T::kPublicKeyLength
          or keypair.privateKey().size()
              != T::kPrivateKeyLength) {
        return boost::none;
      }

      return validate(keypair) ? boost::make_optional(keypair) : boost::none;
    }

    static const std::string kPublicKeyExtension;
    static const std::string kPrivateKeyExtension;

   private:
    /**
     * Check if keypair provides valid signature
     * @param keypair - keypair for validation
     * @return true, if verification of signature is successful
     */
    bool validate(const shared_model::crypto::Keypair &keypair) const {
      try {
        auto test = Blob("12345");
        auto sig = T::sign(test, keypair);
        if (not T::verify(
                sig, test, keypair.publicKey())) {
          log_->error("key validation failed");
          return false;
        }
      } catch (const BadFormatException &exception) {
        log_->error("Cannot validate keyapir: {}", exception.what());
        return false;
      }
      return true;
    }

    /**
     * Tries to read the file
     * @param path - path to the target file
     * @return file contents if reading was successful, otherwise - boost::none
     */
    boost::optional<std::string> loadFile(
        const boost::filesystem::path &path) const {
      auto file_path = path.string();
      std::ifstream file(file_path);
      if (not file) {
        log_->error("Cannot read '" + file_path + "'");
        return {};
      }

      std::string contents;
      file >> contents;
      return contents;
    }

    /**
     * Stores strings, that represent public and private keys on disk
     * @param pub is a public key
     * @param priv is a private key
     * @return true, if saving was successful
     */
    bool store(const std::string &pub, const std::string &priv) {
      std::ofstream pub_file(
          (path_to_keypair_ / (account_id_ + kPublicKeyExtension)).string());
      std::ofstream priv_file(
          (path_to_keypair_ / (account_id_ + kPrivateKeyExtension)).string());
      if (not pub_file or not priv_file) {
        return false;
      }

      pub_file << pub;
      priv_file << priv;
      return pub_file.good() && priv_file.good();
    }

    boost::filesystem::path path_to_keypair_;
    std::string account_id_;
    logger::LoggerPtr log_;
  };

  template <typename T>
  const std::string KeysManagerImpl<T>::kPublicKeyExtension = ".pub";

  template <typename T>
  const std::string KeysManagerImpl<T>::kPrivateKeyExtension = ".priv";

}  // namespace iroha
#endif  // IROHA_KEYS_MANAGER_IMPL_HPP
