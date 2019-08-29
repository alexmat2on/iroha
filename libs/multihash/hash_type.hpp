/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef KAGOME_HASH_TYPE_HPP
#define KAGOME_HASH_TYPE_HPP

namespace libp2p {
  namespace multi {
  /// https://github.com/multiformats/js-multihash/blob/master/src/constants.js
  enum HashType : uint64_t {
    sha1 = 0x11,
    sha256 = 0x12,
    sha512 = 0x13,
    blake2s128 = 0xb250,
    blake2s256 = 0xb260,
ed25519pubsha2 = 0xed13,
ed25519pubsha3 = 0xed14,
ed25519sigsha2 = 0xef13,
ed25519sigsha3 = 0xef14,
  };
}  // namespace libp2p::multi
}

#endif  // KAGOME_HASH_TYPE_HPP
