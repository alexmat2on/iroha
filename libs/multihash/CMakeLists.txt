#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
add_library(hexutil hexutil.cpp)
add_library(uvarint uvarint.cpp)
add_library(multihash STATIC multihash.cpp)

target_link_libraries( multihash
    boost
    )
