// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include "cryptopals/block.hpp"

#include <string>

#include <cfloat>

#include "cryptopals/hamming.hpp"
#include "cryptopals/xor.hpp"

namespace cryptopals {

size_t block::keysize(const std::string &str, float &min_dist,
                      size_t max_keysize) {
  size_t keysize = 0;

  min_dist = FLT_MAX;

  // check keysizes between 2 and max_keysize
  for (size_t k = 2; k <= max_keysize; k++) {
    // break the data into blocks of size of the key,
    // but ignore the trailing block, which may be
    // smaller than the other blocks, preventing
    // out-of-bounds memory access
    const size_t nblocks = (str.length() / k) - 1;
    float dist = 0;

    // sum the hamming distances, normalized
    // by the keysize, between adjacent blocks
    for (size_t b = 0; b < nblocks; b++) {
      const size_t pos = b * k;
      float hd = static_cast<float>(hamming::distance(str, pos, k));
      dist += hd / static_cast<float>(k);
    }

    // average the hamming distances
    dist /= static_cast<float>(nblocks);

    if (dist < min_dist) {
      min_dist = dist;
      keysize = k;
    }
  }

  return keysize;
}

size_t block::keysize(const std::string &str, size_t max_keysize) {
  float min_dist = 0.0;
  return block::keysize(str, min_dist, max_keysize);
}

std::string block::transpose_get_key(const std::string &str,
                                     size_t max_keysize) {
  std::string key;
  std::string block;
  std::string::iterator k;
  size_t keysize = block::keysize(str, max_keysize);
  size_t blocksize = str.length() / keysize;

  key.resize(keysize);
  block.resize(blocksize);
  k = key.begin();

  // transpose blocks
  while (k != key.end()) {
    std::string::iterator b = block.begin();
    std::string::const_iterator s = str.cbegin();
    // str iterator is offset by number of key bytes decoded so far
    s += (k - key.begin());
    // use < for str iterator because it may pass the end
    while (b != block.end() && s < str.cend()) {
      *b++ = *s;
      s += keysize;
    }
    *k++ = xor_::find_key(block);
  }

  return key;
}

} // namespace cryptopals
