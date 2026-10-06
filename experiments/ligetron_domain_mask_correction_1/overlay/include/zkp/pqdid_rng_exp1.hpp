// Experimental CPU-component correspondence only. Not an admitted proof profile.
#pragma once
#include <bit>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include <openssl/rand.h>
#include <params.hpp>
#include <util/csprng.hpp>

namespace ligero::vm::zkp::pqdid_exp1 {
static_assert(std::endian::native == std::endian::little);
static_assert(sizeof(void*) == 8 && sizeof(uint64_t) == 8);

inline void private_encoding_seed(unsigned char (&seed)[32]) {
    if (RAND_priv_bytes(seed, 32) != 1)
        throw std::runtime_error("Cannot obtain private encoding randomness");
}

inline void init_challenge_engines(const unsigned char (&key)[32],
                                  mpz_random_engine& code,
                                  mpz_random_engine& linear,
                                  mpz_random_engine& quadratic) {
    code.init(key, params::ivc);
    linear.init(key, params::ivl);
    quadratic.init(key, params::ivq);
}

using digest = params::hasher::digest;
inline digest stage1_seed(const digest& root, const digest& instance) {
    // Upstream char-array hashing includes the trailing NUL, intentionally.
    return hash<params::hasher>("PQDID-Ligetron-DM-EXP1/k8192-l7936-n32768-t192-d7-D16383/Stage1", root, instance);
}
inline digest stage2_seed(const digest& root, const std::vector<uint32_t>& code,
                         const std::vector<uint32_t>& linear,
                         const std::vector<uint32_t>& quadratic) {
    return hash<params::hasher>("PQDID-Ligetron-DM-EXP1/k8192-l7936-n32768-t192-d7-D16383/Stage2", root,
                               code, linear, quadratic);
}
} // namespace ligero::vm::zkp::pqdid_exp1
