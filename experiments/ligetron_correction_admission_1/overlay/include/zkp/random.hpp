/*
 * Copyright (C) 2023-2026 Ligero, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>
#include <algorithm>

#include <zkp/hash.hpp>
// #include <zkp/finite_ring.hpp>

#include <openssl/evp.h>
#include <openssl/aes.h>

namespace ligero::vm::zkp {

template <typename T, size_t buffer_size = 16 * 1024>
struct aes256ctr_engine {
    using result_type = T;
    
    constexpr static size_t key_size = 32;
    constexpr static size_t block_size = AES_BLOCK_SIZE;

    constexpr static size_t num_elements = buffer_size / sizeof(T);

    constexpr static result_type min() { return std::numeric_limits<result_type>::min(); }
    constexpr static result_type max() { return std::numeric_limits<result_type>::max(); }

    struct deleter { void operator()(EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); } };

    aes256ctr_engine() : ctx_(EVP_CIPHER_CTX_new()) { }
    aes256ctr_engine(const unsigned char (&key)[key_size], const unsigned char (&iv)[block_size])
        : ctx_(EVP_CIPHER_CTX_new()) { init(key, iv); }

    void init(const unsigned char (&key)[key_size], const unsigned char (&iv)[block_size]) {
        int success = EVP_EncryptInit(ctx_.get(), EVP_aes_256_ctr(), key, iv);
        if (!success) {
            throw std::runtime_error("Cannot initialize AES context");
        }
        fill_buf();
    }

    void fill_buf() {
        int size = 0;
        unsigned char *ptr = reinterpret_cast<unsigned char*>(buffer_);
        EVP_EncryptUpdate(ctx_.get(), ptr, &size, data_, buffer_size);
    }

    result_type operator()() {
        if (pos_ >= num_elements) {
            fill_buf();
            pos_ = 0;
        }
        return reinterpret_cast<result_type*>(buffer_)[pos_++];
    }

    result_type* operator()(size_t n) {
        if ((pos_ + n) >= num_elements) {
            fill_buf();
            pos_ = 0;
        }
        auto *ret = reinterpret_cast<result_type*>(buffer_ + pos_);
        pos_ += n;
        return ret;
    }

    alignas(block_size) unsigned char buffer_[buffer_size];
    alignas(block_size) unsigned char data_[buffer_size] = { 0 };
    std::unique_ptr<EVP_CIPHER_CTX, deleter> ctx_;
    size_t pos_ = 0;
};

template <IsHashScheme Hasher>
struct hash_random_engine {
    using result_type = uint8_t;
    using seed_type = typename Hasher::digest;

    constexpr static size_t cycle_size = Hasher::digest_size;
    constexpr static result_type min() { return 0; }
    constexpr static result_type max() { return 255; }

    hash_random_engine() { seed(); }
    explicit hash_random_engine(const seed_type& d) { seed(d); }

    void seed() { seed(seed_type{}); }

    void seed(const seed_type& d) {
        seed_ = d;
        state_ = 0;
        offset_ = cycle_size;
        exhausted_ = false;
    }

    void discard(size_t count) {
        // Equivalent to count invocations, including across block boundaries.
        while (count != 0) {
            if (offset_ == cycle_size) {
                refill();
            }
            const size_t step = std::min(count, cycle_size - offset_);
            offset_ += step;
            count -= step;
        }
    }

    result_type operator()() {
        if (offset_ == cycle_size) {
            refill();
        }
        return buffer_.data[offset_++];
    }

protected:
    void refill() {
        if (exhausted_) {
            throw std::overflow_error("Query counter exhausted");
        }
        constexpr char domain[] = "PQDID-Ligetron-RNG-EXP1/query";
        std::array<uint8_t, 8> counter{};
        for (size_t i = 0; i < counter.size(); ++i) {
            counter[counter.size() - 1 - i] =
                static_cast<uint8_t>(state_ >> (8 * i));
        }
        Hasher h;
        h << byte_view{reinterpret_cast<const uint8_t*>(domain),
                       sizeof(domain) - 1};
        h << seed_;
        h << byte_view{counter.data(), counter.size()};
        buffer_ = h.flush_digest();
        if (state_ == std::numeric_limits<uint64_t>::max()) {
            exhausted_ = true;
        } else {
            ++state_;
        }
        offset_ = 0;
    }

    seed_type seed_{};
    seed_type buffer_{};
    uint64_t state_ = 0;
    size_t offset_ = cycle_size;
    bool exhausted_ = false;
};

struct zero_dist {
    static constexpr bool enabled = false;

    template <typename... Args>
    zero_dist(Args&&...) { }

    template <typename... Args>
    void init(Args&&...) { }
    
    auto operator()() const noexcept { return 0; }
};

struct one_dist {
    using seed_type = hash_random_engine<sha256>;
    static constexpr bool enabled = true;

    template <typename... Args>
    one_dist(Args&&...) { }

    template <typename... Args>
    void init(Args&&...) { }
    
    auto operator()() const noexcept { return 1; }
};

template <typename T, typename Engine = hash_random_engine<sha256>>
struct hash_random_dist {
    using seed_type = typename Engine::seed_type;
    static constexpr bool enabled = true;

    hash_random_dist(T modulus, const typename Engine::seed_type& seed)
        : engine_(seed), dist_(T{0}, modulus - T{1}) { }

    T operator()() {
        // auto t = make_timer("Random", "HashDistribution");
        return dist_(engine_);
        // return 0ULL;
    }

    Engine engine_;
    std::uniform_int_distribution<T> dist_;
};

template <typename T = uint64_t>
struct aes256ctr {
    static constexpr bool enabled = true;

    aes256ctr() = default;
    
    template <typename Key, typename IV>
    aes256ctr(T modulus, Key& key, IV& iv) {
        init(modulus, key, iv);
    }

    template <typename Key, typename IV>
    void init(T modulus, Key& key, IV& iv) {
        modulus_ = modulus;
        mask_ = std::bit_ceil<T>(modulus) - 1;
        engine_.init(key, iv);
    }

    T operator()() {
        T rand = engine_() & mask_;
        if (rand >= modulus_)
            rand -= modulus_;
        
        return rand;
    }

protected:
    T modulus_, mask_;
    aes256ctr_engine<T> engine_;
};

template <typename Ring>
struct aes256ctr_ring {
    static constexpr bool enabled = true;

    aes256ctr_ring() = default;
    
    template <typename Key, typename IV>
    aes256ctr_ring(Key& key, IV& iv) {
        init(key, iv);
    }

    template <typename Key, typename IV>
    void init(Key& key, IV& iv) {
        for (size_t limb = 0; limb < Ring::num_limbs; limb++) {
            mask_[limb] = std::bit_ceil(Ring::modulus[limb]) - 1;
        }
        engine_.init(key, iv);
    }

    Ring operator()() {
        Ring r;
        for (size_t limb = 0; limb < Ring::num_limbs; limb++) {
            auto rand = engine_() & mask_[limb];
            r[limb] = (rand < Ring::modulus[limb]) ? rand : (rand - Ring::modulus[limb]);
        }
        return r;
    }

protected:
    uint64_t mask_[Ring::num_limbs];
    aes256ctr_engine<uint64_t> engine_;
};


// ------------------------------------------------------------


template <typename Fp, size_t NumBits = 252>
struct aes256ctr_gmp {
    static constexpr bool enabled = true;
    static constexpr size_t num_limbs = (NumBits + 63) / 64;
    static constexpr size_t leading_bits = NumBits % 64;

    aes256ctr_gmp() = default;
    
    template <typename Key, typename IV>
    aes256ctr_gmp(Key& key, IV& iv) {
        init(key, iv);
    }

    template <typename Key, typename IV>
    void init(Key& key, IV& iv) {
        engine_.init(key, iv);
    }

    Fp& operator()() {
        auto *buf = engine_(num_limbs);
        tmp.from_limbs(buf);
        Fp::reduce_u256(tmp.data(), tmp.data());
        // mpz_import(tmp.data().get_mpz_t(), num_limbs, -1, sizeof(uint64_t), 0, 0, buf);
        // tmp.reduce_u256();
        return tmp;
    }

protected:
    Fp tmp;
    aes256ctr_engine<uint64_t> engine_;
};


struct random_seeds {
    unsigned int linear;
    unsigned int quadratic_left, quadratic_right, quadratic_out;
};

}  // namespace ligero::zkp
