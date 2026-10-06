// Exact original query routine, renamed for the explicit negative control.
template <ligero::vm::zkp::IsHashScheme Hasher>
struct legacy_query {
    using result_type = uint8_t;
    using seed_type = typename Hasher::digest;
    
    constexpr static int cycle_size = Hasher::digest_size;

    constexpr static result_type min() { return std::numeric_limits<result_type>::min(); }
    constexpr static result_type max() { return std::numeric_limits<result_type>::max(); }

    legacy_query() { }
    // legacy_query(result_type i) { seed(i); }
    // template <typename SeedSeq>
    // legacy_query(SeedSeq seq) { seed(seq); }
    legacy_query(const seed_type& d) : seed_(d) { }

    void seed() {
        state_ = 0;
        offset_ = -1;
        std::fill_n(seed_.begin(), cycle_size, uint8_t{0});
    }

    void seed(const seed_type& d) {
        seed_ = d;
    }

    void discard(size_t i) {
        if (i <= offset_ + 1) {
            offset_ -= i;
        }
        else {
            int32_t remind = i - (offset_ + 1);
            int32_t q = remind / cycle_size, r = remind % cycle_size;

            hash_ << state_ + q - 1;
            buffer_ = hash_.flush_digest();
            hash_ << seed_;
            state_++;
            offset_ = cycle_size - 1 - r;
        }
    }

    result_type operator()() {
        if (offset_ < 0 || offset_ >= cycle_size) {
            hash_ << state_++;
            buffer_ = hash_.flush_digest();
            hash_ << seed_;
            offset_ = cycle_size - 1;
            
        }
        return buffer_.data[offset_--];
    }

protected:
    Hasher hash_;
    typename Hasher::digest seed_;
    typename Hasher::digest buffer_;
    uint64_t state_ = 0;
    int32_t offset_ = -1;
};
