#pragma once

// Isolated, uncompiled source continuation. Does not establish proof admission.
#include <array>
#include <cstdint>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <zlib.h>

namespace ligero::vm::zkp::bounded_io_exp1 {

inline constexpr std::size_t config_limit = 65536;
inline constexpr std::size_t program_limit = 1048576;
inline constexpr std::size_t compressed_limit = 8388608;
inline constexpr std::size_t envelope_limit = 16777216;

inline std::string_view config_view(const char* text) {
    if (!text) throw std::runtime_error("Missing JSON configuration");
    std::size_t n = 0;
    while (n <= config_limit && text[n] != '\0') ++n;
    if (n > config_limit) throw std::runtime_error("JSON configuration exceeds limit");
    return {text, n};
}

inline std::vector<std::uint8_t> read_file(const std::string& path, std::size_t limit) {
    // Read through the same open handle; a file-size check alone would race.
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("Cannot open bounded input");
    std::vector<std::uint8_t> result;
    std::array<char, 16384> block{};
    while (true) {
        input.read(block.data(), static_cast<std::streamsize>(block.size()));
        const auto n = static_cast<std::size_t>(input.gcount());
        if (result.size() > limit || n > limit - result.size())
            throw std::runtime_error("Input exceeds byte limit");
        result.insert(result.end(), block.data(), block.data() + n);
        if (input.bad()) throw std::runtime_error("Bounded input read failed");
        if (input.eof()) break;
        if (input.fail()) throw std::runtime_error("Incomplete bounded input read");
    }
    return result;
}

inline std::string inflate_one_gzip(const std::vector<std::uint8_t>& compressed) {
    if (compressed.empty() || compressed.size() > compressed_limit ||
        compressed.size() > std::numeric_limits<uInt>::max())
        throw std::runtime_error("Invalid compressed proof size");
    z_stream stream{};
    if (inflateInit2(&stream, 15 + 16) != Z_OK)
        throw std::runtime_error("Cannot initialise gzip decoder");
    struct End {
        z_stream* stream;
        ~End() { inflateEnd(stream); }
    } end{&stream};
    stream.next_in = const_cast<Bytef*>(compressed.data());
    stream.avail_in = static_cast<uInt>(compressed.size());
    std::array<unsigned char, 16384> block{};
    std::string output;
    for (;;) {
        const auto before = stream.avail_in;
        stream.next_out = block.data();
        stream.avail_out = static_cast<uInt>(block.size());
        const int status = inflate(&stream, Z_NO_FLUSH);
        const auto produced = block.size() - stream.avail_out;
        if (output.size() > envelope_limit || produced > envelope_limit - output.size())
            throw std::runtime_error("Decompressed proof exceeds limit");
        output.append(reinterpret_cast<const char*>(block.data()), produced);
        if (status == Z_STREAM_END) {
            if (stream.avail_in != 0)
                throw std::runtime_error("Trailing bytes or multiple gzip members");
            return output;
        }
        if (status != Z_OK || (produced == 0 && stream.avail_in == before))
            throw std::runtime_error("Invalid or truncated gzip proof");
    }
}

} // namespace ligero::vm::zkp::bounded_io_exp1
