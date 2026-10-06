// Public synthetic fixture loader into the actual pinned libiop R1CS.
// No prover, FFT, commitment, transcript or private authentication allocation.
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <libff/algebra/fields/binary/gf192.hpp>
#include <libiop/relations/r1cs.hpp>

using F = libff::gf192;
using LC = libiop::linear_combination<F>;
using CS = libiop::r1cs_constraint_system<F>;

static void require(bool condition, const char *reason) {
    if (!condition) throw std::invalid_argument(reason);
}
static std::string bytes(std::istream &in, std::size_t count) {
    std::string out(count, '\0');
    require(bool(in.read(&out[0], count)), "truncated");
    return out;
}
static std::uint32_t u32(std::istream &in) {
    const auto raw = bytes(in, 4);
    std::uint32_t value = 0;
    for (const unsigned char c : raw) value = (value << 8) | c;
    return value;
}
static F fe(std::istream &in) {
    const auto raw = bytes(in, 24);
    std::uint64_t limbs[3] = {0, 0, 0};
    for (std::size_t i = 0; i < 24; ++i)
        limbs[i / 8] |= std::uint64_t(static_cast<unsigned char>(raw[i])) << (8 * (i % 8));
    return F(limbs[2], limbs[1], limbs[0]);
}
static std::string hex(const std::string &raw) {
    std::ostringstream out;
    for (const unsigned char c : raw) out << std::hex << std::setw(2) << std::setfill('0') << unsigned(c);
    return out.str();
}
static std::string hex(const F &value) {
    auto words = value.to_words();
    std::ostringstream out;
    for (std::size_t i = 3; i > 0; --i)
        out << std::hex << std::setw(16) << std::setfill('0') << words[i - 1];
    return out.str();
}
static LC linear(std::istream &in, std::uint32_t variables, std::size_t &total) {
    const auto count = u32(in);
    require(count <= 4096 && total + count <= 65536, "term-bound");
    LC result;
    result.terms.reserve(count);
    std::uint32_t previous = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto column = u32(in);
        const auto coefficient = fe(in);
        require(column <= variables, "column-range");
        require(i == 0 || column > previous, "column-order-or-duplicate");
        require(!coefficient.is_zero(), "zero-coefficient");
        result.add_term(libiop::variable<F>(column), coefficient);
        previous = column;
    }
    total += count;
    return result; // canonical validated terms; empty sum is the zero polynomial
}
static void array(const std::vector<F> &values) {
    std::cout << '[';
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i) std::cout << ',';
        std::cout << '"' << hex(values[i]) << '"';
    }
    std::cout << ']';
}

int main(int argc, char **argv) {
    try {
        require(argc == 3, "arguments");
        std::ifstream in(argv[1], std::ios::binary | std::ios::ate);
        require(bool(in), "input-open");
        const auto length = in.tellg();
        require(length >= 0 && length <= 1048576, "input-bound");
        in.seekg(0);
        require(bytes(in, 8) == "PQR1C001", "magic");
        require(hex(bytes(in, 32)) == argv[2], "public-identity");
        const auto variables = u32(in), primary = u32(in), rows = u32(in);
        const auto primary_count = u32(in), auxiliary_count = u32(in);
        require(variables >= 1 && variables <= 4096 && rows <= 256, "dimension-bound");
        require(primary == 1 && primary_count == primary, "primary-length");
        require(auxiliary_count == variables - primary, "auxiliary-length");
        std::vector<F> pub, aux;
        pub.reserve(primary_count); aux.reserve(auxiliary_count);
        for (std::uint32_t i = 0; i < primary_count; ++i) pub.push_back(fe(in));
        for (std::uint32_t i = 0; i < auxiliary_count; ++i) aux.push_back(fe(in));
        CS system;
        system.primary_input_size_ = primary;
        system.auxiliary_input_size_ = auxiliary_count;
        std::size_t total = 0;
        for (std::uint32_t i = 0; i < rows; ++i) {
            const auto a = linear(in, variables, total);
            const auto b = linear(in, variables, total);
            const auto c = linear(in, variables, total);
            system.add_constraint(libiop::r1cs_constraint<F>(a, b, c));
        }
        require(bytes(in, 4) == "END!" && in.peek() == std::char_traits<char>::eof(), "footer-or-tail");
        // Never invoke the pinned defective linear_combination::is_valid.
        // All dimensions, column bounds, uniqueness and encodings were checked above.
        const auto A = system.A_matrix(), B = system.B_matrix(), C = system.C_matrix();
        require(A.size() == rows && B.size() == rows && C.size() == rows, "matrix-shape");
        std::size_t sparse_terms = 0;
        for (std::size_t i = 0; i < rows; ++i) sparse_terms += A[i].size() + B[i].size() + C[i].size();
        require(sparse_terms == total, "matrix-term-loss");
        std::vector<F> full = {F::one()};
        full.insert(full.end(), pub.begin(), pub.end());
        full.insert(full.end(), aux.begin(), aux.end());
        std::vector<F> az, bz, cz;
        system.create_Az_Bz_Cz_from_variable_assignment(full, az, bz, cz);
        const bool satisfied = system.is_satisfied(pub, aux);
        std::cout << "{\"status\":\"loaded\",\"satisfied\":" << (satisfied ? "true" : "false")
                  << ",\"rows\":" << rows << ",\"variables\":" << variables
                  << ",\"nonzero_terms\":" << total << ",\"field_bytes\":" << sizeof(F)
                  << ",\"term_object_bytes\":" << sizeof(libiop::linear_term<F>)
                  << ",\"constraint_object_bytes\":" << sizeof(libiop::r1cs_constraint<F>)
                  << ",\"az\":";
        array(az); std::cout << ",\"bz\":"; array(bz); std::cout << ",\"cz\":"; array(cz);
        std::cout << "}\n";
        return 0;
    } catch (const std::invalid_argument &error) {
        std::cout << "{\"status\":\"rejected\",\"reason\":\"" << error.what() << "\"}\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "incomplete native operation: " << error.what() << '\n';
        return 2;
    }
}
