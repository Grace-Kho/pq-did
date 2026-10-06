// Proposed public-input checks only. Not compiled or executed in this package.
#include <libff/algebra/fields/binary/gf192.hpp>
#include <libiop/relations/variable.hpp>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>
using F = libff::gf192;
using V = libiop::variable<F>;
using T = libiop::linear_term<F>;
using C = libiop::linear_combination<F>;
void require(bool value) {
    if (!value) throw std::runtime_error("semantic mismatch");
}
int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::runtime_error("one literal case required");
        const int n = std::atoi(argv[1]);
        switch (n) {
        case 1: require(V(0) == V(0)); break;
        case 2: require(!(V(3) == V(4))); break;
        case 3: {
            const T original(V(3), F(2));
            const T scaled = original * F(3);
            // Polynomial bits: x*(x+1)=x^2+x=0x6; no modular reduction.
            require(scaled.index_ == 3 && scaled.coeff_ == F(6));
            require(original.index_ == 3 && original.coeff_ == F(2));
            require(C(scaled).evaluate({F(4), F(5), F(1)}) == F(6));
            break;
        }
        case 4: {
            const T original(V(0), F(2));
            const T scaled = original * F(0);
            require(scaled.index_ == 0 && scaled.coeff_ == F(0));
            require(original.index_ == 0 && original.coeff_ == F(2));
            require(C(scaled).evaluate({}) == F(0));
            break;
        }
        case 5: {
            const T original(V(3), F(2));
            const T negative = -original;
            // GF(2^192) has characteristic two; -x=x, not an odd-prime test.
            require(negative.index_ == 3 && negative.coeff_ == F(2));
            require(original.index_ == 3 && original.coeff_ == F(2));
            require(C(negative).evaluate({F(4), F(5), F(1)}) == F(2));
            break;
        }
        case 6: require(T(V(3), F(2)) == T(V(3), F(2))); break;
        case 7: require(!(T(V(3), F(2)) == T(V(4), F(2)))); break;
        case 8: require(!(T(V(3), F(2)) == T(V(3), F(3)))); break;
        default: throw std::runtime_error("unlisted semantic case");
        }
        std::cout << "SEM-" << n << " pass\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\n";
        return 1;
    }
}
