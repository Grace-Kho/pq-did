#include <iostream>

extern "C" int pqdid_check_native_backend(void);

int main() {
    const int result = pqdid_check_native_backend();
    if (result != 0) {
        std::cerr << "C/C++ liboqs backend check failed\n";
        return result;
    }
    std::cout << "C11/C++17 linkage and liboqs ML-DSA-65 metadata/context support: OK\n";
    return 0;
}
