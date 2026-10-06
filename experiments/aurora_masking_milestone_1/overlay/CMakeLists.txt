# Proposal only: not configured or executed. Harness/patch is implemented later.
cmake_minimum_required(VERSION 3.5)
project(pqdid_masking_native LANGUAGES C CXX)
set(PQ_HARNESS "${CMAKE_CURRENT_SOURCE_DIR}/exp2_native.cpp")
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(IS_LIBFF_PARENT OFF CACHE BOOL "" FORCE)
set(IS_LIBFQFFT_PARENT OFF CACHE BOOL "" FORCE)
set(CURVE ALT_BN128 CACHE STRING "" FORCE)
set(WITH_PROCPS OFF CACHE BOOL "" FORCE)
set(MULTICORE OFF CACHE BOOL "" FORCE)
set(USE_ASM OFF CACHE BOOL "" FORCE)
set(PERFORMANCE OFF CACHE BOOL "" FORCE)
set(GMP_INCLUDE_DIR "${PQ_PREFIX}/usr/include/x86_64-linux-gnu" CACHE PATH "" FORCE)
set(GMP_LIBRARY "${PQ_PREFIX}/usr/lib/x86_64-linux-gnu/libgmp.a" CACHE FILEPATH "" FORCE)
set(SODIUM_INCLUDE_DIR "${PQ_PREFIX}/usr/include" CACHE PATH "" FORCE)
set(SODIUM_LIBRARY "${PQ_PREFIX}/usr/lib/x86_64-linux-gnu/libsodium.a" CACHE FILEPATH "" FORCE)
add_subdirectory("${PQ_SOURCE}/libff" libff-build)
add_library(iop_native STATIC
  "${PQ_SOURCE}/libiop/libiop/common/common.cpp"
  "${PQ_SOURCE}/libiop/libiop/bcs/hashing/blake2b.cpp"
  "${PQ_SOURCE}/libiop/libiop/protocols/ldt/ldt_reducer.cpp"
  "${PQ_SOURCE}/libiop/libiop/protocols/ldt/fri/fri_ldt.cpp"
  "${PQ_SOURCE}/libiop/libiop/protocols/ldt/fri/fri_aux.cpp"
  "${PQ_SOURCE}/libiop/libiop/relations/sparse_matrix.cpp"
  "${PQ_SOURCE}/libiop/libiop/iop/utilities/batching.cpp"
  "${PQ_SOURCE}/libiop/libiop/algebra/utils.cpp")
target_include_directories(iop_native PUBLIC
  "${PQ_SOURCE}/libiop" "${PQ_SOURCE}/libff" "${PQ_SOURCE}/libfqfft")
target_link_libraries(iop_native PUBLIC ff "${SODIUM_LIBRARY}")
target_compile_definitions(iop_native PUBLIC NO_PROCPS CURVE_ALT_BN128)
add_executable(exp2_native "${PQ_HARNESS}")
target_link_libraries(exp2_native PRIVATE iop_native)

# Build-only correction: omit unrelated elliptic-curve implementations.
# Retain all five pinned binary fields and the pinned common support sources.
set_property(TARGET ff PROPERTY SOURCES
  "${PQ_SOURCE}/libff/libff/algebra/fields/binary/gf32.cpp"
  "${PQ_SOURCE}/libff/libff/algebra/fields/binary/gf64.cpp"
  "${PQ_SOURCE}/libff/libff/algebra/fields/binary/gf128.cpp"
  "${PQ_SOURCE}/libff/libff/algebra/fields/binary/gf192.cpp"
  "${PQ_SOURCE}/libff/libff/algebra/fields/binary/gf256.cpp"
  "${PQ_SOURCE}/libff/libff/common/double.cpp"
  "${PQ_SOURCE}/libff/libff/common/profiling.cpp"
  "${PQ_SOURCE}/libff/libff/common/utils.cpp")

# Only this public test target exposes deterministic coefficient fixtures.
add_executable(aurora_masking_native "${CMAKE_CURRENT_SOURCE_DIR}/masking_native.cpp")
target_compile_definitions(aurora_masking_native PRIVATE PQ_MASKING_PUBLIC_FIXTURES)
target_link_libraries(aurora_masking_native PRIVATE iop_native)
