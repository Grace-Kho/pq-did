cmake_minimum_required(VERSION 3.16)
project(pqdid_auth_relation_adapter LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
get_filename_component(PQ_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
set(PQ_RETAINED "${PQ_ROOT}/experiments/aurora_masking_milestone_1")
set(PQ_PREFIX "${PQ_ROOT}/experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1/prefix")
add_executable(relation_adapter relation_adapter.cpp)
target_compile_definitions(relation_adapter PRIVATE NO_PROCPS CURVE_ALT_BN128)
target_include_directories(relation_adapter PRIVATE
  "${PQ_RETAINED}/work/libiop" "${PQ_RETAINED}/work/libff"
  "${PQ_RETAINED}/work/libfqfft" "${PQ_PREFIX}/usr/include"
  "${PQ_PREFIX}/usr/include/x86_64-linux-gnu")
target_link_libraries(relation_adapter PRIVATE
  "${PQ_RETAINED}/build/libiop_native.a"
  "${PQ_RETAINED}/build/libff-build/libff/libff.a"
  "${PQ_PREFIX}/usr/lib/x86_64-linux-gnu/libsodium.a"
  "${PQ_PREFIX}/usr/lib/x86_64-linux-gnu/libgmp.a")
