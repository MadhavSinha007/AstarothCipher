cmake_minimum_required(VERSION 3.16)
project(HybridCrypto VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)

find_package(OpenSSL REQUIRED)
include_directories(include)

add_library(hybrid_crypto_lib STATIC
    src/rsa_keys.cpp
    src/aes_gcm.cpp
    src/hybrid.cpp
)
target_link_libraries(hybrid_crypto_lib OpenSSL::SSL OpenSSL::Crypto)

add_executable(hybrid_crypto src/main.cpp)
target_link_libraries(hybrid_crypto hybrid_crypto_lib)

add_executable(test_rsa    tests/test_rsa.cpp)
add_executable(test_aes    tests/test_aes.cpp)
add_executable(test_hybrid tests/test_hybrid.cpp)

target_link_libraries(test_rsa    hybrid_crypto_lib)
target_link_libraries(test_aes    hybrid_crypto_lib)
target_link_libraries(test_hybrid hybrid_crypto_lib)

enable_testing()
add_test(NAME RSA_Test    COMMAND test_rsa)
add_test(NAME AES_Test    COMMAND test_aes)
add_test(NAME Hybrid_Test COMMAND test_hybrid)