#pragma once
#include "secure_alloc.h"
#include <string>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rsa.h>

struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
};

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;

class RSAKeyManager {
public:
    static EVP_PKEY_ptr generate_keypair(int bits = 4096);
    static std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> load_public_key_from_string(const std::string& pem);
    static std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> load_private_key_from_string(const std::string& pem);
    
    static SecureVector encrypt(EVP_PKEY* pub_key, const SecureVector& plaintext);
    static SecureVector decrypt(EVP_PKEY* priv_key, const SecureVector& ciphertext);
    
    static void print_openssl_error(const std::string& context);
};