#pragma once
#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rsa.h>

// RAII wrapper so EVP_PKEY is auto-freed
struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
};
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;

class RSAKeyManager {
public:
    // Generate a fresh RSA-4096 key pair
    static EVP_PKEY_ptr generate_keypair(int bits = 4096);

    // Save keys to PEM files
    static bool save_private_key(EVP_PKEY* key, const std::string& path,
                                 const std::string& passphrase = "");
    static bool save_public_key(EVP_PKEY* key, const std::string& path);

    // Load keys from PEM files
    static EVP_PKEY_ptr load_private_key(const std::string& path,
                                          const std::string& passphrase = "");
    static EVP_PKEY_ptr load_public_key(const std::string& path);

    // Encrypt with public key (for wrapping an AES key)
    static std::vector<unsigned char> encrypt(EVP_PKEY* pub_key,
                                               const std::vector<unsigned char>& plaintext);

    // Decrypt with private key
    static std::vector<unsigned char> decrypt(EVP_PKEY* priv_key,
                                               const std::vector<unsigned char>& ciphertext);

    // Print last OpenSSL error
    static void print_openssl_error(const std::string& context);
};