#pragma once
#include "secure_alloc.h"
#include <string>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rsa.h>

// Custom deleter for EVP_PKEY to work with unique_ptr
struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
};

// Smart pointer type for automatic EVP_PKEY memory management
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;

// Manages RSA key operations including generation, file I/O, and encryption/decryption
class RSAKeyManager {
public:
    // Creates a new RSA key pair with specified bit length (default 4096)
    // Returns smart pointer to the key pair, or nullptr on failure
    static EVP_PKEY_ptr generate_keypair(int bits = 4096);

    // Writes private key to file in PEM format
    // Optionally encrypts with passphrase (empty = no encryption)
    // Returns true if successful, false otherwise
    static bool save_private_key(EVP_PKEY* key, const std::string& path,
                                 const std::string& passphrase = "");
    
    // Writes public key to file in PEM format
    // Returns true if successful, false otherwise
    static bool save_public_key(EVP_PKEY* key, const std::string& path);

    // Reads private key from PEM file
    // Passphrase required if key is encrypted, empty string if not
    // Returns smart pointer to private key, or nullptr on failure
    static EVP_PKEY_ptr load_private_key(const std::string& path,
                                          const std::string& passphrase = "");
    
    // Reads public key from PEM file
    // Returns smart pointer to public key, or nullptr on failure
    static EVP_PKEY_ptr load_public_key(const std::string& path);

    // Encrypts data using RSA public key
    // Returns encrypted data as securely wiped byte vector, empty on failure
    static SecureVector encrypt(EVP_PKEY* pub_key,
                                const SecureVector& plaintext);
    
    // Decrypts data using RSA private key
    // Returns decrypted data as securely wiped byte vector, empty on failure
    static SecureVector decrypt(EVP_PKEY* priv_key,
                                const SecureVector& ciphertext);

    // Outputs OpenSSL error stack information to stderr with context prefix
    static void print_openssl_error(const std::string& context);
};