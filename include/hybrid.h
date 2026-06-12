#pragma once
#include "rsa_keys.h"
#include "aes_gcm.h"
#include <string>
#include <vector>
#include <cstdint>

/*
  Bundle file format:
  [4 bytes "HCRY" magic] [1 byte version]
  [4 bytes key length] [RSA-encrypted AES key]
  [12 bytes IV] [16 bytes GCM tag]
  [8 bytes ciphertext length] [ciphertext]
*/

// Container for hybrid encrypted data (RSA + AES-GCM)
struct HybridBundle {
    std::vector<unsigned char> enc_aes_key;  // RSA-encrypted AES key
    std::vector<unsigned char> iv;           // Initialization vector for AES
    std::vector<unsigned char> tag;          // GCM authentication tag
    std::vector<unsigned char> ciphertext;   // Actual encrypted data

    bool save(const std::string& path) const;  // Write bundle to file
    bool load(const std::string& path);        // Read bundle from file
};

// Hybrid encryption: RSA for key exchange, AES-GCM for data
class HybridCrypto {
public:
    // Encrypt data with recipient's public key
    static HybridBundle encrypt(const std::vector<unsigned char>& plaintext,
                                EVP_PKEY* pub_key);

    // Decrypt bundle using your private key
    static std::vector<unsigned char> decrypt(const HybridBundle& bundle,
                                              EVP_PKEY* priv_key);

    // Encrypt entire file (large data friendly)
    static bool encrypt_file(const std::string& input_path,
                             const std::string& output_path,
                             EVP_PKEY* pub_key);

    // Decrypt file back to original
    static bool decrypt_file(const std::string& bundle_path,
                             const std::string& output_path,
                             EVP_PKEY* priv_key);
};