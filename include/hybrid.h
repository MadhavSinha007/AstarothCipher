#pragma once

#include "rsa_keys.h"
#include "aes_gcm.h"
#include "secure_alloc.h"
#include <string>
#include <cstdint>


struct HybridBundle {

    // AES key encrypted using the recipient's RSA public key.
    SecureVector enc_aes_key;

    // Initialization Vector used for AES-GCM encryption.
    SecureVector iv;

    // Authentication tag used to verify data integrity.
    SecureVector tag;

    // The encrypted data.
    SecureVector ciphertext;

    // Save the bundle to a file.
    bool save(const std::string& path) const;

    // Load the bundle from a file.
    bool load(const std::string& path);
};


class HybridCrypto {
public:

    // Encrypt plaintext using a randomly generated AES key,
    // then encrypt the AES key with the RSA public key.
    static HybridBundle encrypt(const SecureVector& plaintext,
                                EVP_PKEY* pub_key);

    // Decrypt the AES key using the RSA private key,
    // then decrypt the ciphertext using AES-GCM.
    static SecureVector decrypt(const HybridBundle& bundle,
                                EVP_PKEY* priv_key);

    // Encrypt a single file.
    static bool encrypt_file(const std::string& input_path,
                             const std::string& output_path,
                             EVP_PKEY* pub_key);

    // Decrypt a previously encrypted file.
    static bool decrypt_file(const std::string& bundle_path,
                             const std::string& output_path,
                             EVP_PKEY* priv_key);

    // Compress and encrypt an entire folder.
    static bool encrypt_folder(const std::string& folder_path,
                               const std::string& output_path,
                               EVP_PKEY* pub_key);

    // Decrypt and extract an encrypted folder.
    static bool decrypt_folder(const std::string& bundle_path,
                               const std::string& output_dir,
                               EVP_PKEY* priv_key);
};