#include "aes_gcm.h"
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// Generate random key using cryptographically secure RNG
SecureVector AESGCMCipher::generate_key(int len) {
    SecureVector k(len);
    if (RAND_bytes(k.data(), len) != 1)
        throw std::runtime_error("RAND_bytes failed for key");
    return k;
}

// Generate random initialization vector (nonce)
SecureVector AESGCMCipher::generate_iv(int len) {
    SecureVector v(len);
    if (RAND_bytes(v.data(), len) != 1)
        throw std::runtime_error("RAND_bytes failed for IV");
    return v;
}

// Encrypt data with AES-256-GCM, produces ciphertext + authentication tag
SecureVector AESGCMCipher::encrypt(
        const SecureVector& plaintext,
        const SecureVector& key,
        const SecureVector& iv,
        SecureVector&       tag_out,
        const SecureVector& aad) {

    // Validate inputs
    if (key.size() != KEY_LEN) throw std::invalid_argument("Key must be 32 bytes");
    if (iv.size()  != IV_LEN)  throw std::invalid_argument("IV must be 12 bytes");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    auto cleanup = [&]{ EVP_CIPHER_CTX_free(ctx); };

    // Initialize encryption context with AES-256-GCM
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        cleanup(); throw std::runtime_error("EncryptInit cipher failed");
    }
    // Set IV length (12 bytes recommended for GCM)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1) {
        cleanup(); throw std::runtime_error("Set IV len failed");
    }
    // Set key and IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        cleanup(); throw std::runtime_error("EncryptInit key/iv failed");
    }

    // Process additional authenticated data (not encrypted, but protected)
    int len = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1) {
            cleanup(); throw std::runtime_error("AAD feed failed");
        }
    }

    // Encrypt the actual data
    SecureVector ciphertext(plaintext.size());
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                plaintext.data(), plaintext.size()) != 1) {
            cleanup(); throw std::runtime_error("EncryptUpdate failed");
        }
        ciphertext.resize(len);
    }

    // Finalize encryption
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len) != 1) {
        cleanup(); throw std::runtime_error("EncryptFinal failed");
    }
    ciphertext.resize(len + final_len);

    // Get authentication tag for later verification
    tag_out.resize(TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag_out.data()) != 1) {
        cleanup(); throw std::runtime_error("Get tag failed");
    }

    cleanup();
    return ciphertext;
}

// Decrypt AES-256-GCM data, verifies tag before returning plaintext
SecureVector AESGCMCipher::decrypt(
        const SecureVector& ciphertext,
        const SecureVector& key,
        const SecureVector& iv,
        const SecureVector& tag,
        const SecureVector& aad) {

    // Validate inputs
    if (key.size() != KEY_LEN) throw std::invalid_argument("Key must be 32 bytes");
    if (iv.size()  != IV_LEN)  throw std::invalid_argument("IV must be 12 bytes");
    if (tag.size() != TAG_LEN) throw std::invalid_argument("Tag must be 16 bytes");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    auto cleanup = [&]{ EVP_CIPHER_CTX_free(ctx); };

    // Initialize decryption context
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        cleanup(); throw std::runtime_error("DecryptInit cipher failed");
    }
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1) {
        cleanup(); throw std::runtime_error("Set IV len failed");
    }
    // Set key and IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        cleanup(); throw std::runtime_error("DecryptInit key/iv failed");
    }

    // Process additional authenticated data (must match encryption)
    int len = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1) {
            cleanup(); throw std::runtime_error("AAD feed failed");
        }
    }

    // Decrypt the ciphertext
    SecureVector plaintext(ciphertext.size());
    if (!ciphertext.empty()) {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                ciphertext.data(), ciphertext.size()) != 1) {
            cleanup(); throw std::runtime_error("DecryptUpdate failed");
        }
    }

    // Set expected authentication tag for verification
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
            const_cast<unsigned char*>(tag.data())) != 1) {
        cleanup(); throw std::runtime_error("Set tag failed");
    }

    // Finalize and verify tag
    int final_len = 0;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len);
    cleanup();

    // Tag mismatch means data was tampered with
    if (ret <= 0)
        throw std::runtime_error("AES-GCM authentication tag mismatch — data integrity failed");

    plaintext.resize(len + final_len);
    return plaintext;
}