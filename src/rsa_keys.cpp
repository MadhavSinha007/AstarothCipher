#include "rsa_keys.h"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

// Print all pending OpenSSL errors to stderr
void RSAKeyManager::print_openssl_error(const std::string& context) {
    unsigned long err;
    char buf[256];
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << "[OpenSSL] " << context << ": " << buf << "\n";
    }
}

// Generate new RSA key pair with specified bit length
EVP_PKEY_ptr RSAKeyManager::generate_keypair(int bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        throw std::runtime_error("EVP_PKEY_keygen_init failed");

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
        throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        throw std::runtime_error("EVP_PKEY_keygen failed");

    EVP_PKEY_CTX_free(ctx);
    return EVP_PKEY_ptr(pkey);
}

// Save private key to PEM file (encrypted if passphrase provided)
bool RSAKeyManager::save_private_key(EVP_PKEY* key, const std::string& path,
                                      const std::string& passphrase) {
    FILE* fp = fopen(path.c_str(), "wb");
    if (!fp) { std::cerr << "Cannot open " << path << "\n"; return false; }

    int ok;
    if (passphrase.empty()) {
        // No encryption
        ok = PEM_write_PrivateKey(fp, key, nullptr, nullptr, 0, nullptr, nullptr);
    } else {
        // Encrypt with AES-256-CBC
        ok = PEM_write_PrivateKey(fp, key, EVP_aes_256_cbc(),
            reinterpret_cast<const unsigned char*>(passphrase.c_str()),
            static_cast<int>(passphrase.size()), nullptr, nullptr);
    }
    fclose(fp);
    if (!ok) { print_openssl_error("save_private_key"); return false; }
    return true;
}

// Save public key to PEM file (never encrypted)
bool RSAKeyManager::save_public_key(EVP_PKEY* key, const std::string& path) {
    FILE* fp = fopen(path.c_str(), "wb");
    if (!fp) { std::cerr << "Cannot open " << path << "\n"; return false; }
    int ok = PEM_write_PUBKEY(fp, key);
    fclose(fp);
    if (!ok) { print_openssl_error("save_public_key"); return false; }
    return true;
}

// Load private key from PEM file (decrypt if passphrase provided)
EVP_PKEY_ptr RSAKeyManager::load_private_key(const std::string& path,
                                               const std::string& passphrase) {
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) throw std::runtime_error("Cannot open private key: " + path);

    EVP_PKEY* key = nullptr;
    if (passphrase.empty()) {
        key = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    } else {
        key = PEM_read_PrivateKey(fp, nullptr, nullptr,
            const_cast<char*>(passphrase.c_str()));
    }
    fclose(fp);
    if (!key) {
        print_openssl_error("load_private_key");
        throw std::runtime_error("Failed to load private key");
    }
    return EVP_PKEY_ptr(key);
}

// Load public key from PEM file
EVP_PKEY_ptr RSAKeyManager::load_public_key(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) throw std::runtime_error("Cannot open public key: " + path);
    EVP_PKEY* key = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!key) {
        print_openssl_error("load_public_key");
        throw std::runtime_error("Failed to load public key");
    }
    return EVP_PKEY_ptr(key);
}

// Encrypt data with RSA public key using OAEP padding with SHA-256
std::vector<unsigned char> RSAKeyManager::encrypt(
        EVP_PKEY* pub_key, const std::vector<unsigned char>& plaintext) {

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new failed");

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        throw std::runtime_error("EVP_PKEY_encrypt_init failed");

    // Use OAEP padding (more secure than PKCS#1 v1.5)
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        throw std::runtime_error("set_rsa_padding OAEP failed");

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
        throw std::runtime_error("set_rsa_oaep_md failed");

    // First call gets required output size
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext.data(), plaintext.size()) <= 0)
        throw std::runtime_error("EVP_PKEY_encrypt (size query) failed");

    std::vector<unsigned char> out(outlen);
    // Second call actually encrypts
    if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, plaintext.data(), plaintext.size()) <= 0) {
        print_openssl_error("RSA encrypt");
        throw std::runtime_error("EVP_PKEY_encrypt failed");
    }

    EVP_PKEY_CTX_free(ctx);
    out.resize(outlen);
    return out;
}

// Decrypt data with RSA private key using OAEP padding
std::vector<unsigned char> RSAKeyManager::decrypt(
        EVP_PKEY* priv_key, const std::vector<unsigned char>& ciphertext) {

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new failed");

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        throw std::runtime_error("EVP_PKEY_decrypt_init failed");

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        throw std::runtime_error("set_rsa_padding OAEP failed");

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
        throw std::runtime_error("set_rsa_oaep_md failed");

    // First call gets required output size
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0)
        throw std::runtime_error("EVP_PKEY_decrypt (size query) failed");

    std::vector<unsigned char> out(outlen);
    // Second call actually decrypts
    if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        print_openssl_error("RSA decrypt");
        throw std::runtime_error("EVP_PKEY_decrypt failed");
    }

    EVP_PKEY_CTX_free(ctx);
    out.resize(outlen);
    return out;
}