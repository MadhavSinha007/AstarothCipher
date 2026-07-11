#include "rsa_keys.h"
#include <stdexcept>
#include <cstdio>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

void RSAKeyManager::print_openssl_error(const std::string& context) {
    unsigned long err;
    char buf[256];
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        printf("[OpenSSL] %s: %s\n", context.c_str(), buf);
    }
}

std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> RSAKeyManager::load_public_key_from_string(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return {pkey, EVP_PKEY_free};
}

std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> RSAKeyManager::load_private_key_from_string(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return {pkey, EVP_PKEY_free};
}

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

SecureVector RSAKeyManager::encrypt(EVP_PKEY* pub_key, const SecureVector& plaintext) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new failed");

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        throw std::runtime_error("EVP_PKEY_encrypt_init failed");

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        throw std::runtime_error("set_rsa_padding OAEP failed");

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
        throw std::runtime_error("set_rsa_oaep_md failed");

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext.data(), plaintext.size()) <= 0)
        throw std::runtime_error("EVP_PKEY_encrypt (size query) failed");

    SecureVector out(outlen);
    if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, plaintext.data(), plaintext.size()) <= 0) {
        print_openssl_error("RSA encrypt");
        throw std::runtime_error("EVP_PKEY_encrypt failed");
    }

    EVP_PKEY_CTX_free(ctx);
    out.resize(outlen);
    return out;
}

SecureVector RSAKeyManager::decrypt(EVP_PKEY* priv_key, const SecureVector& ciphertext) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new failed");

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        throw std::runtime_error("EVP_PKEY_decrypt_init failed");

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        throw std::runtime_error("set_rsa_padding OAEP failed");

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
        throw std::runtime_error("set_rsa_oaep_md failed");

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0)
        throw std::runtime_error("EVP_PKEY_decrypt (size query) failed");

    SecureVector out(outlen);
    if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        print_openssl_error("RSA decrypt");
        throw std::runtime_error("EVP_PKEY_decrypt failed");
    }

    EVP_PKEY_CTX_free(ctx);
    out.resize(outlen);
    return out;
}