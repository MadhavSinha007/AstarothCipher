#include "hybrid.h"
#include <stdexcept>
#include <cstring>
#include <vector>

// RAII Deleter for OpenSSL Cipher Contexts
struct EVP_CIPHER_CTX_Deleter {
    void operator()(EVP_CIPHER_CTX* ctx) const { if (ctx) EVP_CIPHER_CTX_free(ctx); }
};
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;

// ── Helper functions for byte arrays (memory-only) ─────────

static void vec_push_u32(SecureVector& v, uint32_t n) {
    v.push_back(static_cast<unsigned char>((n >> 24) & 0xFF));
    v.push_back(static_cast<unsigned char>((n >> 16) & 0xFF));
    v.push_back(static_cast<unsigned char>((n >>  8) & 0xFF));
    v.push_back(static_cast<unsigned char>( n        & 0xFF));
}

static void vec_push_u64(SecureVector& v, uint64_t n) {
    unsigned char b[8];
    for (int i = 7; i >= 0; --i) { b[i] = n & 0xFF; n >>= 8; }
    v.insert(v.end(), b, b + 8);
}

static uint32_t vec_read_u32(const SecureVector& v, size_t& pos) {
    if (pos + 4 > v.size()) throw std::runtime_error("Buffer underflow reading u32");
    uint32_t n = ((uint32_t)v[pos]<<24)|((uint32_t)v[pos+1]<<16)
               |((uint32_t)v[pos+2]<<8)|(uint32_t)v[pos+3];
    pos += 4; return n;
}

static uint64_t vec_read_u64(const SecureVector& v, size_t& pos) {
    if (pos + 8 > v.size()) throw std::runtime_error("Buffer underflow reading u64");
    uint64_t n = 0;
    for (int i = 0; i < 8; ++i) n = (n << 8) | v[pos++];
    return n;
}

// ── Main encryption/decryption logic ────────────────────────────────────────

HybridBundle HybridCrypto::encrypt(const SecureVector& plaintext, EVP_PKEY* pub_key) {
    auto aes_key = AESGCMCipher::generate_key();  // 256-bit key
    auto iv      = AESGCMCipher::generate_iv();   // 96-bit nonce

    SecureVector tag;
    auto ciphertext = AESGCMCipher::encrypt(plaintext, aes_key, iv, tag);

    auto enc_aes_key = RSAKeyManager::encrypt(pub_key, aes_key);

    return HybridBundle{ enc_aes_key, iv, tag, ciphertext };
}

SecureVector HybridCrypto::decrypt(const HybridBundle& bundle, EVP_PKEY* priv_key) {
    auto aes_key = RSAKeyManager::decrypt(priv_key, bundle.enc_aes_key);
    return AESGCMCipher::decrypt(bundle.ciphertext, aes_key, bundle.iv, bundle.tag);
}

SecureVector HybridBundle::to_bytes() const {
    SecureVector buf;
    
    buf.insert(buf.end(), {'H','C','R','Y'});
    buf.push_back(0x01);
    
    vec_push_u32(buf, static_cast<uint32_t>(enc_aes_key.size()));
    buf.insert(buf.end(), enc_aes_key.begin(), enc_aes_key.end());
    
    buf.insert(buf.end(), iv.begin(), iv.end());
    buf.insert(buf.end(), tag.begin(), tag.end());
    
    vec_push_u64(buf, static_cast<uint64_t>(ciphertext.size()));
    buf.insert(buf.end(), ciphertext.begin(), ciphertext.end());
    
    return buf;
}

HybridBundle HybridBundle::from_bytes(const SecureVector& data) {
    size_t pos = 0;
    if (data.size() < 4 || memcmp(data.data(), "HCRY", 4) != 0) 
        throw std::runtime_error("Invalid bundle: missing magic signature");
    pos += 4;
    
    if (pos >= data.size() || data[pos] != 0x01)
        throw std::runtime_error("Invalid bundle version");
    pos += 1;

    HybridBundle b;
    uint32_t k_len = vec_read_u32(data, pos);
    if (pos + k_len > data.size()) throw std::runtime_error("Buffer underflow reading key");
    b.enc_aes_key.assign(data.begin() + pos, data.begin() + pos + k_len);
    pos += k_len;

    if (pos + AESGCMCipher::IV_LEN > data.size()) throw std::runtime_error("Buffer underflow reading IV");
    b.iv.assign(data.begin() + pos, data.begin() + pos + AESGCMCipher::IV_LEN);
    pos += AESGCMCipher::IV_LEN;
    
    if (pos + AESGCMCipher::TAG_LEN > data.size()) throw std::runtime_error("Buffer underflow reading tag");
    b.tag.assign(data.begin() + pos, data.begin() + pos + AESGCMCipher::TAG_LEN);
    pos += AESGCMCipher::TAG_LEN;

    uint64_t ct_len = vec_read_u64(data, pos);
    if (pos + ct_len > data.size()) throw std::runtime_error("Buffer underflow reading ciphertext");
    b.ciphertext.assign(data.begin() + pos, data.begin() + pos + ct_len);
    
    return b;
}