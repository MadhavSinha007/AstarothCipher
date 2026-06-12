#include "hybrid.h"
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <cstring>

// Helper: Write 32-bit unsigned integer in big-endian format
static void write_u32_be(std::ostream& os, uint32_t v) {
    unsigned char b[4] = {(unsigned char)(v>>24),(unsigned char)(v>>16),
                          (unsigned char)(v>>8), (unsigned char)(v)};
    os.write(reinterpret_cast<char*>(b), 4);
}

// Helper: Write 64-bit unsigned integer in big-endian format
static void write_u64_be(std::ostream& os, uint64_t v) {
    unsigned char b[8];
    for (int i = 7; i >= 0; --i) { b[i] = v & 0xFF; v >>= 8; }
    os.write(reinterpret_cast<char*>(b), 8);
}

// Helper: Read 32-bit unsigned integer from big-endian stream
static uint32_t read_u32_be(std::istream& is) {
    unsigned char b[4]; is.read(reinterpret_cast<char*>(b), 4);
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
}

// Helper: Read 64-bit unsigned integer from big-endian stream
static uint64_t read_u64_be(std::istream& is) {
    unsigned char b[8]; is.read(reinterpret_cast<char*>(b), 8);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v<<8) | b[i];
    return v;
}

// File format identifiers
static const char MAGIC[4] = {'H','C','R','Y'};
static const unsigned char VERSION = 0x01;

// Save encrypted bundle to file with proper format
bool HybridBundle::save(const std::string& path) const {
    std::ofstream f(path, std::ios::binary);
    if (!f) { std::cerr << "Cannot write: " << path << "\n"; return false; }

    // Write header
    f.write(MAGIC, 4);
    f.put(static_cast<char>(VERSION));
    
    // Write encrypted AES key with length prefix
    write_u32_be(f, static_cast<uint32_t>(enc_aes_key.size()));
    f.write(reinterpret_cast<const char*>(enc_aes_key.data()), enc_aes_key.size());
    
    // Write IV and authentication tag (fixed sizes)
    f.write(reinterpret_cast<const char*>(iv.data()),  iv.size());
    f.write(reinterpret_cast<const char*>(tag.data()), tag.size());
    
    // Write ciphertext with length prefix
    write_u64_be(f, static_cast<uint64_t>(ciphertext.size()));
    f.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    
    return f.good();
}

// Load encrypted bundle from file and validate format
bool HybridBundle::load(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "Cannot read: " << path << "\n"; return false; }

    // Verify magic bytes
    char magic[4]; f.read(magic, 4);
    if (memcmp(magic, MAGIC, 4) != 0)
        throw std::runtime_error("Not a valid HCRY bundle (magic mismatch)");

    // Check version compatibility
    unsigned char ver = static_cast<unsigned char>(f.get());
    if (ver != VERSION)
        throw std::runtime_error("Unsupported bundle version");

    // Read encrypted AES key
    uint32_t key_len = read_u32_be(f);
    enc_aes_key.resize(key_len);
    f.read(reinterpret_cast<char*>(enc_aes_key.data()), key_len);

    // Read IV and tag (fixed sizes)
    iv.resize(AESGCMCipher::IV_LEN);
    f.read(reinterpret_cast<char*>(iv.data()), AESGCMCipher::IV_LEN);

    tag.resize(AESGCMCipher::TAG_LEN);
    f.read(reinterpret_cast<char*>(tag.data()), AESGCMCipher::TAG_LEN);

    // Read ciphertext
    uint64_t ct_len = read_u64_be(f);
    ciphertext.resize(ct_len);
    f.read(reinterpret_cast<char*>(ciphertext.data()), ct_len);
    
    return f.good();
}

// Hybrid encryption: generate AES key, encrypt data with AES, encrypt AES key with RSA
HybridBundle HybridCrypto::encrypt(const std::vector<unsigned char>& plaintext,
                                    EVP_PKEY* pub_key) {
    auto aes_key = AESGCMCipher::generate_key();  // Random AES-256 key
    auto iv      = AESGCMCipher::generate_iv();   // Random IV
    
    std::vector<unsigned char> tag;
    auto ciphertext = AESGCMCipher::encrypt(plaintext, aes_key, iv, tag);  // AES encrypt
    auto enc_aes_key = RSAKeyManager::encrypt(pub_key, aes_key);           // RSA encrypt key

    return HybridBundle{ enc_aes_key, iv, tag, ciphertext };
}

// Hybrid decryption: decrypt AES key with RSA, then decrypt data with AES
std::vector<unsigned char> HybridCrypto::decrypt(const HybridBundle& bundle,
                                                   EVP_PKEY* priv_key) {
    auto aes_key = RSAKeyManager::decrypt(priv_key, bundle.enc_aes_key);   // Recover AES key
    return AESGCMCipher::decrypt(bundle.ciphertext, aes_key, bundle.iv, bundle.tag);
}

// Encrypt entire file - reads whole file, encrypts, writes bundle
bool HybridCrypto::encrypt_file(const std::string& input_path,
                                 const std::string& output_path,
                                 EVP_PKEY* pub_key) {
    std::ifstream fin(input_path, std::ios::binary);
    if (!fin) { std::cerr << "Cannot open input: " << input_path << "\n"; return false; }
    
    // Read entire input file
    std::vector<unsigned char> data(std::istreambuf_iterator<char>(fin), {});

    HybridBundle bundle = encrypt(data, pub_key);
    return bundle.save(output_path);
}

// Decrypt file back to original - loads bundle, decrypts, writes plaintext
bool HybridCrypto::decrypt_file(const std::string& bundle_path,
                                 const std::string& output_path,
                                 EVP_PKEY* priv_key) {
    HybridBundle bundle;
    if (!bundle.load(bundle_path)) return false;

    auto plaintext = decrypt(bundle, priv_key);

    std::ofstream fout(output_path, std::ios::binary);
    if (!fout) { std::cerr << "Cannot open output: " << output_path << "\n"; return false; }
    
    fout.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    return fout.good();
}