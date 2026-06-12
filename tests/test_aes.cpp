#include "aes_gcm.h"
#include <iostream>
#include <cassert>
#include <cstring>

static int pass_count = 0, fail_count = 0;
#define TEST(name, expr) \
    do { \
        if (expr) { std::cout << "  [PASS] " << name << "\n"; ++pass_count; } \
        else      { std::cerr << "  [FAIL] " << name << "\n"; ++fail_count; } \
    } while(0)

int main() {
    std::cout << "=== AES-256-GCM Tests ===\n";

    auto key = AESGCMCipher::generate_key();
    auto iv  = AESGCMCipher::generate_iv();
    TEST("key length 32 bytes",        key.size() == 32);
    TEST("iv  length 12 bytes",        iv.size()  == 12);
    TEST("key and iv different length", key.size() != iv.size());

    // 1. Basic round-trip
    std::cout << "\n[1] Basic encrypt/decrypt round-trip...\n";
    std::string msg = "Hello, Hybrid Crypto World!";
    std::vector<unsigned char> plain(msg.begin(), msg.end());

    std::vector<unsigned char> tag;
    auto cipher = AESGCMCipher::encrypt(plain, key, iv, tag);
    TEST("ciphertext not empty",      !cipher.empty());
    TEST("tag is 16 bytes",           tag.size() == 16);
    TEST("ciphertext != plaintext",   cipher != plain);

    auto recovered = AESGCMCipher::decrypt(cipher, key, iv, tag);
    TEST("decrypted length matches",  recovered.size() == plain.size());
    TEST("decrypted content matches", recovered == plain);

    // 2. Empty message
    std::cout << "\n[2] Empty plaintext...\n";
    std::vector<unsigned char> empty;
    std::vector<unsigned char> empty_tag;
    auto empty_cipher    = AESGCMCipher::encrypt(empty, key, iv, empty_tag);
    auto empty_recovered = AESGCMCipher::decrypt(empty_cipher, key, iv, empty_tag);
    TEST("empty encrypt+decrypt ok", empty_recovered == empty);

    // 3. Large data (1 MB)
    std::cout << "\n[3] Large data (1 MB)...\n";
    std::vector<unsigned char> big(1024 * 1024);
    for (size_t i = 0; i < big.size(); i++) big[i] = i & 0xFF;
    auto big_iv = AESGCMCipher::generate_iv();
    std::vector<unsigned char> big_tag;
    auto big_cipher = AESGCMCipher::encrypt(big, key, big_iv, big_tag);
    auto big_rec    = AESGCMCipher::decrypt(big_cipher, key, big_iv, big_tag);
    TEST("1 MB round-trip ok", big_rec == big);

    // 4. Additional Authenticated Data (AAD)
    std::cout << "\n[4] Additional Authenticated Data (AAD)...\n";
    std::vector<unsigned char> aad_val = {'m', 'e', 't', 'a'};
    auto aad_iv = AESGCMCipher::generate_iv();
    std::vector<unsigned char> aad_tag;
    auto aad_cipher = AESGCMCipher::encrypt(plain, key, aad_iv, aad_tag, aad_val);
    auto aad_rec    = AESGCMCipher::decrypt(aad_cipher, key, aad_iv, aad_tag, aad_val);
    TEST("AAD round-trip ok", aad_rec == plain);

    std::vector<unsigned char> bad_aad = {'b', 'a', 'd'};
    bool aad_threw = false;
    try { AESGCMCipher::decrypt(aad_cipher, key, aad_iv, aad_tag, bad_aad); }
    catch (...) { aad_threw = true; }
    TEST("wrong AAD throws", aad_threw);

    // 5. Tamper detection
    std::cout << "\n[5] Tamper detection...\n";
    auto tampered = cipher;
    tampered[0] ^= 0xFF;
    bool tamper_threw = false;
    try { AESGCMCipher::decrypt(tampered, key, iv, tag); }
    catch (...) { tamper_threw = true; }
    TEST("tampered ciphertext throws", tamper_threw);

    auto bad_tag = tag;
    bad_tag[0] ^= 0x01;
    bool bad_tag_threw = false;
    try { AESGCMCipher::decrypt(cipher, key, iv, bad_tag); }
    catch (...) { bad_tag_threw = true; }
    TEST("wrong tag throws", bad_tag_threw);

    auto wrong_key = AESGCMCipher::generate_key();
    bool wrong_key_threw = false;
    try { AESGCMCipher::decrypt(cipher, wrong_key, iv, tag); }
    catch (...) { wrong_key_threw = true; }
    TEST("wrong key throws", wrong_key_threw);

    // 6. Different IV produces different ciphertext
    std::cout << "\n[6] IV uniqueness...\n";
    auto iv2 = AESGCMCipher::generate_iv();
    std::vector<unsigned char> tag2;
    auto cipher2 = AESGCMCipher::encrypt(plain, key, iv2, tag2);
    TEST("different IV = different ciphertext", cipher != cipher2);
    auto rec2 = AESGCMCipher::decrypt(cipher2, key, iv2, tag2);
    TEST("second IV decrypts correctly", rec2 == plain);

    // 7. Bad key/iv size rejected
    std::cout << "\n[7] Bad parameter rejection...\n";
    std::vector<unsigned char> short_key(16, 0xAA); // 128-bit, not 256
    std::vector<unsigned char> dummy_tag;
    bool short_key_threw = false;
    try { AESGCMCipher::encrypt(plain, short_key, iv, dummy_tag); }
    catch (...) { short_key_threw = true; }
    TEST("short key rejected", short_key_threw);

    std::vector<unsigned char> short_iv(8, 0xBB); // 64-bit, not 96
    bool short_iv_threw = false;
    try { AESGCMCipher::encrypt(plain, key, short_iv, dummy_tag); }
    catch (...) { short_iv_threw = true; }
    TEST("short IV rejected", short_iv_threw);

    std::cout << "\n--- Results: " << pass_count << " passed, " << fail_count << " failed ---\n";
    return fail_count > 0 ? 1 : 0;
}