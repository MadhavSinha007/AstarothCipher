#include "rsa_keys.h"
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
    std::cout << "=== RSA Key Tests ===\n";

    // 1. Generate key pair (2048 in tests for speed; use 4096 in production)
    std::cout << "\n[1] Key generation (2048-bit for speed)...\n";
    EVP_PKEY_ptr keypair;
    try {
        keypair = RSAKeyManager::generate_keypair(2048);
        TEST("keypair not null", keypair != nullptr);
    } catch (const std::exception& e) {
        std::cerr << "  Exception: " << e.what() << "\n";
        return 1;
    }

    // 2. Save and reload keys
    std::cout << "\n[2] Save / load PEM files...\n";
    bool saved_priv = RSAKeyManager::save_private_key(keypair.get(), "/tmp/test_priv.pem");
    bool saved_pub  = RSAKeyManager::save_public_key (keypair.get(), "/tmp/test_pub.pem");
    TEST("save private key", saved_priv);
    TEST("save public key",  saved_pub);

    EVP_PKEY_ptr loaded_priv = RSAKeyManager::load_private_key("/tmp/test_priv.pem");
    EVP_PKEY_ptr loaded_pub  = RSAKeyManager::load_public_key ("/tmp/test_pub.pem");
    TEST("load private key", loaded_priv != nullptr);
    TEST("load public key",  loaded_pub  != nullptr);

    // 3. Encrypt → Decrypt round-trip
    std::cout << "\n[3] Encrypt / decrypt round-trip...\n";
    std::vector<unsigned char> aes_key(32, 0xAB); // fake 256-bit key

    auto enc = RSAKeyManager::encrypt(loaded_pub.get(), aes_key);
    TEST("ciphertext not empty",     !enc.empty());
    TEST("ciphertext != plaintext",   enc != aes_key);

    auto dec = RSAKeyManager::decrypt(loaded_priv.get(), enc);
    TEST("decrypted length matches",  dec.size() == aes_key.size());
    TEST("decrypted content matches", dec == aes_key);

    // 4. Wrong key should fail
    std::cout << "\n[4] Wrong key rejection...\n";
    auto other = RSAKeyManager::generate_keypair(2048);
    bool threw = false;
    try { RSAKeyManager::decrypt(other.get(), enc); }
    catch (...) { threw = true; }
    TEST("wrong key throws", threw);

    // 5. Passphrase-protected private key
    std::cout << "\n[5] Passphrase-protected key...\n";
    bool sp = RSAKeyManager::save_private_key(keypair.get(), "/tmp/test_priv_pass.pem", "s3cr3t");
    TEST("save with passphrase", sp);
    EVP_PKEY_ptr lp = RSAKeyManager::load_private_key("/tmp/test_priv_pass.pem", "s3cr3t");
    TEST("load with correct passphrase", lp != nullptr);
    bool wrong_pass_threw = false;
    try { RSAKeyManager::load_private_key("/tmp/test_priv_pass.pem", "wrong"); }
    catch (...) { wrong_pass_threw = true; }
    TEST("wrong passphrase throws", wrong_pass_threw);

    std::cout << "\n--- Results: " << pass_count << " passed, " << fail_count << " failed ---\n";
    return fail_count > 0 ? 1 : 0;
}