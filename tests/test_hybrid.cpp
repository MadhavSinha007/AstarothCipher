#include "hybrid.h"
#include <iostream>
#include <fstream>
#include <cassert>

static int pass_count = 0, fail_count = 0;
#define TEST(name, expr) \
    do { \
        if (expr) { std::cout << "  [PASS] " << name << "\n"; ++pass_count; } \
        else      { std::cerr << "  [FAIL] " << name << "\n"; ++fail_count; } \
    } while(0)

int main() {
    std::cout << "=== Hybrid Encryption Tests ===\n";

    // Generate two RSA key pairs (2048 for test speed)
    std::cout << "\n[setup] Generating RSA key pairs...\n";
    auto keypair  = RSAKeyManager::generate_keypair(2048);
    auto keypair2 = RSAKeyManager::generate_keypair(2048);
    std::cout << "  Done.\n";

    // ── 1. In-memory round-trip ───────────────────────────────────────────────
    std::cout << "\n[1] In-memory encrypt/decrypt round-trip...\n";
    std::string msg = "Top secret: AES-256-GCM + RSA-4096 hybrid works!";
    SecureVector plain(msg.begin(), msg.end());

    auto bundle    = HybridCrypto::encrypt(plain, keypair.get());
    auto recovered = HybridCrypto::decrypt(bundle, keypair.get());

    TEST("ciphertext not empty",       !bundle.ciphertext.empty());
    TEST("enc_aes_key not empty",      !bundle.enc_aes_key.empty());
    TEST("iv is 12 bytes",             bundle.iv.size()  == 12);
    TEST("tag is 16 bytes",            bundle.tag.size() == 16);
    TEST("ciphertext != plaintext",    bundle.ciphertext != plain);
    TEST("decrypted matches original", recovered == plain);

    // ── 2. Each encryption produces a unique ciphertext ──────────────────────
    std::cout << "\n[2] Ciphertext uniqueness (fresh IV/key each call)...\n";
    auto bundle2 = HybridCrypto::encrypt(plain, keypair.get());
    TEST("different ciphertext each call",  bundle.ciphertext  != bundle2.ciphertext);
    TEST("different enc_aes_key each call", bundle.enc_aes_key != bundle2.enc_aes_key);
    TEST("different IV each call",          bundle.iv          != bundle2.iv);
    auto rec2 = HybridCrypto::decrypt(bundle2, keypair.get());
    TEST("second bundle decrypts correctly", rec2 == plain);

    // ── 3. File round-trip ────────────────────────────────────────────────────
    std::cout << "\n[3] File encrypt/decrypt round-trip...\n";
    RSAKeyManager::save_private_key(keypair.get(), "/tmp/hybrid_priv.pem");
    RSAKeyManager::save_public_key (keypair.get(), "/tmp/hybrid_pub.pem");

    {
        std::ofstream f("/tmp/test_input.txt");
        f << "This is a secret file.\nLine 2: Sensitive data.\nLine 3: RSA + AES = secure.\n";
    }

    bool enc_ok = HybridCrypto::encrypt_file("/tmp/test_input.txt",
                                              "/tmp/test_enc.hcry", keypair.get());
    TEST("file encrypt ok", enc_ok);

    bool dec_ok = HybridCrypto::decrypt_file("/tmp/test_enc.hcry",
                                              "/tmp/test_output.txt", keypair.get());
    TEST("file decrypt ok", dec_ok);

    std::ifstream f1("/tmp/test_input.txt"), f2("/tmp/test_output.txt");
    std::string orig((std::istreambuf_iterator<char>(f1)), {});
    std::string dec_str((std::istreambuf_iterator<char>(f2)), {});
    TEST("file content matches", orig == dec_str);

    // ── 4. Bundle save / load integrity ──────────────────────────────────────
    std::cout << "\n[4] Bundle save/load integrity...\n";
    bundle.save("/tmp/test_bundle.hcry");
    HybridBundle loaded;
    bool load_ok = loaded.load("/tmp/test_bundle.hcry");
    TEST("load ok",              load_ok);
    TEST("enc_key preserved",    loaded.enc_aes_key == bundle.enc_aes_key);
    TEST("iv preserved",         loaded.iv          == bundle.iv);
    TEST("tag preserved",        loaded.tag         == bundle.tag);
    TEST("ciphertext preserved", loaded.ciphertext  == bundle.ciphertext);

    auto dec_loaded = HybridCrypto::decrypt(loaded, keypair.get());
    TEST("decrypt after save/load matches", dec_loaded == plain);

    // ── 5. Wrong private key fails ────────────────────────────────────────────
    std::cout << "\n[5] Wrong key rejection...\n";
    bool wrong_key_threw = false;
    try { HybridCrypto::decrypt(bundle, keypair2.get()); }
    catch (...) { wrong_key_threw = true; }
    TEST("wrong private key throws", wrong_key_threw);

    // ── 6. Tamper detection ───────────────────────────────────────────────────
    std::cout << "\n[6] Tamper detection...\n";

    // Flip a byte in ciphertext
    HybridBundle tampered_ct = bundle;
    tampered_ct.ciphertext[0] ^= 0xFF;
    bool ct_tamper_threw = false;
    try { HybridCrypto::decrypt(tampered_ct, keypair.get()); }
    catch (...) { ct_tamper_threw = true; }
    TEST("tampered ciphertext throws", ct_tamper_threw);

    // Flip a byte in the auth tag
    HybridBundle tampered_tag = bundle;
    tampered_tag.tag[0] ^= 0x01;
    bool tag_tamper_threw = false;
    try { HybridCrypto::decrypt(tampered_tag, keypair.get()); }
    catch (...) { tag_tamper_threw = true; }
    TEST("tampered auth tag throws", tag_tamper_threw);

    // Flip a byte in the IV
    HybridBundle tampered_iv = bundle;
    tampered_iv.iv[0] ^= 0x01;
    bool iv_tamper_threw = false;
    try { HybridCrypto::decrypt(tampered_iv, keypair.get()); }
    catch (...) { iv_tamper_threw = true; }
    TEST("tampered IV throws", iv_tamper_threw);

    // Flip a byte in the encrypted AES key
    HybridBundle tampered_key = bundle;
    tampered_key.enc_aes_key[0] ^= 0xFF;
    bool key_tamper_threw = false;
    try { HybridCrypto::decrypt(tampered_key, keypair.get()); }
    catch (...) { key_tamper_threw = true; }
    TEST("tampered enc_aes_key throws", key_tamper_threw);

    // ── 7. Large file (5 MB) ──────────────────────────────────────────────────
    std::cout << "\n[7] Large file (5 MB)...\n";
    {
        std::ofstream f("/tmp/large_input.bin", std::ios::binary);
        SecureVector bigdata(5 * 1024 * 1024);
        for (size_t i = 0; i < bigdata.size(); ++i) bigdata[i] = i & 0xFF;
        f.write(reinterpret_cast<const char*>(bigdata.data()), bigdata.size());
    }
    bool le = HybridCrypto::encrypt_file("/tmp/large_input.bin",
                                          "/tmp/large_enc.hcry",   keypair.get());
    bool ld = HybridCrypto::decrypt_file("/tmp/large_enc.hcry",
                                          "/tmp/large_output.bin", keypair.get());
    TEST("5 MB encrypt ok", le);
    TEST("5 MB decrypt ok", ld);

    std::ifstream lf1("/tmp/large_input.bin",  std::ios::binary);
    std::ifstream lf2("/tmp/large_output.bin", std::ios::binary);
    SecureVector lb1((std::istreambuf_iterator<char>(lf1)), {});
    SecureVector lb2((std::istreambuf_iterator<char>(lf2)), {});
    TEST("5 MB content matches", lb1 == lb2);

    // ── 8. Empty file ─────────────────────────────────────────────────────────
    std::cout << "\n[8] Empty file...\n";
    {
        std::ofstream f("/tmp/empty_input.bin", std::ios::binary);
        // write nothing
    }
    bool ee = HybridCrypto::encrypt_file("/tmp/empty_input.bin",
                                          "/tmp/empty_enc.hcry",    keypair.get());
    bool ed = HybridCrypto::decrypt_file("/tmp/empty_enc.hcry",
                                          "/tmp/empty_output.bin",  keypair.get());
    TEST("empty file encrypt ok", ee);
    TEST("empty file decrypt ok", ed);

    std::ifstream ef1("/tmp/empty_input.bin",  std::ios::binary);
    std::ifstream ef2("/tmp/empty_output.bin", std::ios::binary);
    std::string ec1((std::istreambuf_iterator<char>(ef1)), {});
    std::string ec2((std::istreambuf_iterator<char>(ef2)), {});
    TEST("empty file content matches", ec1 == ec2);

    // ── 9. Binary file (all byte values 0x00–0xFF) ────────────────────────────
    std::cout << "\n[9] Binary file (all 256 byte values)...\n";
    {
        std::ofstream f("/tmp/binary_input.bin", std::ios::binary);
        for (int i = 0; i < 256; ++i) { unsigned char c = i; f.write((char*)&c, 1); }
    }
    HybridCrypto::encrypt_file("/tmp/binary_input.bin", "/tmp/binary_enc.hcry",    keypair.get());
    HybridCrypto::decrypt_file("/tmp/binary_enc.hcry",  "/tmp/binary_output.bin",  keypair.get());

    std::ifstream bf1("/tmp/binary_input.bin",  std::ios::binary);
    std::ifstream bf2("/tmp/binary_output.bin", std::ios::binary);
    SecureVector bb1((std::istreambuf_iterator<char>(bf1)), {});
    SecureVector bb2((std::istreambuf_iterator<char>(bf2)), {});
    TEST("binary file content matches", bb1 == bb2);

    // ── 10. Invalid bundle file rejected ─────────────────────────────────────
    std::cout << "\n[10] Corrupt bundle rejected...\n";
    {
        std::ofstream f("/tmp/corrupt.hcry", std::ios::binary);
        f << "JUNK DATA NOT A VALID BUNDLE !!!";
    }
    HybridBundle corrupt;
    bool corrupt_threw = false;
    try { corrupt.load("/tmp/corrupt.hcry"); }
    catch (...) { corrupt_threw = true; }
    TEST("corrupt bundle throws on load", corrupt_threw);

    std::cout << "\n--- Results: " << pass_count << " passed, " << fail_count << " failed ---\n";
    return fail_count > 0 ? 1 : 0;
}