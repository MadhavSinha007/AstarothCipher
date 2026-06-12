#include "hybrid.h"
#include <iostream>
#include <fstream>
#include <filesystem>
namespace fs = std::filesystem;

static int pass_count = 0, fail_count = 0;
#define TEST(name, expr) \
    do { \
        if (expr) { std::cout << "  [PASS] " << name << "\n"; ++pass_count; } \
        else      { std::cerr << "  [FAIL] " << name << "\n"; ++fail_count; } \
    } while(0)

// Create a test folder with nested files
static void create_test_folder(const std::string& root) {
    fs::create_directories(root + "/subdir/deep");
    auto write = [](const std::string& path, const std::string& content) {
        std::ofstream f(path); f << content;
    };
    write(root + "/readme.txt",           "This is the readme.\nLine 2.\n");
    write(root + "/notes.txt",            "Secret notes here.");
    write(root + "/subdir/config.json",   "{\"key\": \"value\", \"num\": 42}");
    write(root + "/subdir/data.csv",      "name,age\nAlice,30\nBob,25\n");
    write(root + "/subdir/deep/logs.txt", "Log line 1\nLog line 2\nLog line 3\n");

    // Binary file (all 256 byte values)
    std::ofstream bf(root + "/binary.bin", std::ios::binary);
    for (int i = 0; i < 256; ++i) { unsigned char c = i; bf.write((char*)&c, 1); }
}

// Compare two directories recursively — returns true if identical
static bool dirs_equal(const std::string& a, const std::string& b) {
    for (const auto& ea : fs::recursive_directory_iterator(a)) {
        if (!ea.is_regular_file()) continue;
        auto rel  = fs::relative(ea.path(), a);
        auto pb   = fs::path(b) / rel;
        if (!fs::exists(pb)) {
            std::cerr << "  Missing in output: " << rel << "\n"; return false;
        }
        std::ifstream fa(ea.path(), std::ios::binary);
        std::ifstream fb(pb,        std::ios::binary);
        std::string ca((std::istreambuf_iterator<char>(fa)), {});
        std::string cb((std::istreambuf_iterator<char>(fb)), {});
        if (ca != cb) {
            std::cerr << "  Content mismatch: " << rel << "\n"; return false;
        }
    }
    return true;
}

int main() {
    std::cout << "=== Folder Encryption Tests ===\n";

    auto kp  = RSAKeyManager::generate_keypair(2048);
    auto kp2 = RSAKeyManager::generate_keypair(2048);

    // ── 1. Basic folder round-trip ────────────────────────────────────────────
    std::cout << "\n[1] Basic folder encrypt/decrypt round-trip...\n";
    const std::string src  = "/tmp/hcry_test_src";
    const std::string enc  = "/tmp/hcry_test.hcry";
    const std::string out  = "/tmp/hcry_test_out";
    fs::remove_all(src); fs::remove_all(out); fs::remove(enc);

    create_test_folder(src);

    bool ok_enc = HybridCrypto::encrypt_folder(src, enc, kp.get());
    TEST("encrypt-folder succeeds", ok_enc);
    TEST("bundle file exists",      fs::exists(enc));
    TEST("bundle is binary (not plaintext)",
         [&]{ std::ifstream f(enc, std::ios::binary);
              std::string s((std::istreambuf_iterator<char>(f)),{});
              return s.find("readme") == std::string::npos; }());

    bool ok_dec = HybridCrypto::decrypt_folder(enc, out, kp.get());
    TEST("decrypt-folder succeeds", ok_dec);
    TEST("output dir exists",       fs::is_directory(out));

    // Check every file matches
    TEST("all files identical", dirs_equal(src, out));

    // ── 2. Nested directory structure preserved ───────────────────────────────
    std::cout << "\n[2] Nested directory structure preserved...\n";
    TEST("subdir/config.json exists",   fs::exists(out+"/subdir/config.json"));
    TEST("subdir/deep/logs.txt exists", fs::exists(out+"/subdir/deep/logs.txt"));

    // ── 3. Binary file survives intact ───────────────────────────────────────
    std::cout << "\n[3] Binary file integrity...\n";
    std::ifstream bsrc(src+"/binary.bin", std::ios::binary);
    std::ifstream bout(out+"/binary.bin", std::ios::binary);
    std::vector<unsigned char> bsv(std::istreambuf_iterator<char>(bsrc), {});
    std::vector<unsigned char> bov(std::istreambuf_iterator<char>(bout), {});
    TEST("binary.bin size matches",   bsv.size() == 256 && bov.size() == 256);
    TEST("binary.bin content matches", bsv == bov);

    // ── 4. Wrong key fails ────────────────────────────────────────────────────
    std::cout << "\n[4] Wrong key rejection...\n";
    bool wrong_threw = false;
    try { HybridCrypto::decrypt_folder(enc, "/tmp/hcry_wrong_out", kp2.get()); }
    catch (...) { wrong_threw = true; }
    // decrypt_folder returns false on failure (doesn't throw at top level)
    // check it at least didn't succeed
    bool wrong_failed = wrong_threw ||
        !fs::exists("/tmp/hcry_wrong_out") ||
        fs::is_empty("/tmp/hcry_wrong_out");
    TEST("wrong key fails", wrong_failed);

    // ── 5. Empty folder ───────────────────────────────────────────────────────
    std::cout << "\n[5] Empty folder...\n";
    const std::string esrc = "/tmp/hcry_empty_src";
    const std::string eenc = "/tmp/hcry_empty.hcry";
    const std::string eout = "/tmp/hcry_empty_out";
    fs::remove_all(esrc); fs::remove_all(eout); fs::remove(eenc);
    fs::create_directories(esrc);

    bool ee = HybridCrypto::encrypt_folder(esrc, eenc, kp.get());
    bool ed = HybridCrypto::decrypt_folder(eenc, eout, kp.get());
    TEST("empty folder encrypt ok", ee);
    TEST("empty folder decrypt ok", ed);

    // ── 6. Large files inside folder ─────────────────────────────────────────
    std::cout << "\n[6] Large file inside folder...\n";
    const std::string lsrc = "/tmp/hcry_large_src";
    const std::string lenc = "/tmp/hcry_large.hcry";
    const std::string lout = "/tmp/hcry_large_out";
    fs::remove_all(lsrc); fs::remove_all(lout); fs::remove(lenc);
    fs::create_directories(lsrc);
    {
        std::ofstream f(lsrc+"/big.bin", std::ios::binary);
        std::vector<unsigned char> big(2*1024*1024);
        for (size_t i=0;i<big.size();++i) big[i]=i&0xFF;
        f.write(reinterpret_cast<const char*>(big.data()), big.size());
        std::ofstream g(lsrc+"/small.txt"); g << "tiny file\n";
    }
    bool le = HybridCrypto::encrypt_folder(lsrc, lenc, kp.get());
    bool ld = HybridCrypto::decrypt_folder(lenc, lout, kp.get());
    TEST("large-file folder encrypt ok", le);
    TEST("large-file folder decrypt ok", ld);
    TEST("large-file folder content matches", dirs_equal(lsrc, lout));

    // ── 7. Tampered bundle rejected ───────────────────────────────────────────
    std::cout << "\n[7] Tamper detection on folder bundle...\n";
    {
        std::fstream f(enc, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(-10, std::ios::end);
        char c; f.get(c); f.seekp(-1, std::ios::cur); f.put(c ^ 0xFF);
    }
    bool tamper_failed = !HybridCrypto::decrypt_folder(enc, "/tmp/hcry_tamper_out", kp.get());
    TEST("tampered folder bundle rejected", tamper_failed);

    std::cout << "\n--- Results: " << pass_count << " passed, " << fail_count << " failed ---\n";
    return fail_count > 0 ? 1 : 0;
}