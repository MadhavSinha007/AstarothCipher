#include "hybrid.h"
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <cstring>

// ── Helper functions for reading/writing numbers (big-endian format) ─────────
// These ensure the file format works the same on all computers

// Write a 4-byte number to file (most significant byte first)
static void write_u32_be(std::ostream& os, uint32_t v) {
    unsigned char b[4] = { (unsigned char)(v>>24), (unsigned char)(v>>16),
                           (unsigned char)(v>>8),  (unsigned char)(v) };
    os.write(reinterpret_cast<char*>(b), 4);
}

// Write an 8-byte number to file
static void write_u64_be(std::ostream& os, uint64_t v) {
    unsigned char b[8];
    for (int i = 7; i >= 0; --i) { b[i] = v & 0xFF; v >>= 8; }
    os.write(reinterpret_cast<char*>(b), 8);
}

// Read a 4-byte number from file
static uint32_t read_u32_be(std::istream& is) {
    unsigned char b[4]; is.read(reinterpret_cast<char*>(b), 4);
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
}

// Read an 8-byte number from file
static uint64_t read_u64_be(std::istream& is) {
    unsigned char b[8]; is.read(reinterpret_cast<char*>(b), 8);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v<<8) | b[i];
    return v;
}

// ── Saving and loading encrypted bundles ────────────────────────────────────

static const char MAGIC[4] = {'H','C','R','Y'};  // File signature
static const unsigned char VERSION = 0x01;       // File format version

// Save encrypted data bundle to a file
bool HybridBundle::save(const std::string& path) const {
    std::ofstream f(path, std::ios::binary);
    if (!f) { std::cerr << "Cannot write: " << path << "\n"; return false; }

    // Write file header
    f.write(MAGIC, 4);                    // Magic number "HCRY"
    f.put(static_cast<char>(VERSION));    // Version number
    
    // Write the RSA-encrypted AES key (with length prefix)
    write_u32_be(f, static_cast<uint32_t>(enc_aes_key.size()));
    f.write(reinterpret_cast<const char*>(enc_aes_key.data()), enc_aes_key.size());
    
    // Write IV and authentication tag (fixed sizes)
    f.write(reinterpret_cast<const char*>(iv.data()),  iv.size());
    f.write(reinterpret_cast<const char*>(tag.data()), tag.size());
    
    // Write the encrypted data (with length prefix)
    write_u64_be(f, static_cast<uint64_t>(ciphertext.size()));
    f.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    
    return f.good();
}

// Load encrypted data bundle from a file
bool HybridBundle::load(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "Cannot read: " << path << "\n"; return false; }

    // Check file signature
    char magic[4]; f.read(magic, 4);
    if (memcmp(magic, MAGIC, 4) != 0)
        throw std::runtime_error("Not a valid HCRY bundle (magic mismatch)");

    // Check version
    unsigned char ver = static_cast<unsigned char>(f.get());
    if (ver != VERSION)
        throw std::runtime_error("Unsupported bundle version");

    // Read the encrypted AES key
    uint32_t key_len = read_u32_be(f);
    enc_aes_key.resize(key_len); 
    f.read(reinterpret_cast<char*>(enc_aes_key.data()), key_len);

    // Read IV and tag
    iv.resize(AESGCMCipher::IV_LEN);  
    f.read(reinterpret_cast<char*>(iv.data()),  AESGCMCipher::IV_LEN);
    tag.resize(AESGCMCipher::TAG_LEN); 
    f.read(reinterpret_cast<char*>(tag.data()), AESGCMCipher::TAG_LEN);

    // Read the encrypted data
    uint64_t ct_len = read_u64_be(f);
    ciphertext.resize(ct_len); 
    f.read(reinterpret_cast<char*>(ciphertext.data()), ct_len);
    
    return f.good();
}

// ── Main encryption/decryption logic ────────────────────────────────────────

// Encrypt data using hybrid approach (RSA + AES)
HybridBundle HybridCrypto::encrypt(const SecureVector& plaintext,
                                    EVP_PKEY* pub_key) {
    // Step 1: Create a random AES key and random IV for this session
    auto aes_key = AESGCMCipher::generate_key();  // 256-bit key
    auto iv      = AESGCMCipher::generate_iv();   // 96-bit nonce

    // Step 2: Encrypt the actual data using AES-GCM
    SecureVector tag;
    auto ciphertext = AESGCMCipher::encrypt(plaintext, aes_key, iv, tag);

    // Step 3: Encrypt the AES key using the recipient's RSA public key
    auto enc_aes_key = RSAKeyManager::encrypt(pub_key, aes_key);

    // Package everything together
    return HybridBundle{ enc_aes_key, iv, tag, ciphertext };
}

// Decrypt data using hybrid approach
SecureVector HybridCrypto::decrypt(const HybridBundle& bundle,
                                                   EVP_PKEY* priv_key) {
    // Step 1: Decrypt the AES key using our RSA private key
    auto aes_key = RSAKeyManager::decrypt(priv_key, bundle.enc_aes_key);

    // Step 2: Decrypt the data using AES-GCM (will throw if tampered with)
    return AESGCMCipher::decrypt(bundle.ciphertext, aes_key, bundle.iv, bundle.tag);
}

// ── Single file operations ──────────────────────────────────────────────────

// Encrypt a single file
bool HybridCrypto::encrypt_file(const std::string& input_path,
                                 const std::string& output_path,
                                 EVP_PKEY* pub_key) {
    // Read the whole file into memory
    std::ifstream fin(input_path, std::ios::binary);
    if (!fin) { std::cerr << "Cannot open input: " << input_path << "\n"; return false; }
    SecureVector data(std::istreambuf_iterator<char>(fin), {});

    // Encrypt and save
    HybridBundle bundle = encrypt(data, pub_key);
    return bundle.save(output_path);
}

// Decrypt a single file
bool HybridCrypto::decrypt_file(const std::string& bundle_path,
                                 const std::string& output_path,
                                 EVP_PKEY* priv_key) {
    // Load the encrypted bundle
    HybridBundle bundle;
    if (!bundle.load(bundle_path)) return false;

    // Decrypt the data
    auto plaintext = decrypt(bundle, priv_key);

    // Write to output file
    std::ofstream fout(output_path, std::ios::binary);
    if (!fout) { std::cerr << "Cannot open output: " << output_path << "\n"; return false; }
    fout.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    return fout.good();
}

// ── Folder operations (encrypt entire directories) ──────────────────────────

#include <filesystem>
namespace fs = std::filesystem;

// Helper: Add a 4-byte number to a byte array
static void vec_push_u32(SecureVector& v, uint32_t n) {
    v.push_back(static_cast<unsigned char>((n >> 24) & 0xFF));
    v.push_back(static_cast<unsigned char>((n >> 16) & 0xFF));
    v.push_back(static_cast<unsigned char>((n >>  8) & 0xFF));
    v.push_back(static_cast<unsigned char>( n        & 0xFF));
}

// Helper: Add an 8-byte number to a byte array
static void vec_push_u64(SecureVector& v, uint64_t n) {
    unsigned char b[8];
    for (int i = 7; i >= 0; --i) { b[i] = n & 0xFF; n >>= 8; }
    v.insert(v.end(), b, b + 8);
}

// Helper: Read a 4-byte number from a byte array
static uint32_t vec_read_u32(const SecureVector& v, size_t& pos) {
    uint32_t n = ((uint32_t)v[pos]<<24)|((uint32_t)v[pos+1]<<16)
               |((uint32_t)v[pos+2]<<8)|(uint32_t)v[pos+3];
    pos += 4; return n;
}

// Helper: Read an 8-byte number from a byte array
static uint64_t vec_read_u64(const SecureVector& v, size_t& pos) {
    uint64_t n = 0;
    for (int i = 0; i < 8; ++i) n = (n << 8) | v[pos++];
    return n;
}

// Take a folder and pack all files into a simple archive format
// Archive format: for each file we store [path length][path][file length][file data]
// Then a marker with path length = 0 at the end
static SecureVector pack_folder(const std::string& folder_path) {
    fs::path root(folder_path);
    if (!fs::is_directory(root))
        throw std::runtime_error("Not a directory: " + folder_path);

    SecureVector archive;
    size_t file_count = 0;

    // Loop through every file in the folder and subfolders
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) continue;  // Skip folders, symlinks, etc.

        // Get the file path relative to the folder (e.g., "docs/readme.txt")
        std::string rel = fs::relative(entry.path(), root).generic_string();

        // Read the entire file content
        std::ifstream fin(entry.path(), std::ios::binary);
        if (!fin) throw std::runtime_error("Cannot read: " + entry.path().string());
        SecureVector content(std::istreambuf_iterator<char>(fin), {});

        // Write this file to the archive
        vec_push_u32(archive, static_cast<uint32_t>(rel.size()));  // Path length
        archive.insert(archive.end(), rel.begin(), rel.end());     // Path string
        vec_push_u64(archive, static_cast<uint64_t>(content.size())); // File size
        archive.insert(archive.end(), content.begin(), content.end()); // File data
        ++file_count;

        std::cout << "  + " << rel << " (" << content.size() << " bytes)\n";
    }

    // Add end marker (just a 4-byte zero)
    vec_push_u32(archive, 0);

    std::cout << "  Packed " << file_count << " files ("
              << archive.size() << " bytes total)\n";
    return archive;
}

// Take an archive and extract all files back to a folder
static void unpack_folder(const SecureVector& archive,
                           const std::string& output_dir) {
    fs::path outroot(output_dir);
    fs::create_directories(outroot);  // Create output folder if needed

    size_t pos = 0;
    size_t file_count = 0;

    while (pos + 4 <= archive.size()) {
        uint32_t path_len = vec_read_u32(archive, pos);
        if (path_len == 0) break;  // End marker - we're done

        // Make sure we won't read past the end
        if (pos + path_len > archive.size())
            throw std::runtime_error("Corrupt archive: path overrun");

        // Read the file path
        std::string rel(reinterpret_cast<const char*>(archive.data() + pos), path_len);
        pos += path_len;

        // Security check: make sure the path doesn't try to escape our output folder
        fs::path full = outroot / rel;
        auto canonical_out  = fs::weakly_canonical(outroot);
        auto canonical_full = fs::weakly_canonical(full.parent_path());
        auto rel_check = fs::relative(canonical_full, canonical_out);
        if (!rel_check.empty() && rel_check.native().substr(0,2) == "..") {
            throw std::runtime_error("Path traversal detected: " + rel);
        }

        // Read the file size
        if (pos + 8 > archive.size())
            throw std::runtime_error("Corrupt archive: file_len overrun");
        uint64_t file_len = vec_read_u64(archive, pos);

        // Read the file content
        if (pos + file_len > archive.size())
            throw std::runtime_error("Corrupt archive: content overrun");

        // Create parent folders if needed
        fs::create_directories(full.parent_path());

        // Write the file
        std::ofstream fout(full, std::ios::binary);
        if (!fout) throw std::runtime_error("Cannot write: " + full.string());
        fout.write(reinterpret_cast<const char*>(archive.data() + pos), file_len);
        pos += file_len;
        ++file_count;

        std::cout << "  -> " << rel << " (" << file_len << " bytes)\n";
    }

    std::cout << "  Unpacked " << file_count << " files\n";
}

// Encrypt an entire folder (all files and subfolders)
bool HybridCrypto::encrypt_folder(const std::string& folder_path,
                                   const std::string& output_path,
                                   EVP_PKEY* pub_key) {
    std::cout << "Packing folder: " << folder_path << "\n";
    
    // First, pack all files into a single archive
    SecureVector archive;
    try {
        archive = pack_folder(folder_path);
    } catch (const std::exception& e) {
        std::cerr << "Pack failed: " << e.what() << "\n";
        return false;
    }

    // Then encrypt the archive like a regular file
    std::cout << "Encrypting archive...\n";
    HybridBundle bundle = encrypt(archive, pub_key);
    if (!bundle.save(output_path)) return false;
    
    std::cout << "Folder bundle saved to: " << output_path << "\n";
    return true;
}

// Decrypt a folder bundle and restore all files
bool HybridCrypto::decrypt_folder(const std::string& bundle_path,
                                   const std::string& output_dir,
                                   EVP_PKEY* priv_key) {
    // Load the encrypted bundle
    HybridBundle bundle;
    if (!bundle.load(bundle_path)) return false;

    // Decrypt to get the archive
    std::cout << "Decrypting archive...\n";
    SecureVector archive;
    try {
        archive = decrypt(bundle, priv_key);
    } catch (const std::exception& e) {
        std::cerr << "Decrypt failed: " << e.what() << "\n";
        return false;
    }

    // Extract all files from the archive
    std::cout << "Unpacking to: " << output_dir << "\n";
    try {
        unpack_folder(archive, output_dir);
    } catch (const std::exception& e) {
        std::cerr << "Unpack failed: " << e.what() << "\n";
        return false;
    }
    return true;
}