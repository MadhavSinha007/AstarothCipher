#pragma once
#include "rsa_keys.h"
#include "aes_gcm.h"
#include <string>
#include <vector>
#include <cstdint>

/*
  Single-file bundle layout:
  [ 4 bytes magic "HCRY" ][ 1 byte version ]
  [ 4 bytes enc_key_len  ][ N bytes RSA-encrypted AES key ]
  [ 12 bytes IV          ][ 16 bytes GCM tag ]
  [ 8 bytes ct_len       ][ M bytes ciphertext ]

  Folder bundle: same layout, but ciphertext is a mini-tar archive
  containing all files with their relative paths preserved.

  Mini-tar entry format (repeated for every file):
  [ 4 bytes path_len ][ path bytes ]
  [ 8 bytes file_len ][ file bytes ]
  Followed by end marker: [ 4 bytes = 0x00000000 ]
*/

struct HybridBundle {
    std::vector<unsigned char> enc_aes_key;
    std::vector<unsigned char> iv;
    std::vector<unsigned char> tag;
    std::vector<unsigned char> ciphertext;

    bool save(const std::string& path) const;
    bool load(const std::string& path);
};

class HybridCrypto {
public:
    // Core in-memory encrypt / decrypt
    static HybridBundle encrypt(const std::vector<unsigned char>& plaintext,
                                EVP_PKEY* pub_key);

    static std::vector<unsigned char> decrypt(const HybridBundle& bundle,
                                              EVP_PKEY* priv_key);

    // ── Single file ───────────────────────────────────────────────────────────
    static bool encrypt_file(const std::string& input_path,
                             const std::string& output_path,
                             EVP_PKEY* pub_key);

    static bool decrypt_file(const std::string& bundle_path,
                             const std::string& output_path,
                             EVP_PKEY* priv_key);

    // ── Folder (recursive) ────────────────────────────────────────────────────
    // Packs every file in the folder (recursively) into a mini-tar in memory,
    // encrypts the whole archive as a single AES-GCM blob, saves as .hcry.
    static bool encrypt_folder(const std::string& folder_path,
                               const std::string& output_path,
                               EVP_PKEY* pub_key);

    // Decrypts a folder bundle and recreates the full directory tree inside
    // output_dir, preserving all relative paths.
    static bool decrypt_folder(const std::string& bundle_path,
                               const std::string& output_dir,
                               EVP_PKEY* priv_key);
};