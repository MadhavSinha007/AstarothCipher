#pragma once
#include <vector>
#include <cstddef>

// AES-GCM encryption: provides confidentiality + authentication
class AESGCMCipher {
public:
    static constexpr int KEY_LEN = 32;   // 256-bit key
    static constexpr int IV_LEN  = 12;   // 96-bit nonce
    static constexpr int TAG_LEN = 16;   // 128-bit auth tag

    // Encrypt data, output ciphertext + authentication tag
    static std::vector<unsigned char> encrypt(
        const std::vector<unsigned char>& plaintext,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv,
        std::vector<unsigned char>& tag_out,
        const std::vector<unsigned char>& aad = {}
    );

    // Decrypt data, verifies tag before returning plaintext
    static std::vector<unsigned char> decrypt(
        const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv,
        const std::vector<unsigned char>& tag,
        const std::vector<unsigned char>& aad = {}
    );

    // Generate random key (32 bytes by default)
    static std::vector<unsigned char> generate_key(int len = KEY_LEN);
    
    // Generate random IV/nonce (12 bytes by default)
    static std::vector<unsigned char> generate_iv (int len = IV_LEN);
};