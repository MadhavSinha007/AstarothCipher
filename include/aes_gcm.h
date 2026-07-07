#pragma once
#include "secure_alloc.h"
#include <vector>
#include <cstddef>

// AES-GCM encryption: provides confidentiality + authentication
class AESGCMCipher {
public:
    static constexpr int KEY_LEN = 32;   // 256-bit key
    static constexpr int IV_LEN  = 12;   // 96-bit nonce
    static constexpr int TAG_LEN = 16;   // 128-bit auth tag

    // Encrypt data, output ciphertext + authentication tag
    static SecureVector encrypt(
        const SecureVector& plaintext,
        const SecureVector& key,
        const SecureVector& iv,
        SecureVector& tag_out,
        const SecureVector& aad = {}
    );

    // Decrypt data, verifies tag before returning plaintext
    static SecureVector decrypt(
        const SecureVector& ciphertext,
        const SecureVector& key,
        const SecureVector& iv,
        const SecureVector& tag,
        const SecureVector& aad = {}
    );

    // Generate random key (32 bytes by default)
    static SecureVector generate_key(int len = KEY_LEN);
    
    // Generate random IV/nonce (12 bytes by default)
    static SecureVector generate_iv (int len = IV_LEN);
};