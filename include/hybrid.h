#pragma once

#include "rsa_keys.h"
#include "aes_gcm.h"
#include "secure_alloc.h"
#include <string>
#include <cstdint>

struct HybridBundle {
    SecureVector enc_aes_key;
    SecureVector iv;
    SecureVector tag;
    SecureVector ciphertext;

    // Pure memory serialization methods
    SecureVector to_bytes() const;
    static HybridBundle from_bytes(const SecureVector& data);
};

class HybridCrypto {
public:
    static HybridBundle encrypt(const SecureVector& plaintext, EVP_PKEY* pub_key);
    static SecureVector decrypt(const HybridBundle& bundle, EVP_PKEY* priv_key);
};