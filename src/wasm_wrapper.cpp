#include <emscripten/bind.h>
#include <emscripten/val.h>
#include "hybrid.h"
#include <fstream>
#include "rsa_keys.h"
#include "secure_alloc.h"

using namespace emscripten;

// Helper: Convert JS Uint8Array to C++ SecureVector
SecureVector js_to_secure_vec(const val& js_array) {
    auto length = js_array["length"].as<size_t>();
    SecureVector vec(length);
    val memoryView{typed_memory_view(length, vec.data())};
    memoryView.call<void>("set", js_array);
    return vec;
}

// Helper: Convert C++ SecureVector to JS Uint8Array (COPIED SAFELY)
val secure_vec_to_js(const SecureVector& vec) {
    val memory_view = val(typed_memory_view(vec.size(), vec.data()));
    val js_array = val::global("Uint8Array").new_(vec.size());
    js_array.call<void>("set", memory_view);
    return js_array;
}

// ── Expose RSA Key Generation ─────────────────────────────────────────────
// Returns a simple JS object with { privateKey: "...", publicKey: "..." }
val generate_keys_js(int bits) {
    auto keypair = RSAKeyManager::generate_keypair(bits);
    
    // Save keys to Emscripten's virtual in-memory file system
    RSAKeyManager::save_private_key(keypair.get(), "/virt_priv.pem");
    RSAKeyManager::save_public_key(keypair.get(), "/virt_pub.pem");

    // Read them back as strings to send to JavaScript
    std::ifstream priv_file("/virt_priv.pem");
    std::string priv_str((std::istreambuf_iterator<char>(priv_file)), {});
    
    std::ifstream pub_file("/virt_pub.pem");
    std::string pub_str((std::istreambuf_iterator<char>(pub_file)), {});

    val result = val::object();
    result.set("privateKey", priv_str);
    result.set("publicKey", pub_str);
    return result;
}

// ── Expose Hybrid Encryption ──────────────────────────────────────────────
val encrypt_data_js(const val& js_plaintext, const std::string& pub_key_pem) {
    // 1. Convert JS array to C++ secure vector
    SecureVector plaintext = js_to_secure_vec(js_plaintext);

    // 2. Write the PEM string to the virtual filesystem to load it
    std::ofstream pub_out("/virt_pub.pem");
    pub_out << pub_key_pem;
    pub_out.close();
    auto pub_key = RSAKeyManager::load_public_key("/virt_pub.pem");

    // 3. Encrypt the data
    HybridBundle bundle = HybridCrypto::encrypt(plaintext, pub_key.get());

    // 4. Save bundle to virtual filesystem, then read bytes back
    bundle.save("/virt_bundle.hcry");
    std::ifstream enc_in("/virt_bundle.hcry", std::ios::binary);
    SecureVector enc_data((std::istreambuf_iterator<char>(enc_in)), {});

    return secure_vec_to_js(enc_data);
}

// ── Expose Hybrid Decryption ──────────────────────────────────────────────
val decrypt_data_js(const val& js_bundle, const std::string& priv_key_pem) {
    // 1. Convert JS array to C++ secure vector
    SecureVector enc_data = js_to_secure_vec(js_bundle);

    // 2. Write bytes to virtual filesystem to load the bundle
    std::ofstream bundle_out("/virt_bundle.hcry", std::ios::binary);
    bundle_out.write(reinterpret_cast<const char*>(enc_data.data()), enc_data.size());
    bundle_out.close();

    HybridBundle bundle;
    if (!bundle.load("/virt_bundle.hcry")) {
        return val("ERROR: Corrupt Bundle"); // Handle error gracefully in JS
    }

    // 3. Load private key
    std::ofstream priv_out("/virt_priv.pem");
    priv_out << priv_key_pem;
    priv_out.close();
    auto priv_key = RSAKeyManager::load_private_key("/virt_priv.pem");

    // 4. Decrypt
    try {
        SecureVector plaintext = HybridCrypto::decrypt(bundle, priv_key.get());
        return secure_vec_to_js(plaintext);
    } catch (...) {
        return val("ERROR: Decryption Failed (Wrong key or tampered data)");
    }
}

// ── Bindings ──────────────────────────────────────────────────────────────
EMSCRIPTEN_BINDINGS(hybrid_crypto_module) {
    function("generateKeys", &generate_keys_js);
    function("encryptData", &encrypt_data_js);
    function("decryptData", &decrypt_data_js);
}