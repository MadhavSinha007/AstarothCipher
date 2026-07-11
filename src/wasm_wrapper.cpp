#include <emscripten/bind.h>
#include <emscripten/val.h>
#include "hybrid.h"
#include <fstream>
#include "rsa_keys.h"
#include "secure_alloc.h"
#include <string>

using namespace emscripten;

// --- OpenSSL 3.x WASM Fix ---
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

struct OpenSSLInitializer {
    OpenSSLInitializer() {
        OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
        OSSL_PROVIDER_load(NULL, "default");
    }
} g_openssl_init; 

// --- Secure Memory Helpers ---
SecureVector js_to_secure_vec(const val& js_array) {
    auto length = js_array["length"].as<size_t>();
    SecureVector vec(length);
    val memoryView{typed_memory_view(length, vec.data())};
    memoryView.call<void>("set", js_array);
    return vec;
}

val secure_vec_to_js(const SecureVector& vec) {
    val memory_view = val(typed_memory_view(vec.size(), vec.data()));
    val js_array = val::global("Uint8Array").new_(vec.size());
    js_array.call<void>("set", memory_view);
    return js_array;
}

// --- Key Management (Fixed for Browser Compatibility) ---
std::string last_priv = "";
std::string last_pub = "";

void generate_keys_js(int bits) {
    auto keypair = RSAKeyManager::generate_keypair(bits);
    
    RSAKeyManager::save_private_key(keypair.get(), "/virt_priv.pem");
    RSAKeyManager::save_public_key(keypair.get(), "/virt_pub.pem");

    std::ifstream priv_file("/virt_priv.pem");
    last_priv = std::string((std::istreambuf_iterator<char>(priv_file)), {});
    
    std::ifstream pub_file("/virt_pub.pem");
    last_pub = std::string((std::istreambuf_iterator<char>(pub_file)), {});
}

std::string get_priv_key() { return last_priv; }
std::string get_pub_key() { return last_pub; }

// --- Encryption/Decryption ---
val encrypt_data_js(const val& js_plaintext, const std::string& pub_key_pem) {
    SecureVector plaintext = js_to_secure_vec(js_plaintext);

    std::ofstream pub_out("/virt_pub.pem");
    pub_out << pub_key_pem << "\n";
    pub_out.close();
    auto pub_key = RSAKeyManager::load_public_key("/virt_pub.pem");

    HybridBundle bundle = HybridCrypto::encrypt(plaintext, pub_key.get());
    bundle.save("/virt_bundle.hcry");
    
    std::ifstream enc_in("/virt_bundle.hcry", std::ios::binary);
    SecureVector enc_data((std::istreambuf_iterator<char>(enc_in)), {});

    return secure_vec_to_js(enc_data);
}

val decrypt_data_js(const val& js_bundle, const std::string& priv_key_pem) {
    SecureVector enc_data = js_to_secure_vec(js_bundle);

    std::ofstream bundle_out("/virt_bundle.hcry", std::ios::binary);
    bundle_out.write(reinterpret_cast<const char*>(enc_data.data()), enc_data.size());
    bundle_out.close();

    HybridBundle bundle;
    if (!bundle.load("/virt_bundle.hcry")) return val("ERROR: Corrupt Bundle");

    std::ofstream priv_out("/virt_priv.pem");
    priv_out << priv_key_pem << "\n";
    priv_out.close();
    auto priv_key = RSAKeyManager::load_private_key("/virt_priv.pem");

    try {
        SecureVector plaintext = HybridCrypto::decrypt(bundle, priv_key.get());
        return secure_vec_to_js(plaintext);
    } catch (...) {
        return val("ERROR: Decryption Failed");
    }
}

EMSCRIPTEN_BINDINGS(hybrid_crypto_module) {
    function("generateKeys", &generate_keys_js);
    function("getPrivKey", &get_priv_key);
    function("getPubKey", &get_pub_key);
    function("encryptData", &encrypt_data_js);
    function("decryptData", &decrypt_data_js);
}