#include <emscripten/bind.h>
#include <emscripten/val.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include "hybrid.h"
#include "rsa_keys.h"
#include "secure_alloc.h"
#include <string>

using namespace emscripten;

static std::string last_priv;
static std::string last_pub;

void init_openssl_if_needed() {
    static bool initialized = false;
    if (!initialized) {
        OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
        initialized = true;
    }
}

void generate_keys_js(int bits) {
    init_openssl_if_needed();
    auto keypair = RSAKeyManager::generate_keypair(bits);
    if (!keypair) throw std::runtime_error("Keypair generation failed");

    // Private Key to Memory
    BIO* priv_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(priv_bio, keypair.get(), nullptr, nullptr, 0, nullptr, nullptr);
    BUF_MEM* priv_buf = nullptr;
    BIO_get_mem_ptr(priv_bio, &priv_buf);
    last_priv = std::string(priv_buf->data, priv_buf->length);
    BIO_free(priv_bio);

    // Public Key to Memory
    BIO* pub_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pub_bio, keypair.get());
    BUF_MEM* pub_buf = nullptr;
    BIO_get_mem_ptr(pub_bio, &pub_buf);
    last_pub = std::string(pub_buf->data, pub_buf->length);
    BIO_free(pub_bio);
}

// BULLETPROOF STRING EXTRACTION
val string_to_js_array(const std::string& str) {
    val memory_view = val(typed_memory_view(str.size(), str.data()));
    val js_array = val::global("Uint8Array").new_(str.size());
    js_array.call<void>("set", memory_view);
    return js_array;
}

val get_priv_key() { return string_to_js_array(last_priv); }
val get_pub_key() { return string_to_js_array(last_pub); }

// --- ENCRYPTION / DECRYPTION GLUE ---

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

val encrypt_data_js(const val& js_plaintext, const std::string& pub_key_pem) {
    init_openssl_if_needed();
    SecureVector plaintext = js_to_secure_vec(js_plaintext);
    auto pub_key = RSAKeyManager::load_public_key_from_string(pub_key_pem);
    if (!pub_key) throw std::runtime_error("Invalid public key");
    
    HybridBundle bundle = HybridCrypto::encrypt(plaintext, pub_key.get());
    return secure_vec_to_js(bundle.to_bytes());
}

val decrypt_data_js(const val& js_bundle, const std::string& priv_key_pem) {
    init_openssl_if_needed();
    SecureVector bundle_bytes = js_to_secure_vec(js_bundle);
    HybridBundle bundle = HybridBundle::from_bytes(bundle_bytes);

    auto priv_key = RSAKeyManager::load_private_key_from_string(priv_key_pem);
    if (!priv_key) throw std::runtime_error("Invalid private key");
    
    SecureVector plaintext = HybridCrypto::decrypt(bundle, priv_key.get());
    return secure_vec_to_js(plaintext);
}

// BINDINGS
EMSCRIPTEN_BINDINGS(hybrid_crypto_module) {
    function("generateKeys", &generate_keys_js);
    function("getPrivKey", &get_priv_key);
    function("getPubKey", &get_pub_key);
    function("encryptData", &encrypt_data_js);
    function("decryptData", &decrypt_data_js);
}