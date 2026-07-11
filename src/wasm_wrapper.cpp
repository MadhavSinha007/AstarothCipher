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

// BULLETPROOF STRING EXTRACTION: Copy string to isolated JS Uint8Array
val string_to_js_array(const std::string& str) {
    val memory_view = val(typed_memory_view(str.size(), str.data()));
    val js_array = val::global("Uint8Array").new_(str.size());
    js_array.call<void>("set", memory_view);
    return js_array;
}

val get_priv_key() { return string_to_js_array(last_priv); }
val get_pub_key() { return string_to_js_array(last_pub); }

EMSCRIPTEN_BINDINGS(hybrid_crypto_module) {
    function("generateKeys", &generate_keys_js);
    function("getPrivKey", &get_priv_key);
    function("getPubKey", &get_pub_key);
}