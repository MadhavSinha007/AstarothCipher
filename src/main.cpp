#include "hybrid.h"
#include <iostream>
#include <string>
#include <cstring>

static void usage(const char* prog) {
    std::cout << "AES-256-GCM + RSA-4096 Hybrid Encryption Tool\n\n"
              << "Usage:\n"
              << "  " << prog << " genkeys  <priv.pem> <pub.pem>  [--bits 4096]\n"
              << "  " << prog << " encrypt  <input>  <output.hcry>  <pub.pem>\n"
              << "  " << prog << " decrypt  <input.hcry>  <output>  <priv.pem>\n\n"
              << "Examples:\n"
              << "  " << prog << " genkeys  private.pem  public.pem\n"
              << "  " << prog << " encrypt  secret.txt  secret.hcry  public.pem\n"
              << "  " << prog << " decrypt  secret.hcry recovered.txt  private.pem\n";
}

int cmd_genkeys(int argc, char** argv) {
    if (argc < 4) { usage(argv[0]); return 1; }
    std::string priv_path = argv[2];
    std::string pub_path  = argv[3];
    int bits = 4096;
    for (int i = 4; i < argc-1; ++i)
        if (strcmp(argv[i], "--bits") == 0) bits = std::stoi(argv[i+1]);

    std::cout << "Generating RSA-" << bits << " key pair...\n";
    auto kp = RSAKeyManager::generate_keypair(bits);
    if (!RSAKeyManager::save_private_key(kp.get(), priv_path)) return 1;
    if (!RSAKeyManager::save_public_key (kp.get(), pub_path))  return 1;
    std::cout << "  Private key -> " << priv_path << "\n"
              << "  Public  key -> " << pub_path  << "\n"
              << "Done.\n";
    return 0;
}

int cmd_encrypt(int argc, char** argv) {
    if (argc < 5) { usage(argv[0]); return 1; }
    auto pk = RSAKeyManager::load_public_key(argv[4]);
    std::cout << "Encrypting: " << argv[2] << " -> " << argv[3] << "\n";
    if (!HybridCrypto::encrypt_file(argv[2], argv[3], pk.get())) {
        std::cerr << "Encryption failed.\n"; return 1;
    }
    std::cout << "Done.\n";
    return 0;
}

int cmd_decrypt(int argc, char** argv) {
    if (argc < 5) { usage(argv[0]); return 1; }
    auto pk = RSAKeyManager::load_private_key(argv[4]);
    std::cout << "Decrypting: " << argv[2] << " -> " << argv[3] << "\n";
    if (!HybridCrypto::decrypt_file(argv[2], argv[3], pk.get())) {
        std::cerr << "Decryption failed.\n"; return 1;
    }
    std::cout << "Done.\n";
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(argv[0]); return 1; }
    std::string cmd = argv[1];
    if      (cmd == "genkeys") return cmd_genkeys(argc, argv);
    else if (cmd == "encrypt") return cmd_encrypt(argc, argv);
    else if (cmd == "decrypt") return cmd_decrypt(argc, argv);
    else { usage(argv[0]); return 1; }
}