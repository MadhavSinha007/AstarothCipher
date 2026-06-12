#include "hybrid.h"
#include <iostream>
#include <string>
#include <cstring>
#include <filesystem>
namespace fs = std::filesystem;

// Show help text explaining how to use the program
static void usage(const char* prog) {
    std::cout <<
        "AES-256-GCM + RSA-4096 Hybrid Encryption Tool\n\n"
        "Usage:\n"
        "  " << prog << " genkeys        <priv.pem>   <pub.pem>     [--bits 4096]\n"
        "  " << prog << " encrypt        <file>       <out.hcry>    <pub.pem>\n"
        "  " << prog << " decrypt        <in.hcry>    <out-file>    <priv.pem>\n"
        "  " << prog << " encrypt-folder <folder/>    <out.hcry>    <pub.pem>\n"
        "  " << prog << " decrypt-folder <in.hcry>    <out-folder/> <priv.pem>\n\n"
        "Examples:\n"
        "  " << prog << " genkeys        private.pem  public.pem\n"
        "  " << prog << " encrypt        secret.txt   secret.hcry        public.pem\n"
        "  " << prog << " decrypt        secret.hcry  recovered.txt      private.pem\n"
        "  " << prog << " encrypt-folder my_docs/     my_docs.hcry       public.pem\n"
        "  " << prog << " decrypt-folder my_docs.hcry my_docs_recovered/ private.pem\n";
}

// Generate RSA key pair (private + public keys)
int cmd_genkeys(int argc, char** argv) {
    if (argc < 4) { usage(argv[0]); return 1; }
    
    // Check if user specified custom key size (default is 4096)
    int bits = 4096;
    for (int i = 4; i < argc-1; ++i)
        if (strcmp(argv[i], "--bits") == 0) bits = std::stoi(argv[i+1]);

    std::cout << "Generating RSA-" << bits << " key pair...\n";
    
    // Create the key pair
    auto kp = RSAKeyManager::generate_keypair(bits);
    
    // Save both keys to files
    if (!RSAKeyManager::save_private_key(kp.get(), argv[2])) return 1;
    if (!RSAKeyManager::save_public_key (kp.get(), argv[3])) return 1;
    
    std::cout << "  Private key -> " << argv[2] << "\n"
              << "  Public  key -> " << argv[3] << "\n"
              << "Done.\n";
    return 0;
}

// Encrypt a single file using public key
int cmd_encrypt(int argc, char** argv) {
    if (argc < 5) { usage(argv[0]); return 1; }
    
    // Load the recipient's public key
    auto pk = RSAKeyManager::load_public_key(argv[4]);
    
    std::cout << "Encrypting file: " << argv[2] << " -> " << argv[3] << "\n";
    
    // Encrypt the file
    if (!HybridCrypto::encrypt_file(argv[2], argv[3], pk.get())) {
        std::cerr << "Encryption failed.\n"; return 1;
    }
    std::cout << "Done.\n";
    return 0;
}

// Decrypt a single file using private key
int cmd_decrypt(int argc, char** argv) {
    if (argc < 5) { usage(argv[0]); return 1; }
    
    // Load our private key
    auto pk = RSAKeyManager::load_private_key(argv[4]);
    
    std::cout << "Decrypting file: " << argv[2] << " -> " << argv[3] << "\n";
    
    // Decrypt the file
    if (!HybridCrypto::decrypt_file(argv[2], argv[3], pk.get())) {
        std::cerr << "Decryption failed.\n"; return 1;
    }
    std::cout << "Done.\n";
    return 0;
}

// Encrypt an entire folder (all files and subfolders)
int cmd_encrypt_folder(int argc, char** argv) {
    if (argc < 5) { usage(argv[0]); return 1; }
    
    // Make sure the input is actually a folder
    if (!fs::is_directory(argv[2])) {
        std::cerr << "Error: " << argv[2] << " is not a directory.\n"; return 1;
    }
    
    // Load the recipient's public key
    auto pk = RSAKeyManager::load_public_key(argv[4]);
    
    // Encrypt the entire folder
    if (!HybridCrypto::encrypt_folder(argv[2], argv[3], pk.get())) {
        std::cerr << "Folder encryption failed.\n"; return 1;
    }
    std::cout << "Done.\n";
    return 0;
}

// Decrypt a folder bundle and restore all files
int cmd_decrypt_folder(int argc, char** argv) {
    if (argc < 5) { usage(argv[0]); return 1; }
    
    // Load our private key
    auto pk = RSAKeyManager::load_private_key(argv[4]);
    
    // Decrypt and restore the folder
    if (!HybridCrypto::decrypt_folder(argv[2], argv[3], pk.get())) {
        std::cerr << "Folder decryption failed.\n"; return 1;
    }
    std::cout << "Done.\n";
    return 0;
}

// Main program - figure out which command the user wants
int main(int argc, char** argv) {
    if (argc < 2) { usage(argv[0]); return 1; }
    
    std::string cmd = argv[1];
    
    // Route to the appropriate command handler
    if      (cmd == "genkeys")        return cmd_genkeys(argc, argv);
    else if (cmd == "encrypt")        return cmd_encrypt(argc, argv);
    else if (cmd == "decrypt")        return cmd_decrypt(argc, argv);
    else if (cmd == "encrypt-folder") return cmd_encrypt_folder(argc, argv);
    else if (cmd == "decrypt-folder") return cmd_decrypt_folder(argc, argv);
    else { usage(argv[0]); return 1; }
}