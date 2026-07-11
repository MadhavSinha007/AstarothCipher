#pragma once
#include <vector>
#include <cstdlib>
#include <new>
#include <openssl/crypto.h>

template <typename T>
struct SecureAllocator {
    using value_type = T;

    SecureAllocator() = default;
    template <typename U> constexpr SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        if (n > std::size_t(-1) / sizeof(T)) throw std::bad_alloc();
        if (auto p = static_cast<T*>(std::malloc(n * sizeof(T)))) {
            return p;
        }
        throw std::bad_alloc();
    }

    void deallocate(T* p, std::size_t n) noexcept {
        if (p) {
            // Securely wipe the memory with zeroes before freeing
            OPENSSL_cleanse(p, n * sizeof(T));
            std::free(p);
        }
    }
};

// --- Add these two operator overloads ---
template <class T, class U>
bool operator==(const SecureAllocator<T>&, const SecureAllocator<U>&) { return true; }

template <class T, class U>
bool operator!=(const SecureAllocator<T>&, const SecureAllocator<U>&) { return false; }
// ----------------------------------------

// The alias you will use throughout your codebase
using SecureVector = std::vector<unsigned char, SecureAllocator<unsigned char>>;