#pragma once
#include <vector>
#include <cstdlib>
#include <new>
#include <openssl/crypto.h>

//custom allocator that securely wipe memory before releaing it.
template <typename T>
struct SecureAllocator {

    //T is the type of object this allocator manages
    using value_type = T;

    SecureAllocator() = default;

    //allows the allocator to be used with different types of objects
    template <typename U> constexpr SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        //prevent integer overflow when calculating the size to allocate
        if (n > std::size_t(-1) / sizeof(T)) throw std::bad_alloc();
        //allocate raw memory uisng malloc
        if (auto p = static_cast<T*>(std::malloc(n * sizeof(T)))) {
            return p;
        }
        throw std::bad_alloc();
    }

    void deallocate(T* p, std::size_t n) noexcept {
        if (p) {
            // Securely wipe the memory before freeing it
            OPENSSL_cleanse(p, n * sizeof(T));
            std::free(p);
        }
    }
};

// Create a friendly alias for your secure byte array
using SecureVector = std::vector<unsigned char, SecureAllocator<unsigned char>>;