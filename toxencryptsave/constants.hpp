#ifndef TOXENCRYPTSAVE_CONSTANTS_H
#define TOXENCRYPTSAVE_CONSTANTS_H

#include <stddef.h>
#include <stdint.h>

// hardcoded constants
// if they change, userdata will be lost

#define TOXENCRYPTSAVE_MAGIC_NUMBER "toxEsave"
#define TOXENCRYPTSAVE_MAGIC_LENGTH 8U

#define TOXENCRYPTSAVE_SALT_LENGTH 32U
#define TOXENCRYPTSAVE_KEY_LENGTH 32U
#define TOXENCRYPTSAVE_NONCEBYTES 24U
#define TOXENCRYPTSAVE_ENCRYPTION_EXTRA_LENGTH 80U

namespace toxencryptsave
{
    namespace constants
    {
        extern const char* magic;
        static const size_t magic_len = TOXENCRYPTSAVE_MAGIC_LENGTH;
        static const size_t salt_len = TOXENCRYPTSAVE_SALT_LENGTH;
        static const size_t nonce_len = TOXENCRYPTSAVE_NONCEBYTES;
        static const size_t pass_hash_len = TOXENCRYPTSAVE_KEY_LENGTH;
        static const size_t encrypted_overhead = TOXENCRYPTSAVE_ENCRYPTION_EXTRA_LENGTH;
    }
}

#endif
