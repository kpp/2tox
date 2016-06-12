#include "constants.hpp"

#include <sodium.h>

const char* toxencryptsave::constants::magic = TOXENCRYPTSAVE_MAGIC_HEADER;

#if TOXENCRYPTSAVE_SALT_LENGTH != crypto_pwhash_scryptsalsa208sha256_SALTBYTES
#error TOXENCRYPTSAVE_SALT_LENGTH is assumed to be equal to crypto_pwhash_scryptsalsa208sha256_SALTBYTES
#endif

#if TOXENCRYPTSAVE_KEY_LENGTH != crypto_box_BEFORENMBYTES
#error TOXENCRYPTSAVE_KEY_LENGTH is assumed to be equal to crypto_box_BEFORENMBYTES
#endif

#if TOXENCRYPTSAVE_NONCEBYTES != crypto_box_NONCEBYTES
#error TOXENCRYPTSAVE_NONCEBYTES is assumed to be equal to crypto_box_NONCEBYTES
#endif

#if TOXENCRYPTSAVE_ENCRYPTION_EXTRA_LENGTH != (crypto_box_MACBYTES + TOXENCRYPTSAVE_NONCEBYTES + TOXENCRYPTSAVE_SALT_LENGTH + TOXENCRYPTSAVE_MAGIC_LENGTH)
#error TOXENCRYPTSAVE_ENCRYPTION_EXTRA_LENGTH is assumed to be equal to (crypto_box_MACBYTES + TOXENCRYPTSAVE_NONCEBYTES + TOXENCRYPTSAVE_SALT_LENGTH + TOXENCRYPTSAVE_MAGIC_LENGTH)
#endif
