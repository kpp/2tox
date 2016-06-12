#ifndef TOXENCRYPTSAVE_KEY_H
#define TOXENCRYPTSAVE_KEY_H

#include "constants.hpp"
#include "error_status.hpp"

/* This key structure's internals should not be used by any client program, even
 * if they are straightforward here.
 */

struct TOX_PASS_KEY
{
    uint8_t salt[TOXENCRYPTSAVE_SALT_LENGTH];
    uint8_t key[TOXENCRYPTSAVE_KEY_LENGTH];

    bool derive_from_pass_with_salt(uint8_t* passphrase, size_t pplength, const uint8_t* salt, TOX_ERR_KEY_DERIVATION* out_error);
    bool derive_from_pass_with_random_salt(uint8_t* passphrase, size_t pplength, TOX_ERR_KEY_DERIVATION* out_error);
};

#endif
