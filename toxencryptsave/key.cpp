#include "key.hpp"
#include "mem_guard.hpp"

#include <sodium.h>
#include <string.h>

#define SET_ERROR_PARAMETER(param, x) {if(param) {*param = x;}}

bool TOX_PASS_KEY::derive_from_pass_with_salt(uint8_t* passphrase, size_t pplength, const uint8_t* new_salt, TOX_ERR_KEY_DERIVATION* error)
{
    toxencryptsave::Mem_Guard pass_guard(passphrase, pplength);

    if (!new_salt || (!passphrase && pplength != 0)) {
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_NULL);
        return false;
    }

    uint8_t passkey[toxencryptsave::constants::pass_hash_len];
    crypto_hash_sha256(passkey, passphrase, pplength);
    sodium_memzero(passphrase, pplength); /* wipe plaintext pw */
    memmove(salt, new_salt, toxencryptsave::constants::salt_len);

    /* Derive a key from the password */
    /* http://doc.libsodium.org/key_derivation/README.html */
    /* note that, according to the documentation, a generic pwhash interface will be created
     * once the pwhash competition (https://password-hashing.net/) is over */
    if (crypto_pwhash_scryptsalsa208sha256(
                key, toxencryptsave::constants::pass_hash_len,
                reinterpret_cast<char*>(passkey), sizeof(passkey),
                salt,
                crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE * 2, /* slightly stronger */
                crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
        /* out of memory most likely */
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_FAILED);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_OK);
    return true;
}

bool TOX_PASS_KEY::derive_from_pass_with_random_salt(uint8_t* passphrase, size_t pplength, TOX_ERR_KEY_DERIVATION* error)
{
    toxencryptsave::Mem_Guard pass_guard(passphrase, pplength);
    uint8_t salt[toxencryptsave::constants::salt_len];
    randombytes(salt, sizeof salt);
    return this->derive_from_pass_with_salt(pass_guard.ptr, pplength, salt, error);
}

