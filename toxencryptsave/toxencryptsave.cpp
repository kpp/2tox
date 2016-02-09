#include "toxencryptsave.hpp"
#include <toxcore/crypto_core.hpp>

#include <sodium.h>
#include <string.h>

#define TOX_ENC_SAVE_MAGIC_NUMBER "toxEsave"
#define TOX_ENC_SAVE_MAGIC_LENGTH 8

#define SET_ERROR_PARAMETER(param, x) {if(param) {*param = x;}}

#if TOX_PASS_SALT_LENGTH != crypto_pwhash_scryptsalsa208sha256_SALTBYTES
#error TOX_PASS_SALT_LENGTH is assumed to be equal to crypto_pwhash_scryptsalsa208sha256_SALTBYTES
#endif

#if TOX_PASS_KEY_LENGTH != crypto_box_BEFORENMBYTES
#error TOX_PASS_KEY_LENGTH is assumed to be equal to crypto_box_BEFORENMBYTES
#endif

#if TOX_PASS_ENCRYPTION_EXTRA_LENGTH != (crypto_box_MACBYTES + crypto_box_NONCEBYTES + crypto_pwhash_scryptsalsa208sha256_SALTBYTES + TOX_ENC_SAVE_MAGIC_LENGTH)
#error TOX_PASS_ENCRYPTION_EXTRA_LENGTH is assumed to be equal to (crypto_box_MACBYTES + crypto_box_NONCEBYTES + crypto_pwhash_scryptsalsa208sha256_SALTBYTES + TOX_ENC_SAVE_MAGIC_LENGTH)
#endif

bool tox_pass_encrypt(const uint8_t* data, size_t data_len, const uint8_t* passphrase, size_t pplength, uint8_t* out, TOX_ERR_ENCRYPTION* error)
{
    TOX_PASS_KEY key;
    TOX_ERR_KEY_DERIVATION _error;

    if (!tox_derive_key_from_pass(passphrase, pplength, &key, &_error)) {
        if (_error == TOX_ERR_KEY_DERIVATION_NULL) {
            SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_NULL);
        } else if (_error == TOX_ERR_KEY_DERIVATION_FAILED) {
            SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_KEY_DERIVATION_FAILED);
        }

        return 0;
    }

    return tox_pass_key_encrypt(data, data_len, &key, out, error);
}

bool tox_pass_decrypt(const uint8_t* data, size_t length, const uint8_t* passphrase, size_t pplength, uint8_t* out, TOX_ERR_DECRYPTION* error)
{
    if (length <= TOX_PASS_ENCRYPTION_EXTRA_LENGTH) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_INVALID_LENGTH);
        return 0;
    }

    if (!data || !passphrase || !out) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_NULL);
        return 0;
    }

    if (sodium_memcmp(data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_BAD_FORMAT);
        return 0;
    }

    uint8_t salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    memcpy(salt, data + TOX_ENC_SAVE_MAGIC_LENGTH, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);

    /* derive the key */
    TOX_PASS_KEY key;

    if (!tox_derive_key_with_salt(passphrase, pplength, salt, &key, NULL)) {
        /* out of memory most likely */
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_KEY_DERIVATION_FAILED);
        return 0;
    }

    return tox_pass_key_decrypt(data, length, &key, out, error);
}

bool tox_derive_key_from_pass(const uint8_t* passphrase, size_t pplength, TOX_PASS_KEY *out_key, TOX_ERR_KEY_DERIVATION* error)
{
    uint8_t salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    randombytes(salt, sizeof salt);
    return tox_derive_key_with_salt(passphrase, pplength, salt, out_key, error);
}

bool tox_derive_key_with_salt(const uint8_t* passphrase, size_t pplength, const uint8_t* salt, TOX_PASS_KEY* out_key, TOX_ERR_KEY_DERIVATION* error)
{
    if (!salt || !out_key || (!passphrase && pplength != 0)) {
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_NULL);
        return 0;
    }

    uint8_t passkey[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(passkey, passphrase, pplength);

    uint8_t key[crypto_box_BEFORENMBYTES];

    /* Derive a key from the password */
    /* http://doc.libsodium.org/key_derivation/README.html */
    /* note that, according to the documentation, a generic pwhash interface will be created
     * once the pwhash competition (https://password-hashing.net/) is over */
    if (crypto_pwhash_scryptsalsa208sha256(
                key, sizeof(key), (char *)passkey, sizeof(passkey), salt,
                crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE * 2, /* slightly stronger */
                crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
        /* out of memory most likely */
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_FAILED);
        return 0;
    }

    sodium_memzero(passkey, crypto_hash_sha256_BYTES); /* wipe plaintext pw */
    memcpy(out_key->salt, salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    memcpy(out_key->key, key, crypto_box_BEFORENMBYTES);
    SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_OK);
    return 1;
}

bool tox_get_salt(const uint8_t* data, uint8_t* salt)
{
    if (memcmp(data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) != 0)
        return 0;

    data += TOX_ENC_SAVE_MAGIC_LENGTH;
    memcpy(salt, data, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    return 1;
}

bool tox_pass_key_encrypt(const uint8_t* data, size_t data_len, const TOX_PASS_KEY* key, uint8_t* out, TOX_ERR_ENCRYPTION* error)
{
    if (data_len == 0 || !data || !key || !out) {
        SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_NULL);
        return 0;
    }

    /* the output data consists of, in order:
     * salt, nonce, mac, enc_data
     * where the mac is automatically prepended by the encrypt()
     * the salt+nonce is called the prefix
     * I'm not sure what else I'm supposed to do with the salt and nonce, since we
     * need them to decrypt the data
     */

    /* first add the magic number */
    memcpy(out, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH);
    out += TOX_ENC_SAVE_MAGIC_LENGTH;

    /* then add the rest prefix */
    memcpy(out, key->salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    out += crypto_pwhash_scryptsalsa208sha256_SALTBYTES;

    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);
    memcpy(out, nonce, crypto_box_NONCEBYTES);
    out += crypto_box_NONCEBYTES;

    /* now encrypt */
    if (encrypt_data_symmetric(key->key, nonce, data, data_len, out) != data_len + crypto_box_MACBYTES) {
        SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_FAILED);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_OK);
    return 1;
}

bool tox_pass_key_decrypt(const uint8_t* data, size_t length, const TOX_PASS_KEY* key, uint8_t* out, TOX_ERR_DECRYPTION* error)
{
    if (length <= TOX_PASS_ENCRYPTION_EXTRA_LENGTH) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_INVALID_LENGTH);
        return 0;
    }

    if (!data || !key || !out) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_NULL);
        return 0;
    }

    if (memcmp(data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_BAD_FORMAT);
        return 0;
    }

    data += TOX_ENC_SAVE_MAGIC_LENGTH;
    data += crypto_pwhash_scryptsalsa208sha256_SALTBYTES; // salt only affects key derivation

    size_t decrypt_length = length - TOX_PASS_ENCRYPTION_EXTRA_LENGTH;

    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, data, crypto_box_NONCEBYTES);
    data += crypto_box_NONCEBYTES;

    /* decrypt the data */
    if (decrypt_data_symmetric(key->key, nonce, data, decrypt_length + crypto_box_MACBYTES, out)
            != decrypt_length) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_FAILED);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_OK);
    return 1;
}

bool tox_is_data_encrypted(const uint8_t* data)
{
    if (memcmp(data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) == 0)
        return 1;
    else
        return 0;
}
