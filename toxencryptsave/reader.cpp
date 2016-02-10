#include "reader.hpp"
#include "mem_guard.hpp"

#include <sodium.h>
#include <string.h>

#define SET_ERROR_PARAMETER(param, x) {if(param) {*param = x;}}

#include <toxcore/crypto_core.hpp>

namespace toxencryptsave
{

bool Reader::magic_is_valid() const {
    if (!ro_data.base)
        return false;

    return sodium_memcmp(ro_data.magic, constants::magic, constants::magic_len) == 0;
}

bool Reader::extract_salt_into(uint8_t*const out_salt) const {
    if (!this->magic_is_valid() || !out_salt)
        return false;

    memcpy(out_salt, ro_data.salt, constants::salt_len);
    return true;
}

bool Reader::extract_key_into(uint8_t* passphrase, size_t pplength, TOX_PASS_KEY* out_key, TOX_ERR_KEY_DERIVATION* error) const
{
    Mem_Guard pass_guard(passphrase, pplength);
    if (!ro_data.base || !out_key || (!pass_guard.ptr && pplength != 0)) {
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_NULL);
        return false;
    }

    if ( !this->extract_salt_into(out_key->salt) ) {
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_FAILED);
        return false;
    }

    return out_key->derive_from_pass_with_salt(pass_guard.ptr, pplength, out_key->salt, error);
}

bool Reader::decrypt_by_key(size_t data_length, const TOX_PASS_KEY* key, uint8_t* out, TOX_ERR_DECRYPTION* error) const
{
    if (data_length <= constants::encrypted_overhead) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_INVALID_LENGTH);
        return false;
    }

    if (!ro_data.base || !key || !out) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_NULL);
        return false;
    }

    if (!this->magic_is_valid()) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_BAD_FORMAT);
        return false;
    }

    size_t decrypt_expected_length = data_length - constants::encrypted_overhead;
    int decrypted_result = decrypt_data_symmetric(key->key, ro_data.nonce, ro_data.crypted_raw, decrypt_expected_length + crypto_box_MACBYTES, out);

    if (decrypted_result == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_FAILED);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_OK);
    return true;
}

bool Reader::decrypt_by_passphrase(size_t data_length, uint8_t* passphrase, size_t pplength, uint8_t* out, TOX_ERR_DECRYPTION* error) const
{
    Mem_Guard pass_guard(passphrase, pplength);
    /* extract the key */
    TOX_PASS_KEY key;
    TOX_ERR_KEY_DERIVATION _error;

    if ( !this->extract_key_into(pass_guard.ptr, pplength, &key, &_error)) {
        if (_error == TOX_ERR_KEY_DERIVATION_NULL) {
            SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_NULL);
        } else if ( !this->magic_is_valid() ) {
            SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_BAD_FORMAT);
        } else {
            /* out of memory most likely */
            SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_KEY_DERIVATION_FAILED);
        }
        return false;
    }

    return this->decrypt_by_key(data_length, &key, out, error);
}

}
