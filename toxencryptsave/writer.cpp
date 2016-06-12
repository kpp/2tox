#include "writer.hpp"
#include "mem_guard.hpp"

#include <string.h>
#include <toxcore/crypto_core.hpp>
#include <sodium.h>

#define SET_ERROR_PARAMETER(param, x) {if(param) {*param = x;}}

namespace toxencryptsave
{

bool Writer::encrypt_by_key(const uint8_t* data, size_t data_length, const TOX_PASS_KEY* key, TOX_ERR_ENCRYPTION* out_error) const
{
    if (data_length == 0 || !rw_data.base || !key || !data) {
        SET_ERROR_PARAMETER(out_error, TOX_ERR_ENCRYPTION_NULL);
        return 0;
    }

    memmove(rw_data.magic, constants::magic, constants::magic_len);
    memmove(rw_data.salt, key->salt, constants::salt_len);
    random_nonce(rw_data.nonce);

    if (encrypt_data_symmetric(key->key, rw_data.nonce, data, data_length, rw_data.crypted_raw) != data_length + crypto_box_MACBYTES) {
        SET_ERROR_PARAMETER(out_error, TOX_ERR_ENCRYPTION_FAILED);
        return 0;
    }

    SET_ERROR_PARAMETER(out_error, TOX_ERR_ENCRYPTION_OK);
    return 1;
}

bool Writer::encrypt_by_passphrase(const uint8_t* data, size_t data_length, uint8_t* passphrase, size_t pplength, TOX_ERR_ENCRYPTION* out_error) const
{
    Mem_Guard pass_guard(passphrase, pplength);
    TOX_PASS_KEY key;
    TOX_ERR_KEY_DERIVATION derivation_error;

    if ( !key.derive_from_pass_with_random_salt(pass_guard.ptr, pplength, &derivation_error) ) {
        if (derivation_error == TOX_ERR_KEY_DERIVATION_NULL) {
            SET_ERROR_PARAMETER(out_error, TOX_ERR_ENCRYPTION_NULL);
        } else if (derivation_error == TOX_ERR_KEY_DERIVATION_FAILED) {
            SET_ERROR_PARAMETER(out_error, TOX_ERR_ENCRYPTION_KEY_DERIVATION_FAILED);
        }
        return false;
    }

    return this->encrypt_by_key(data, data_length, &key, out_error);
}

}
