#include "toxencryptsave.hpp"
#include "reader.hpp"
#include "writer.hpp"
#include "mem_guard.hpp"

#include <toxcore/crypto_core.hpp>

#define SET_ERROR_PARAMETER(param, x) {if(param) {*param = x;}}

bool tox_pass_encrypt(const uint8_t* data, size_t data_len, uint8_t* passphrase, size_t pplength, uint8_t* out, TOX_ERR_ENCRYPTION* error)
{
    toxencryptsave::Writer writer(out);
    return writer.encrypt_by_passphrase(data, data_len, passphrase, pplength, error);
}

bool tox_pass_decrypt(const uint8_t* data, size_t length, uint8_t* passphrase, size_t pplength, uint8_t* out, TOX_ERR_DECRYPTION* error)
{
    toxencryptsave::Reader reader(data);
    return reader.decrypt_by_passphrase(length, passphrase, pplength, out, error);
}

bool tox_derive_key_from_pass(uint8_t* passphrase, size_t pplength, TOX_PASS_KEY* out_key, TOX_ERR_KEY_DERIVATION* error)
{
    toxencryptsave::Mem_Guard pass_guard(passphrase, pplength);
    if (!out_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_NULL);
        return false;
    }
    return out_key->derive_from_pass_with_random_salt(pass_guard.ptr, pplength, error);
}

bool tox_derive_key_with_salt(uint8_t* passphrase, size_t pplength, const uint8_t* salt, TOX_PASS_KEY* out_key, TOX_ERR_KEY_DERIVATION* error)
{
    toxencryptsave::Mem_Guard pass_guard(passphrase, pplength);
    if (!out_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_NULL);
        return false;
    }
    return out_key->derive_from_pass_with_salt(pass_guard.ptr, pplength, salt, error);
}

bool tox_get_salt(const uint8_t* data, uint8_t* salt)
{
    toxencryptsave::Reader reader(data);
    return reader.extract_salt_into(salt);
}

bool tox_pass_key_encrypt(const uint8_t* data, size_t data_len, const TOX_PASS_KEY* key, uint8_t* out, TOX_ERR_ENCRYPTION* error)
{
    toxencryptsave::Writer writer(out);
    return writer.encrypt_by_key(data, data_len, key, error);
}

bool tox_pass_key_decrypt(const uint8_t* data, size_t length, const TOX_PASS_KEY* key, uint8_t* out, TOX_ERR_DECRYPTION* error)
{
    toxencryptsave::Reader reader(data);
    return reader.decrypt_by_key(length, key, out, error);
}

bool tox_is_data_encrypted(const uint8_t* data)
{
    toxencryptsave::Reader reader(data);
    return reader.magic_is_valid();
}
