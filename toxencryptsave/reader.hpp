#ifndef TOXENCRYPTSAVE_READER_H
#define TOXENCRYPTSAVE_READER_H

#include "data_description.hpp"
#include "key.hpp"

namespace toxencryptsave
{

struct Reader
{
    Data_Description<const uint8_t*> const ro_data;

    explicit Reader(const uint8_t* const raw_encryptsave_data):
        ro_data( raw_encryptsave_data )
    {}

    bool magic_is_valid() const;

    bool extract_salt_into(uint8_t* const out_salt) const;
    bool extract_key_into(uint8_t* const passphrase, size_t pplength, TOX_PASS_KEY* const out_key, TOX_ERR_KEY_DERIVATION* error) const;

    bool decrypt_by_key(size_t data_length, const TOX_PASS_KEY* key, uint8_t* out, TOX_ERR_DECRYPTION* error) const;
    bool decrypt_by_passphrase(size_t data_length, uint8_t* passphrase, size_t pplength, uint8_t* out, TOX_ERR_DECRYPTION* error) const;

private:
    Reader(); // = delete
    Reader(const Reader&); // = delete
    Reader& operator= (const Reader&); // = delete
};

}

#endif
