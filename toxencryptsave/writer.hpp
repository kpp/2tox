#ifndef TOXENCRYPTSAVE_WRITER_H
#define TOXENCRYPTSAVE_WRITER_H

#include "data_description.hpp"
#include "key.hpp"

namespace toxencryptsave
{

struct Writer /* encryptsave data writer */
{
    Data_Description<uint8_t*> const rw_data;

    explicit Writer(uint8_t* const raw_encryptsave_data):
        rw_data( raw_encryptsave_data )
    {}

    bool encrypt_by_key(const uint8_t* data, size_t data_length, const TOX_PASS_KEY* key, TOX_ERR_ENCRYPTION* error) const;
    bool encrypt_by_passphrase(const uint8_t* data, size_t data_length, uint8_t* passphrase, size_t pplength, TOX_ERR_ENCRYPTION* error) const;

private:
    Writer(); // = delete
    Writer(const Writer&); // = delete
    Writer& operator= (const Writer&); // = delete
};

}

#endif
