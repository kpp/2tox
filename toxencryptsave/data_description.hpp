#ifndef TOXENCRYPTSAVE_DATA_DESCRIPTION_H
#define TOXENCRYPTSAVE_DATA_DESCRIPTION_H

#include "constants.hpp"

namespace toxencryptsave
{

namespace offsets
{
    static const size_t base = 0;
    static const size_t magic = base;
    static const size_t salt = magic + constants::magic_len;
    static const size_t nonce = salt + constants::salt_len;
    static const size_t crypted_raw = nonce + constants::nonce_len;
};

template<class PointerT>
struct Data_Description /* encryptsave data offsets + length */
{
    PointerT const base; // 0 offset from the given pointer to data
    PointerT const magic;
    PointerT const salt;
    PointerT const nonce;
    PointerT const crypted_raw;

    explicit Data_Description(PointerT const data):
        base( data + offsets::base ),
        magic( data + offsets::magic ),
        salt( data + offsets::salt ),
        nonce( data + offsets::nonce ),
        crypted_raw( data + offsets::crypted_raw )
    {}

private:
    Data_Description(); // = delete
    Data_Description(const Data_Description&); // = delete
    Data_Description& operator= (const Data_Description&); // = delete
};

}

#endif
