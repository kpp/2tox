#include "crypto_core.hpp"

#include <sodium.h>
#include <sodium/utils.h>

#include <arpa/inet.h>
#include <limits>

#if !(crypto_box_BEFORENMBYTES >= crypto_secretbox_KEYBYTES)
  #error "crypto_box_beforenm will not work correctly"
#endif

int public_key_cmp(const uint8_t* pk1, const uint8_t* pk2)
{
    return sodium_memcmp(pk1, pk2, crypto_box_PUBLICKEYBYTES);
}

uint32_t random_int(void)
{
    uint32_t result;
    randombytes(reinterpret_cast<uint8_t*>(&result), sizeof(result));
    return result;
}

uint64_t random_64b(void)
{
    uint64_t result;
    randombytes(reinterpret_cast<uint8_t*>(&result), sizeof(result));
    return result;
}

int public_key_valid(const uint8_t* public_key)
{
    return 0;
}

void encrypt_precompute(const uint8_t* public_key, const uint8_t* secret_key, uint8_t* precomputed_key)
{
    crypto_box_beforenm(precomputed_key, public_key, secret_key);
}


int encrypt_data(const uint8_t* public_key, const uint8_t* secret_key, const uint8_t* nonce,
                 const uint8_t* plain, uint32_t length, uint8_t* encrypted)
{
    uint8_t precomputed_key[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, precomputed_key);

    int ret = encrypt_data_symmetric(precomputed_key, nonce, plain, length, encrypted);

    sodium_memzero(precomputed_key, sizeof precomputed_key);
    return ret;
}

int encrypt_data_symmetric(const uint8_t* precomputed_key, const uint8_t* nonce, const uint8_t* plain, uint32_t length,
                           uint8_t* encrypted)
{
    if (length == 0 || length > std::numeric_limits<size_t>::max() - crypto_box_MACBYTES)
        return -1;

    int ret = crypto_secretbox_detached(encrypted + crypto_box_MACBYTES /* cyphertext */ , encrypted /* MAC */,
                                        plain, length, nonce, precomputed_key);
    if (ret != 0)
        return -1;

    return length + crypto_box_MACBYTES;
}


int decrypt_data(const uint8_t* public_key, const uint8_t* secret_key, const uint8_t* nonce,
                 const uint8_t* encrypted, uint32_t length, uint8_t* plain)
{
    uint8_t precomputed_key[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, precomputed_key);

    int ret = decrypt_data_symmetric(precomputed_key, nonce, encrypted, length, plain);

    sodium_memzero(precomputed_key, sizeof precomputed_key);
    return ret;
}

int decrypt_data_symmetric(const uint8_t* precomputed_key, const uint8_t* nonce, const uint8_t* encrypted, uint32_t length,
                           uint8_t* plain)
{
    if (length < crypto_box_MACBYTES)
        return -1;

    int ret = crypto_secretbox_open_detached(plain, encrypted + crypto_box_MACBYTES /* cyphertext */ , encrypted /* MAC */,
                                            length - crypto_box_MACBYTES, nonce, precomputed_key);
    if (ret != 0)
        return -1;

    return length - crypto_box_MACBYTES;
}

void increment_nonce(uint8_t* nonce)
{
    /* FIXME use increment_nonce_number(nonce, 1) or sodium_increment (change to little endian)
     * NOTE don't use breaks inside this loop
     * In particular, make sure, as far as possible,
     * that loop bounds and their potential underflow or overflow
     * are independent of user-controlled input (you may have heard of the Heartbleed bug).
     */
    uint32_t i = crypto_box_NONCEBYTES;
    uint_fast16_t carry = 1U;
    for (; i != 0; --i) {
        carry += (uint_fast16_t) nonce[i - 1];
        nonce[i - 1] = (uint8_t) carry;
        carry >>= 8;
    }
}

void increment_nonce_number(uint8_t* nonce, uint32_t host_order_num)
{
    /* NOTE don't use breaks inside this loop
     * In particular, make sure, as far as possible,
     * that loop bounds and their potential underflow or overflow
     * are independent of user-controlled input (you may have heard of the Heartbleed bug).
     */
    const uint32_t big_endian_num = htonl(host_order_num);
    const uint8_t* const num_vec = reinterpret_cast<const uint8_t*>( &big_endian_num );
    uint8_t num_as_nonce[crypto_box_NONCEBYTES] = {0};
    num_as_nonce[crypto_box_NONCEBYTES - 4] = num_vec[0];
    num_as_nonce[crypto_box_NONCEBYTES - 3] = num_vec[1];
    num_as_nonce[crypto_box_NONCEBYTES - 2] = num_vec[2];
    num_as_nonce[crypto_box_NONCEBYTES - 1] = num_vec[3];

    uint32_t i = crypto_box_NONCEBYTES;
    uint_fast16_t carry = 0U;
    for (; i != 0; --i) {
        carry += (uint_fast16_t) nonce[i] + (uint_fast16_t) num_as_nonce[i];
        nonce[i] = (unsigned char) carry;
        carry >>= 8;
    }
}

void random_nonce(uint8_t* nonce)
{
    randombytes_buf(nonce, crypto_box_NONCEBYTES);
}

void new_symmetric_key(uint8_t* key)
{
    return;
}

void new_nonce(uint8_t* nonce)
{
    random_nonce(nonce);
}

int create_request(const uint8_t* send_public_key, const uint8_t* send_secret_key, uint8_t* packet,
                   const uint8_t* recv_public_key, const uint8_t* data, uint32_t length, uint8_t request_id)
{
    return 0;
}

int handle_request(const uint8_t* self_public_key, const uint8_t* self_secret_key, uint8_t* public_key, uint8_t* data,
                   uint8_t* request_id, const uint8_t* packet, uint16_t length)
{
    return 0;
}
