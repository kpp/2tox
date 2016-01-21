#include "crypto_core.hpp"

#include <sodium.h>
#include <sodium/utils.h>

#include <arpa/inet.h>
#include <string.h>
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
    if (!public_key || !secret_key)
        return -1;

    uint8_t precomputed_key[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, precomputed_key);

    int ret = encrypt_data_symmetric(precomputed_key, nonce, plain, length, encrypted);

    sodium_memzero(precomputed_key, sizeof precomputed_key);
    return ret;
}

int encrypt_data_symmetric(const uint8_t* precomputed_key, const uint8_t* nonce, const uint8_t* plain, uint32_t length,
                           uint8_t* encrypted)
{
    if (length == 0 || length > std::numeric_limits<size_t>::max() - crypto_box_MACBYTES || !precomputed_key || !nonce || !plain || !encrypted)
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
    if (!public_key || !secret_key)
        return -1;

    uint8_t precomputed_key[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, precomputed_key);

    int ret = decrypt_data_symmetric(precomputed_key, nonce, encrypted, length, plain);

    sodium_memzero(precomputed_key, sizeof precomputed_key);
    return ret;
}

int decrypt_data_symmetric(const uint8_t* precomputed_key, const uint8_t* nonce, const uint8_t* encrypted, uint32_t length,
                           uint8_t* plain)
{
    if (length < crypto_box_MACBYTES || !precomputed_key || !nonce || !encrypted || !plain)
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

void new_nonce(uint8_t* nonce)
{
    random_nonce(nonce);
}

void new_symmetric_key(uint8_t* key)
{
    randombytes(key, crypto_box_BEFORENMBYTES);
}

template<class PointerT>
struct Packet_Pointers
{
    PointerT const type;
    PointerT const recv_public_key;
    PointerT const send_public_key;
    PointerT const nonce;
    PointerT const cyphertext;

    explicit Packet_Pointers(PointerT const packet):
        type( packet + 0 ),
        recv_public_key( packet + 1 ),
        send_public_key( packet + 1 + crypto_box_PUBLICKEYBYTES ),
        nonce( packet + 1 + crypto_box_PUBLICKEYBYTES * 2 ),
        cyphertext( packet + 1 + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES)
    {}
private:
    Packet_Pointers(); // = delete
    Packet_Pointers(const Packet_Pointers&); // = delete
    Packet_Pointers& operator= (const Packet_Pointers&); // = delete
};

int create_request(const uint8_t* send_public_key, const uint8_t* send_secret_key, uint8_t* packet,
                   const uint8_t* recv_public_key, const uint8_t* data, uint32_t length, uint8_t request_id)
{
    if (MAX_CRYPTO_REQUEST_SIZE < length + 1 + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + 1 +
        crypto_box_MACBYTES)
    return -1;

    Packet_Pointers<uint8_t*> packet_ptr(packet);

    *packet_ptr.type = NET_PACKET_CRYPTO;
    memcpy(packet_ptr.recv_public_key, recv_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(packet_ptr.send_public_key, send_public_key, crypto_box_PUBLICKEYBYTES);
    new_nonce(packet_ptr.nonce);

    uint8_t message[MAX_CRYPTO_REQUEST_SIZE];
    uint8_t* const message_request_id = message + 0;
    uint8_t* const message_data = message + 1;

    *message_request_id = request_id;
    memcpy(message_data, data, length);
    const size_t message_length = length + 1 /* request_id */;

    int len = encrypt_data(recv_public_key, send_secret_key, packet_ptr.nonce, message, message_length, packet_ptr.cyphertext);

    if (len == -1)
        return -1;

    return len + 1 /*packet type*/ + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES;
}

int handle_request(const uint8_t* self_public_key, const uint8_t* self_secret_key, uint8_t* public_key, uint8_t* data,
                   uint8_t* request_id, const uint8_t* packet, uint16_t length)
{
    if (length <= 1 /*packet type*/ + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + crypto_box_MACBYTES || length > MAX_CRYPTO_REQUEST_SIZE)
        return -1;

    Packet_Pointers<const uint8_t*> packet_ptr(packet);

    if ( public_key_cmp(packet_ptr.recv_public_key, self_public_key) != 0)
        return -1;

    memcpy(public_key, packet_ptr.send_public_key, crypto_box_PUBLICKEYBYTES);

    uint8_t message[MAX_CRYPTO_REQUEST_SIZE];
    uint8_t* const message_request_id = message + 0;
    uint8_t* const message_data = message + 1;

    const int message_length = decrypt_data(public_key, self_secret_key, packet_ptr.nonce, packet_ptr.cyphertext,
                            length - (1 /*packet type*/ + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES), message);

    if (message_length == -1 /*error during decryption*/ || message_length == 0 /*result message length must be > 1, the first byte is request_id*/)
        return -1;

    *request_id = *message_request_id;
    const size_t data_length = message_length - 1 /* request_id */;
    memcpy(data, message_data, data_length);

    return data_length;
}
