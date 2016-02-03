#include <gtest/gtest.h>
#include <toxcore/crypto_core.hpp>
#include <sodium.h>

#include <algorithm>

std::string nonce_to_string(uint8_t* nonce) {
    char hex[2*crypto_box_NONCEBYTES+1];
    sodium_bin2hex(hex, sizeof(hex), nonce, crypto_box_NONCEBYTES);
    return std::string(hex);
}

TEST(random, ui32)
{
    uint32_t a = random_int();
    uint32_t b = random_int();
    ASSERT_FALSE(a == b) << "You are very lucky this test has failed for you. The probability to fail equals 5.4*10^-20";
}

TEST(random, ui64)
{
    uint64_t a = random_64b();
    uint64_t b = random_64b();
    ASSERT_FALSE(a == b) << "You are very lucky this test has failed for you. The probability to fail equals 2.9*10^-39";
}

TEST(nonce, new)
{
    uint8_t nonce[crypto_box_NONCEBYTES] = {0};
    ASSERT_STREQ("000000000000000000000000000000000000000000000000", nonce_to_string(nonce).c_str());
    new_nonce(nonce);
    ASSERT_STRNE("000000000000000000000000000000000000000000000000", nonce_to_string(nonce).c_str()) << "You are very lucky this test has failed for you. The probability to fail equals 1.59*10^-58";
}

TEST(nonce, increment)
{
    {
        SCOPED_TRACE("0+1=1");
        uint8_t nonce[crypto_box_NONCEBYTES] = {0};
        ASSERT_STREQ("000000000000000000000000000000000000000000000000", nonce_to_string(nonce).c_str());
        increment_nonce(nonce);
        ASSERT_STREQ("000000000000000000000000000000000000000000000001", nonce_to_string(nonce).c_str());
    }
    {
        SCOPED_TRACE("f+1=10");
        uint8_t nonce[crypto_box_NONCEBYTES] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x0f};
        ASSERT_STREQ("00000000000000000000000000000000000000000000000f", nonce_to_string(nonce).c_str());
        increment_nonce(nonce);
        ASSERT_STREQ("000000000000000000000000000000000000000000000010", nonce_to_string(nonce).c_str());
    }
    {
        SCOPED_TRACE("ff+1=100");
        uint8_t nonce[crypto_box_NONCEBYTES] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xff};
        ASSERT_STREQ("0000000000000000000000000000000000000000000000ff", nonce_to_string(nonce).c_str());
        increment_nonce(nonce);
        ASSERT_STREQ("000000000000000000000000000000000000000000000100", nonce_to_string(nonce).c_str());
    }
}

TEST(nonce, increment_number)
{
    {
        SCOPED_TRACE("ff100000+f00000=100000000");
        uint8_t nonce[crypto_box_NONCEBYTES] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xff,0x10,0,0};
        ASSERT_STREQ("0000000000000000000000000000000000000000ff100000", nonce_to_string(nonce).c_str());
        increment_nonce_number(nonce, 0xf00000);
        ASSERT_STREQ("000000000000000000000000000000000000000100000000", nonce_to_string(nonce).c_str());
    }
    {
        SCOPED_TRACE("memory overlapping");
        // we will check increment_nonce_number not to access memory before and after nonce:
        // [byte_before][n][o][n][c][e][...][byte_after]
        // set byte_before and byte_after to 1, the value should not ever change
        // set each byte of nonce to 0xff to increment every byte of nonce

        uint8_t mem[crypto_box_NONCEBYTES + 2] = {0}; // we will check 1 bytes before nonce and 1 byte after nonce

        uint8_t* byte_before = mem + 0;
        uint8_t* nonce = mem + 1;
        uint8_t* byte_after = mem + crypto_box_NONCEBYTES + 1;

        *byte_before = 1;
        *byte_after = 1;
        // set each byte of nonce to 0xff
        for(uint8_t* byte = nonce; byte < nonce + crypto_box_NONCEBYTES; ++byte) {
            *byte = 0xff;
        }

        ASSERT_EQ(1, *byte_before);
        ASSERT_EQ(1, *byte_after);

        increment_nonce_number(nonce, 1);

        {
            SCOPED_TRACE("check bytes before and after were not changed");
            ASSERT_EQ(1, *byte_before);
            ASSERT_EQ(1, *byte_after);
        }
        {
            SCOPED_TRACE("check nonce");
            ASSERT_STREQ("000000000000000000000000000000000000000000000000", nonce_to_string(nonce).c_str());
        }
    }
}

TEST(pub_key, cmp)
{
    uint8_t alice_publickey[crypto_box_PUBLICKEYBYTES] = {0};
    uint8_t alice_secretkey[crypto_box_SECRETKEYBYTES] = {0};

    uint8_t bob_publickey[crypto_box_PUBLICKEYBYTES] = {0};
    uint8_t bob_secretkey[crypto_box_SECRETKEYBYTES] = {0};

    {
        SCOPED_TRACE("empty = empty");
        ASSERT_EQ(0, public_key_cmp(alice_publickey, bob_publickey));
        ASSERT_EQ(0, public_key_cmp(bob_publickey, alice_publickey));
    }

    crypto_box_keypair(alice_publickey, alice_secretkey);
    crypto_box_keypair(bob_publickey, bob_secretkey);

    {
        SCOPED_TRACE("alice != bob");
        ASSERT_EQ(-1, public_key_cmp(alice_publickey, bob_publickey));
        ASSERT_EQ(-1, public_key_cmp(bob_publickey, alice_publickey));
    }

    {
        SCOPED_TRACE("alice = alice & bob = bob");
        ASSERT_EQ(0, public_key_cmp(alice_publickey, alice_publickey));
        ASSERT_EQ(0, public_key_cmp(bob_publickey, bob_publickey));
    }
}

TEST(encrypt_decrypt, alice_bob)
{
    uint8_t alice_publickey[crypto_box_PUBLICKEYBYTES] = {0};
    uint8_t alice_secretkey[crypto_box_SECRETKEYBYTES] = {0};

    uint8_t bob_publickey[crypto_box_PUBLICKEYBYTES] = {0};
    uint8_t bob_secretkey[crypto_box_SECRETKEYBYTES] = {0};

    crypto_box_keypair(alice_publickey, alice_secretkey);
    crypto_box_keypair(bob_publickey, bob_secretkey);

    uint8_t nonce[crypto_box_NONCEBYTES] = {0};
    new_nonce(nonce);

    std::string data = "Hello world!";

    size_t cyphertext_len = data.length() + crypto_box_MACBYTES;
    uint8_t* cyphertext = reinterpret_cast<uint8_t*>( malloc(cyphertext_len) );

    size_t message_len = data.length();
    uint8_t* message = reinterpret_cast<uint8_t*>( malloc(message_len) );

    {
        SCOPED_TRACE("bad args for encryption");
        {
            SCOPED_TRACE("empty data");
            ASSERT_EQ(-1, encrypt_data(bob_publickey, alice_secretkey, nonce, reinterpret_cast<const uint8_t*>(data.c_str()), 0, cyphertext) );
        }
        {
            SCOPED_TRACE("null ptrs");
            ASSERT_EQ(-1, encrypt_data(bob_publickey, alice_secretkey, nonce, reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), NULL) );
            ASSERT_EQ(-1, encrypt_data(bob_publickey, alice_secretkey, nonce, NULL, data.length(), cyphertext) );
            ASSERT_EQ(-1, encrypt_data(bob_publickey, alice_secretkey, NULL, reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), cyphertext) );
            ASSERT_EQ(-1, encrypt_data(bob_publickey, NULL, nonce, reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), cyphertext) );
            ASSERT_EQ(-1, encrypt_data(NULL, alice_secretkey, nonce, reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), cyphertext) );
        }
    }

    ASSERT_EQ(cyphertext_len, encrypt_data(bob_publickey, alice_secretkey, nonce, reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), cyphertext) );

    {
        SCOPED_TRACE("bad args for decryption");
        {
            SCOPED_TRACE("bad keys");
            ASSERT_EQ(-1, decrypt_data(alice_publickey, alice_secretkey, nonce, cyphertext, cyphertext_len, message) );
            ASSERT_EQ(-1, decrypt_data(bob_publickey, bob_secretkey, nonce, cyphertext, cyphertext_len, message) );
        }
        {
            SCOPED_TRACE("bad nonce");
            uint8_t bad_nonce[crypto_box_NONCEBYTES] = {0};
            new_nonce(bad_nonce);
            ASSERT_EQ(-1, decrypt_data(alice_publickey, bob_secretkey, bad_nonce, cyphertext, cyphertext_len, message) );
            ASSERT_EQ(-1, decrypt_data(bob_publickey, alice_secretkey, bad_nonce, cyphertext, cyphertext_len, message) );
        }
        {
            SCOPED_TRACE("empty cyphertext");
            ASSERT_EQ(-1, decrypt_data(alice_publickey, bob_secretkey, nonce, cyphertext, 0, message) );
            ASSERT_EQ(-1, decrypt_data(bob_publickey, alice_secretkey, nonce, cyphertext, 0, message) );
        }
        {
            SCOPED_TRACE("null ptrs");
            ASSERT_EQ(-1, decrypt_data(alice_publickey, bob_secretkey, nonce, cyphertext, cyphertext_len, NULL) );
            ASSERT_EQ(-1, decrypt_data(bob_publickey, alice_secretkey, nonce, cyphertext, cyphertext_len, NULL) );
            ASSERT_EQ(-1, decrypt_data(alice_publickey, bob_secretkey, nonce, NULL, cyphertext_len, message) );
            ASSERT_EQ(-1, decrypt_data(bob_publickey, alice_secretkey, nonce, NULL, cyphertext_len, message) );
            ASSERT_EQ(-1, decrypt_data(alice_publickey, bob_secretkey, NULL, cyphertext, cyphertext_len, message) );
            ASSERT_EQ(-1, decrypt_data(bob_publickey, alice_secretkey, NULL, cyphertext, cyphertext_len, message) );
            ASSERT_EQ(-1, decrypt_data(alice_publickey, NULL, nonce, cyphertext, cyphertext_len, message) );
            ASSERT_EQ(-1, decrypt_data(bob_publickey, NULL, nonce, cyphertext, cyphertext_len, message) );
            ASSERT_EQ(-1, decrypt_data(NULL, bob_secretkey, nonce, cyphertext, cyphertext_len, message) );
            ASSERT_EQ(-1, decrypt_data(NULL, alice_secretkey, nonce, cyphertext, cyphertext_len, message) );
        }
    }
    {
        SCOPED_TRACE("good args for symmetric decryption");
        ASSERT_EQ(message_len, decrypt_data(alice_publickey, bob_secretkey, nonce, cyphertext, cyphertext_len, message) );
        ASSERT_EQ(message_len, decrypt_data(bob_publickey, alice_secretkey, nonce, cyphertext, cyphertext_len, message) );
    }

    std::string message_str(reinterpret_cast<const char*>(message), message_len);
    ASSERT_EQ(data, message_str);

    free(cyphertext);
    free(message);
}

TEST(request, create_and_handle)
{
    uint8_t alice_publickey[crypto_box_PUBLICKEYBYTES] = {0};
    uint8_t alice_secretkey[crypto_box_SECRETKEYBYTES] = {0};

    uint8_t bob_publickey[crypto_box_PUBLICKEYBYTES] = {0};
    uint8_t bob_secretkey[crypto_box_SECRETKEYBYTES] = {0};

    crypto_box_keypair(alice_publickey, alice_secretkey);
    crypto_box_keypair(bob_publickey, bob_secretkey);

    uint8_t nonce[crypto_box_NONCEBYTES] = {0};
    new_nonce(nonce);

    std::string data = "Hello world!";

    size_t packet_len = data.length() + 1 /*request_id*/ + 1 /*packet type*/ + crypto_box_MACBYTES + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES;
    uint8_t* packet = reinterpret_cast<uint8_t*>( malloc(packet_len) );

    size_t message_len = data.length();
    uint8_t* message = reinterpret_cast<uint8_t*>( malloc(message_len) );

    const uint8_t request_id = 42;

    {
        SCOPED_TRACE("bad args to create request");
        {
            SCOPED_TRACE("too long data");
            ASSERT_EQ(-1, create_request(alice_publickey, alice_secretkey, packet, bob_publickey, reinterpret_cast<const uint8_t*>(data.c_str()), MAX_CRYPTO_REQUEST_SIZE, request_id));
        }
        {
            SCOPED_TRACE("null ptrs");
            ASSERT_EQ(-1, create_request(alice_publickey, alice_secretkey, packet, bob_publickey, NULL, data.length(), request_id));
            ASSERT_EQ(-1, create_request(alice_publickey, alice_secretkey, packet, NULL, reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), request_id));
            ASSERT_EQ(-1, create_request(alice_publickey, alice_secretkey, NULL, bob_publickey, reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), request_id));
            ASSERT_EQ(-1, create_request(alice_publickey, NULL, packet, bob_publickey, reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), request_id));
            ASSERT_EQ(-1, create_request(NULL, alice_secretkey, packet, bob_publickey, reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), request_id));
        }
    }
    ASSERT_EQ(packet_len, create_request(alice_publickey, alice_secretkey, packet, bob_publickey, reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), request_id));

    {
        SCOPED_TRACE("bad args to handle request");
        {
            SCOPED_TRACE("packet length");
            uint8_t handled_request_id = 0;
            uint8_t handled_publickey[crypto_box_PUBLICKEYBYTES] = {0};
            ASSERT_EQ(-1, handle_request(bob_publickey, bob_secretkey, handled_publickey, message, &handled_request_id, packet, MAX_CRYPTO_REQUEST_SIZE + 42));
            ASSERT_EQ(-1, handle_request(bob_publickey, bob_secretkey, handled_publickey, message, &handled_request_id, packet, 0));
        }
        {
            SCOPED_TRACE("null ptrs");
            uint8_t handled_request_id = 0;
            uint8_t handled_publickey[crypto_box_PUBLICKEYBYTES] = {0};
            ASSERT_EQ(-1, handle_request(bob_publickey, bob_secretkey, handled_publickey, message, &handled_request_id, NULL, packet_len));
            ASSERT_EQ(-1, handle_request(bob_publickey, bob_secretkey, handled_publickey, message, NULL, packet, packet_len));
            ASSERT_EQ(-1, handle_request(bob_publickey, bob_secretkey, handled_publickey, NULL, &handled_request_id, packet, packet_len));
            ASSERT_EQ(-1, handle_request(bob_publickey, bob_secretkey, NULL, message, &handled_request_id, packet, packet_len));
            ASSERT_EQ(-1, handle_request(bob_publickey, NULL, handled_publickey, message, &handled_request_id, packet, packet_len));
            ASSERT_EQ(-1, handle_request(NULL, bob_secretkey, handled_publickey, message, &handled_request_id, packet, packet_len));
        }
        {
            SCOPED_TRACE("wrong keys");
            uint8_t handled_request_id = 0;
            uint8_t handled_publickey[crypto_box_PUBLICKEYBYTES] = {0};
            ASSERT_EQ(-1, handle_request(alice_publickey, bob_secretkey, handled_publickey, message, &handled_request_id, packet, packet_len));
            ASSERT_EQ(-1, handle_request(bob_publickey, alice_secretkey, handled_publickey, message, &handled_request_id, packet, packet_len));
            ASSERT_EQ(-1, handle_request(alice_publickey, alice_secretkey, handled_publickey, message, &handled_request_id, packet, packet_len));
        }
    }
    {
        SCOPED_TRACE("good args to handle request");
        uint8_t handled_request_id = 0;
        uint8_t handled_publickey[crypto_box_PUBLICKEYBYTES] = {0};

        ASSERT_EQ(message_len, handle_request(bob_publickey, bob_secretkey, handled_publickey, message, &handled_request_id, packet, packet_len));
        ASSERT_EQ(NET_PACKET_CRYPTO, packet[0]);

        ASSERT_EQ(request_id, handled_request_id);
        ASSERT_EQ(0, public_key_cmp(alice_publickey, handled_publickey));

        std::string message_str(reinterpret_cast<const char*>(message), message_len);
        ASSERT_EQ(data, message_str);
    }

    free(packet);
    free(message);
}
