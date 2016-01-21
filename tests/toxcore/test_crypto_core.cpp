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
    sodium_init(); // for sodium_malloc

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
    uint8_t* cyphertext = reinterpret_cast<uint8_t*>( sodium_malloc(cyphertext_len) );

    size_t message_len = data.length();
    uint8_t* message = reinterpret_cast<uint8_t*>( sodium_malloc(message_len) );

    ASSERT_EQ(cyphertext_len, encrypt_data(bob_publickey, alice_secretkey, nonce, reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), cyphertext) );
    ASSERT_EQ(message_len, decrypt_data(alice_publickey, bob_secretkey, nonce, cyphertext, cyphertext_len, message) );

    std::string message_str(reinterpret_cast<const char*>(message), message_len);
    ASSERT_EQ(data, message_str);

    sodium_free(cyphertext);
}
