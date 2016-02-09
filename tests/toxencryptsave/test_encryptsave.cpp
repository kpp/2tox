#include <gtest/gtest.h>
#include <toxencryptsave/toxencryptsave.hpp>

::testing::AssertionResult pass_was_zeroed(const uint8_t* const passphrase, const size_t pplength)
{
    for(size_t i = 0; i + 1 < pplength; ++i) {
        if (passphrase[i] != 0)
            return ::testing::AssertionFailure() << "non zero char at " << i << " position";
    }
    return ::testing::AssertionSuccess() << "passphrase was zeroed";
}

class tox_derive_key_from_pass : public ::testing::Test
{
public:
    static const char*  s_pass;
    static const size_t s_pass_len;

    uint8_t* passphrase;
    size_t pplength;
    TOX_PASS_KEY key;
    TOX_ERR_KEY_DERIVATION key_derivation_error;

    tox_derive_key_from_pass() : passphrase(NULL), pplength(), key(), key_derivation_error() {}
    ~tox_derive_key_from_pass() {}

    virtual void SetUp() {
        pplength = s_pass_len;
        passphrase = new uint8_t[ pplength ];
        memmove(passphrase, s_pass, pplength);
    }
    virtual void TearDown() {
        delete[] passphrase;
    }
};
const char*  tox_derive_key_from_pass::s_pass = "12345678";
const size_t tox_derive_key_from_pass::s_pass_len = strlen(s_pass);

TEST_F(tox_derive_key_from_pass, all_args_are_good) {
    EXPECT_TRUE( ::tox_derive_key_from_pass(passphrase, pplength, &key, &key_derivation_error) );
    EXPECT_EQ(TOX_ERR_KEY_DERIVATION_OK, key_derivation_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_derive_key_from_pass, len_is_zero_passphrase_is_null) {
    EXPECT_TRUE( ::tox_derive_key_from_pass(NULL, 0, &key, &key_derivation_error) );
    EXPECT_EQ(TOX_ERR_KEY_DERIVATION_OK, key_derivation_error);
    EXPECT_FALSE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_derive_key_from_pass, len_is_zero_passphrase_is_not_null) {
    EXPECT_TRUE( ::tox_derive_key_from_pass(passphrase, 0, &key, &key_derivation_error) );
    EXPECT_EQ(TOX_ERR_KEY_DERIVATION_OK, key_derivation_error);
    EXPECT_FALSE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_derive_key_from_pass, error_is_null) {
    EXPECT_TRUE( ::tox_derive_key_from_pass(passphrase, pplength, &key, NULL) );
    EXPECT_EQ(TOX_ERR_KEY_DERIVATION_OK, key_derivation_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_derive_key_from_pass, passphrase_is_null) {
    EXPECT_FALSE( ::tox_derive_key_from_pass(NULL, pplength, &key, &key_derivation_error) );
    EXPECT_EQ(TOX_ERR_KEY_DERIVATION_NULL, key_derivation_error);
    EXPECT_FALSE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_derive_key_from_pass, key_is_null) {
    EXPECT_FALSE( ::tox_derive_key_from_pass(passphrase, pplength, NULL, &key_derivation_error) );
    EXPECT_EQ(TOX_ERR_KEY_DERIVATION_NULL, key_derivation_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}


class tox_pass_key_encrypt : public ::testing::Test
{
public:
    static const char*  s_pass;
    static const size_t s_pass_len;

    static const uint8_t* s_data;
    static const size_t   s_data_len;

    static TOX_PASS_KEY s_key;

    uint8_t* encrypted_out;
    size_t   encrypted_len;
    TOX_ERR_ENCRYPTION encryption_error;

    tox_pass_key_encrypt() : encrypted_out(), encrypted_len(), encryption_error() {}
    ~tox_pass_key_encrypt() {}

    static void SetUpTestCase() {
        uint8_t* passphrase = new uint8_t[ s_pass_len ];
        memmove(passphrase, s_pass, s_pass_len);

        ASSERT_TRUE( ::tox_derive_key_from_pass(passphrase, s_pass_len, &s_key, NULL) );
        ASSERT_TRUE( pass_was_zeroed(passphrase, s_pass_len) );

        delete[] passphrase;
    }
    static void TearDownTestCase() {
    }

    virtual void SetUp() {
        encrypted_len = s_data_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
        encrypted_out = new uint8_t[encrypted_len];
    }
    virtual void TearDown() {
        delete[] encrypted_out;
    }
};
const char*  tox_pass_key_encrypt::s_pass = "12345678";
const size_t tox_pass_key_encrypt::s_pass_len = strlen(s_pass);
const uint8_t* tox_pass_key_encrypt::s_data = reinterpret_cast<const uint8_t*>("hello world");
const size_t   tox_pass_key_encrypt::s_data_len = 11;
TOX_PASS_KEY tox_pass_key_encrypt::s_key;

TEST_F(tox_pass_key_encrypt, all_args_are_good) {
    EXPECT_TRUE( ::tox_pass_key_encrypt(s_data, s_data_len, &s_key, encrypted_out, &encryption_error) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_OK, encryption_error);
}

TEST_F(tox_pass_key_encrypt, error_is_null) {
    EXPECT_TRUE( ::tox_pass_key_encrypt(s_data, s_data_len, &s_key, encrypted_out, NULL) );
}

TEST_F(tox_pass_key_encrypt, data_len_is_zero_data_is_null) {
    EXPECT_FALSE( ::tox_pass_key_encrypt(NULL, 0, &s_key, encrypted_out, &encryption_error) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_NULL, encryption_error);
}

TEST_F(tox_pass_key_encrypt, data_len_is_zero_data_is_not_null) {
    EXPECT_FALSE( ::tox_pass_key_encrypt(s_data, 0, &s_key, encrypted_out, &encryption_error) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_NULL, encryption_error);
}

TEST_F(tox_pass_key_encrypt, data_is_null) {
    EXPECT_FALSE( ::tox_pass_key_encrypt(NULL, s_data_len, &s_key, encrypted_out, &encryption_error) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_NULL, encryption_error);
}

TEST_F(tox_pass_key_encrypt, key_is_null) {
    EXPECT_FALSE( ::tox_pass_key_encrypt(s_data, s_data_len, NULL, encrypted_out, &encryption_error) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_NULL, encryption_error);
}

TEST_F(tox_pass_key_encrypt, out_is_null) {
    EXPECT_FALSE( ::tox_pass_key_encrypt(s_data, s_data_len, &s_key, NULL, &encryption_error) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_NULL, encryption_error);
}

class tox_is_data_encrypted : public ::testing::Test
{
public:
    tox_is_data_encrypted() {}
    ~tox_is_data_encrypted() {}

    static const char*  s_pass;
    static const size_t s_pass_len;

    static const uint8_t* s_data;
    static const size_t   s_data_len;

    static uint8_t* s_encrypted_out;
    static size_t   s_encrypted_len;

    static void SetUpTestCase() {
        uint8_t* passphrase = new uint8_t[ s_pass_len ];
        memmove(passphrase, s_pass, s_pass_len);

        s_encrypted_len = s_data_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
        s_encrypted_out = new uint8_t[s_encrypted_len];

        ASSERT_TRUE( ::tox_pass_encrypt(s_data, s_data_len, passphrase, s_pass_len, s_encrypted_out, NULL) );
        delete[] passphrase;
    }
    static void TearDownTestCase() {
        delete[] s_encrypted_out;
    }

    virtual void SetUp() {
    }
    virtual void TearDown() {
    }
};
const char*  tox_is_data_encrypted::s_pass = "12345678";
const size_t tox_is_data_encrypted::s_pass_len = strlen(s_pass);
const uint8_t* tox_is_data_encrypted::s_data = reinterpret_cast<const uint8_t*>("hello world");
const size_t   tox_is_data_encrypted::s_data_len = 11;
uint8_t* tox_is_data_encrypted::s_encrypted_out;
size_t   tox_is_data_encrypted::s_encrypted_len;

TEST_F(tox_is_data_encrypted, really_encrypted) {
    EXPECT_TRUE( ::tox_is_data_encrypted(s_encrypted_out) );
}

TEST_F(tox_is_data_encrypted, arg_is_null) {
    EXPECT_FALSE( ::tox_is_data_encrypted(NULL) );
}

TEST_F(tox_is_data_encrypted, zero_mem) {
    uint8_t* mem = new uint8_t[s_encrypted_len];
    memset(mem, 0, s_encrypted_len);
    EXPECT_FALSE( ::tox_is_data_encrypted(mem) );
    delete[] mem;
}

class tox_pass_key_decrypt : public tox_is_data_encrypted
{
public:
    static TOX_PASS_KEY s_key;

    uint8_t* decrypted_out;
    TOX_ERR_DECRYPTION decryption_error;
    uint8_t* passphrase;
    size_t pplength;

    tox_pass_key_decrypt() : tox_is_data_encrypted(), decrypted_out(NULL), decryption_error(), passphrase(NULL) {}
    ~tox_pass_key_decrypt() {}

    static void SetUpTestCase() {
        tox_is_data_encrypted::SetUpTestCase();
        uint8_t* tmp_passphrase = new uint8_t[ s_pass_len ];
        memmove(tmp_passphrase, s_pass, s_pass_len);
        ASSERT_TRUE( ::tox_derive_key_from_pass(tmp_passphrase, s_pass_len, &s_key, NULL) );
        ASSERT_TRUE( ::tox_pass_key_encrypt(s_data, s_data_len, &s_key, s_encrypted_out, NULL) );
        delete[] tmp_passphrase;
    }
    static void TearDownTestCase() {
        tox_is_data_encrypted::TearDownTestCase();
    }

    std::string get_data_before_encrypt() const {
        return std::string(reinterpret_cast<const char*>(s_data), s_data_len);
    }
    std::string get_data_after_decrypt() const {
        return std::string(reinterpret_cast<const char*>(decrypted_out), s_data_len);
    }

    virtual void SetUp() {
        tox_is_data_encrypted::SetUp();

        decrypted_out = new uint8_t[s_data_len];
        passphrase = new uint8_t[ s_pass_len ];
        memmove(passphrase, s_pass, s_pass_len);
    }
    virtual void TearDown() {
        delete[] decrypted_out;
        delete[] passphrase;
        tox_is_data_encrypted::TearDown();
    }
};
TOX_PASS_KEY tox_pass_key_decrypt::s_key;

TEST_F(tox_pass_key_decrypt, all_args_are_good) {
    EXPECT_TRUE( ::tox_pass_key_decrypt(s_encrypted_out, s_encrypted_len, &s_key, decrypted_out, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_OK, decryption_error);
    EXPECT_EQ(get_data_before_encrypt(), get_data_after_decrypt());
}

TEST_F(tox_pass_key_decrypt, error_is_null) {
    EXPECT_TRUE( ::tox_pass_key_decrypt(s_encrypted_out, s_encrypted_len, &s_key, decrypted_out, NULL) );
    EXPECT_EQ(get_data_before_encrypt(), get_data_after_decrypt());
    EXPECT_EQ(get_data_before_encrypt(), get_data_after_decrypt());
}

TEST_F(tox_pass_key_decrypt, encrypted_is_null) {
    EXPECT_FALSE( ::tox_pass_key_decrypt(NULL, s_encrypted_len, &s_key, decrypted_out, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_NULL, decryption_error);
}

TEST_F(tox_pass_key_decrypt, key_is_null) {
    EXPECT_FALSE( ::tox_pass_key_decrypt(s_encrypted_out, s_encrypted_len, NULL, decrypted_out, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_NULL, decryption_error);
}

TEST_F(tox_pass_key_decrypt, out_is_null) {
    EXPECT_FALSE( ::tox_pass_key_decrypt(s_encrypted_out, s_encrypted_len, &s_key, NULL, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_NULL, decryption_error);
}

TEST_F(tox_pass_key_decrypt, small_encrypted_len) {
    EXPECT_FALSE( ::tox_pass_key_decrypt(s_encrypted_out, 1, &s_key, decrypted_out, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_INVALID_LENGTH, decryption_error);
}

TEST_F(tox_pass_key_decrypt, data_is_not_encrypted) {
    uint8_t* mem = new uint8_t[s_encrypted_len];
    memset(mem, 0, s_encrypted_len);

    ASSERT_FALSE( ::tox_is_data_encrypted(mem) );
    EXPECT_FALSE( ::tox_pass_key_decrypt(mem, s_encrypted_len, &s_key, decrypted_out, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_BAD_FORMAT, decryption_error);

    delete[] mem;
}

TEST_F(tox_pass_key_decrypt, wrong_encrypted_len) {
    EXPECT_FALSE( ::tox_pass_key_decrypt(s_encrypted_out, s_encrypted_len - 1 /*sic!*/, &s_key, decrypted_out, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_FAILED, decryption_error);
}

TEST_F(tox_pass_key_decrypt, wrong_key) {
    TOX_PASS_KEY wrong_key;
    TOX_ERR_KEY_DERIVATION key_derivation_error;
    // We need only regenerate it, the salt will be different and the key will be different too even if passphrase is the same
    ASSERT_TRUE( ::tox_derive_key_from_pass(passphrase, s_pass_len, &wrong_key, &key_derivation_error) );
    ASSERT_EQ( TOX_ERR_KEY_DERIVATION_OK, key_derivation_error );
    ASSERT_NE(0, memcmp(wrong_key.key, s_key.key, TOX_PASS_KEY_LENGTH) );
    ASSERT_NE(0, memcmp(wrong_key.salt, s_key.salt, TOX_PASS_SALT_LENGTH) );

    ASSERT_TRUE( ::tox_pass_key_decrypt(s_encrypted_out, s_encrypted_len, &s_key, decrypted_out, &decryption_error) );

    EXPECT_FALSE( ::tox_pass_key_decrypt(s_encrypted_out, s_encrypted_len, &wrong_key, decrypted_out, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_FAILED, decryption_error);
}


class tox_get_salt : public tox_pass_key_decrypt
{
public:

    tox_get_salt() : tox_pass_key_decrypt() {}
    ~tox_get_salt() {}

    static void SetUpTestCase() {
        tox_pass_key_decrypt::SetUpTestCase();
    }
    static void TearDownTestCase() {
        tox_pass_key_decrypt::TearDownTestCase();
    }
    virtual void SetUp() {
        tox_pass_key_decrypt::SetUp();
    }
    virtual void TearDown() {
        tox_pass_key_decrypt::TearDown();
    }
};

TEST_F(tox_get_salt, all_args_are_good) {
    const uint8_t* saved_ptr_encrypted_out = s_encrypted_out;
    uint8_t salt[TOX_PASS_SALT_LENGTH] = {0};

    ASSERT_TRUE( ::tox_is_data_encrypted(s_encrypted_out) );
    EXPECT_TRUE( ::tox_get_salt(s_encrypted_out, salt) );

    EXPECT_EQ(saved_ptr_encrypted_out, s_encrypted_out);
    EXPECT_EQ(0, memcmp(salt, s_key.salt, TOX_PASS_SALT_LENGTH) );
}

TEST_F(tox_get_salt, args_are_null_ptrs) {
    uint8_t salt[TOX_PASS_SALT_LENGTH] = {0};

    EXPECT_FALSE( ::tox_get_salt(NULL, salt) );
    EXPECT_FALSE( ::tox_get_salt(s_encrypted_out, NULL) );
    EXPECT_FALSE( ::tox_get_salt(NULL, NULL) );
}

TEST_F(tox_get_salt, zero_mem) {
    uint8_t salt[TOX_PASS_SALT_LENGTH] = {0};
    uint8_t* mem = new uint8_t[s_encrypted_len];
    memset(mem, 0, s_encrypted_len);

    ASSERT_FALSE( ::tox_is_data_encrypted(mem) );
    EXPECT_FALSE( ::tox_get_salt(mem, salt) );

    delete[] mem;
}

TEST_F(tox_get_salt, actual_value) {
    // FIXME add test to check returned salt
}

class tox_derive_key_with_salt : public tox_derive_key_from_pass
{
public:
    std::string salt_str;
    const uint8_t* salt;

    tox_derive_key_with_salt() : tox_derive_key_from_pass(), salt_str(), salt(NULL) {}
    ~tox_derive_key_with_salt() {}

    virtual void SetUp() {
        tox_derive_key_from_pass::SetUp();
        set_salt("1234567890 1234567890 1234567890");
    }
    virtual void TearDown() {
        tox_derive_key_from_pass::TearDown();
    }
    void set_salt(const std::string& new_salt) {
        salt_str = new_salt;
        salt = reinterpret_cast<const uint8_t*>(salt_str.c_str());
    }
};

TEST_F(tox_derive_key_with_salt, all_args_are_good) {
    EXPECT_TRUE( ::tox_derive_key_with_salt(passphrase, pplength, salt, &key, &key_derivation_error) );
    EXPECT_EQ(TOX_ERR_KEY_DERIVATION_OK, key_derivation_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_derive_key_with_salt, same_salt_produces_same_keys) {
    uint8_t* passphrase_copy = new uint8_t[ pplength ];
    memmove(passphrase_copy, passphrase, pplength);
    std::string salt_copy = salt_str;

    ASSERT_TRUE( ::tox_derive_key_with_salt(passphrase, pplength, salt, &key, &key_derivation_error) );
    ASSERT_TRUE( pass_was_zeroed(passphrase, pplength) );

    TOX_PASS_KEY other_key;
    set_salt(salt_copy);
    EXPECT_TRUE( ::tox_derive_key_with_salt(passphrase_copy, pplength, salt, &other_key, &key_derivation_error) );
    EXPECT_TRUE( pass_was_zeroed(passphrase_copy, pplength) );

    EXPECT_EQ(0, memcmp(other_key.key, key.key, TOX_PASS_KEY_LENGTH) );
    EXPECT_EQ(0, memcmp(other_key.salt, key.salt, TOX_PASS_SALT_LENGTH) );

    delete[] passphrase_copy;
}

TEST_F(tox_derive_key_with_salt, different_salt_produces_different_keys) {
    uint8_t* passphrase_copy = new uint8_t[ pplength ];
    memmove(passphrase_copy, passphrase, pplength);
    std::string other_salt = "11111111111 1234567890 1234567890";

    ASSERT_NE(other_salt, salt_str);
    ASSERT_TRUE( ::tox_derive_key_with_salt(passphrase, pplength, salt, &key, &key_derivation_error) );

    TOX_PASS_KEY other_key;
    set_salt(other_salt);
    EXPECT_TRUE( ::tox_derive_key_with_salt(passphrase_copy, pplength, salt, &other_key, &key_derivation_error) );

    EXPECT_NE(0, memcmp(other_key.key, key.key, TOX_PASS_KEY_LENGTH) );
    EXPECT_NE(0, memcmp(other_key.salt, key.salt, TOX_PASS_SALT_LENGTH) );

    delete[] passphrase_copy;
}

TEST_F(tox_derive_key_with_salt, key_is_null) {
    EXPECT_FALSE( ::tox_derive_key_with_salt(passphrase, pplength, salt, NULL, &key_derivation_error) );
    EXPECT_EQ(TOX_ERR_KEY_DERIVATION_NULL, key_derivation_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}


class tox_pass_encrypt : public tox_derive_key_from_pass
{
public:
    std::string data_str;
    size_t data_len;
    const uint8_t* data;

    size_t encrypted_len;
    uint8_t* encrypted_out;
    TOX_ERR_ENCRYPTION encryption_error;

    tox_pass_encrypt() : tox_derive_key_from_pass(), data_str(), data_len(), data(), encrypted_len(), encrypted_out(), encryption_error() {}
    ~tox_pass_encrypt() {}

    virtual void SetUp() {
        tox_derive_key_from_pass::SetUp();

        data_str = "hello world";
        data_len = data_str.size();
        data = reinterpret_cast<const uint8_t*>(data_str.c_str());

        encrypted_len = data_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
        encrypted_out = new uint8_t[encrypted_len];
    }
    virtual void TearDown() {
        delete[] encrypted_out;
        tox_derive_key_from_pass::TearDown();
    }
};

TEST_F(tox_pass_encrypt, all_args_are_good) {
    EXPECT_TRUE( ::tox_pass_encrypt(data, data_len, passphrase, pplength, encrypted_out, &encryption_error) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_OK, encryption_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_encrypt, error_is_null) {
    EXPECT_TRUE( ::tox_pass_encrypt(data, data_len, passphrase, pplength, encrypted_out, NULL) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_OK, encryption_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_encrypt, passphrase_is_null_pplen_is_zero) {
    EXPECT_TRUE( ::tox_pass_encrypt(data, data_len, NULL, 0, encrypted_out, &encryption_error) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_OK, encryption_error);
    EXPECT_FALSE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_encrypt, data_len_is_zero_data_is_null) {
    EXPECT_FALSE( ::tox_pass_encrypt(NULL, 0, passphrase, pplength, encrypted_out, &encryption_error) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_NULL, encryption_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_encrypt, data_len_is_zero_data_is_not_null) {
    EXPECT_FALSE( ::tox_pass_encrypt(data, 0, passphrase, pplength, encrypted_out, &encryption_error) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_NULL, encryption_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_encrypt, data_is_null) {
    EXPECT_FALSE( ::tox_pass_encrypt(NULL, data_len, passphrase, pplength, encrypted_out, &encryption_error) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_NULL, encryption_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_encrypt, passphrase_is_null_pplen_is_not_zero) {
    EXPECT_FALSE( ::tox_pass_encrypt(data, data_len, NULL, pplength, encrypted_out, &encryption_error) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_NULL, encryption_error);
    EXPECT_FALSE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_encrypt, out_is_null) {
    EXPECT_FALSE( ::tox_pass_encrypt(data, data_len, passphrase, pplength, NULL, &encryption_error) );
    EXPECT_EQ(TOX_ERR_ENCRYPTION_NULL, encryption_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}


class tox_pass_decrypt : public tox_derive_key_from_pass
{
public:
    static std::string s_data_str;
    static size_t s_data_len;
    static const uint8_t* s_data;

    static uint8_t* s_encrypted_out;
    static size_t   s_encrypted_len;

    uint8_t* decrypted_out;
    TOX_ERR_DECRYPTION decryption_error;

    tox_pass_decrypt() : tox_derive_key_from_pass(), decrypted_out(), decryption_error() {}
    ~tox_pass_decrypt() {}

    static void SetUpTestCase() {
        tox_derive_key_from_pass::SetUpTestCase();

        s_data_str = "hello world";
        s_data_len = s_data_str.size();
        s_data = reinterpret_cast<const uint8_t*>(s_data_str.c_str());

        s_encrypted_len = s_data_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
        s_encrypted_out = new uint8_t[s_encrypted_len];

        uint8_t*  tmp_passphrase = new uint8_t[ s_pass_len ];
        memmove(tmp_passphrase, s_pass, s_pass_len);

        ASSERT_TRUE( ::tox_pass_encrypt(s_data, s_data_len, tmp_passphrase, s_pass_len, s_encrypted_out, NULL) );

        delete[] tmp_passphrase;
    }
    static void TearDownTestCase() {
        delete[] s_encrypted_out;
        tox_derive_key_from_pass::TearDownTestCase();
    }

    virtual void SetUp() {
        tox_derive_key_from_pass::SetUp();
        memmove(passphrase, s_pass, s_pass_len);
        decrypted_out = new uint8_t[s_data_len];
    }
    virtual void TearDown() {
        delete[] decrypted_out;
        tox_derive_key_from_pass::TearDown();
    }

    std::string get_data_before_encrypt() const {
        return std::string(reinterpret_cast<const char*>(s_data), s_data_len);
    }
    std::string get_data_after_decrypt() const {
        return std::string(reinterpret_cast<const char*>(decrypted_out), s_data_len);
    }
};
std::string tox_pass_decrypt::s_data_str;
size_t tox_pass_decrypt::s_data_len;
const uint8_t* tox_pass_decrypt::s_data;
uint8_t* tox_pass_decrypt::s_encrypted_out;
size_t   tox_pass_decrypt::s_encrypted_len;


TEST_F(tox_pass_decrypt, all_args_are_good) {
    EXPECT_TRUE( ::tox_pass_decrypt(s_encrypted_out, s_encrypted_len, passphrase, pplength, decrypted_out, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_OK, decryption_error);
    EXPECT_EQ(get_data_before_encrypt(), get_data_after_decrypt());
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_decrypt, error_is_null) {
    EXPECT_TRUE( ::tox_pass_decrypt(s_encrypted_out, s_encrypted_len, passphrase, pplength, decrypted_out, NULL) );
    EXPECT_EQ(get_data_before_encrypt(), get_data_after_decrypt());
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_decrypt, encrypted_is_null) {
    EXPECT_FALSE( ::tox_pass_decrypt(NULL, s_encrypted_len, passphrase, pplength, decrypted_out, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_NULL, decryption_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_decrypt, out_is_null) {
    EXPECT_FALSE( ::tox_pass_decrypt(s_encrypted_out, s_encrypted_len, passphrase, pplength, NULL, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_NULL, decryption_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_decrypt, small_encrypted_len) {
    EXPECT_FALSE( ::tox_pass_decrypt(s_encrypted_out, 1, passphrase, pplength, decrypted_out, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_INVALID_LENGTH, decryption_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_decrypt, data_is_not_encrypted) {
    uint8_t* mem = new uint8_t[s_encrypted_len];
    memset(mem, 0, s_encrypted_len);

    ASSERT_FALSE( ::tox_is_data_encrypted(mem) );
    EXPECT_FALSE( ::tox_pass_decrypt(mem, s_encrypted_len, passphrase, pplength, decrypted_out, &decryption_error) );
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_BAD_FORMAT, decryption_error);

    delete[] mem;
}

TEST_F(tox_pass_decrypt, wrong_encrypted_len) {
    EXPECT_FALSE( ::tox_pass_decrypt(s_encrypted_out, s_encrypted_len - 1 /*sic!*/, passphrase, pplength, decrypted_out, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_FAILED, decryption_error);
    EXPECT_TRUE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_decrypt, pplen_is_zero_passphrase_is_not_null) {
    EXPECT_FALSE( ::tox_pass_decrypt(s_encrypted_out, s_encrypted_len, passphrase, 0, decrypted_out, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_FAILED, decryption_error);
    EXPECT_FALSE( pass_was_zeroed(passphrase, pplength) );
}

TEST_F(tox_pass_decrypt, passphrase_is_null_pplen_is_zero) {
    EXPECT_FALSE( ::tox_pass_decrypt(s_encrypted_out, s_encrypted_len, NULL, 0, decrypted_out, &decryption_error) );
    EXPECT_EQ(TOX_ERR_DECRYPTION_FAILED, decryption_error);
    EXPECT_FALSE( pass_was_zeroed(passphrase, pplength) );
}
