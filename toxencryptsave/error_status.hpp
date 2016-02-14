#ifndef TOXENCRYPTSAVE_ERROR_STATUS_H
#define TOXENCRYPTSAVE_ERROR_STATUS_H

enum TOX_ERR_KEY_DERIVATION {
    TOX_ERR_KEY_DERIVATION_OK,
    /**
     * Some input data, or maybe the output pointer, was null.
     */
    TOX_ERR_KEY_DERIVATION_NULL,
    /**
     * The crypto lib was unable to derive a key from the given passphrase,
     * which is usually a lack of memory issue. The functions accepting keys
     * do not produce this error.
     */
    TOX_ERR_KEY_DERIVATION_FAILED
};

enum TOX_ERR_ENCRYPTION {
    TOX_ERR_ENCRYPTION_OK,
    /**
     * Some input data, or maybe the output pointer, was null.
     */
    TOX_ERR_ENCRYPTION_NULL,
    /**
     * The crypto lib was unable to derive a key from the given passphrase,
     * which is usually a lack of memory issue. The functions accepting keys
     * do not produce this error.
     */
    TOX_ERR_ENCRYPTION_KEY_DERIVATION_FAILED,
    /**
     * The encryption itself failed.
     */
    TOX_ERR_ENCRYPTION_FAILED
};

enum TOX_ERR_DECRYPTION {
    TOX_ERR_DECRYPTION_OK,
    /**
     * Some input data, or maybe the output pointer, was null.
     */
    TOX_ERR_DECRYPTION_NULL,
    /**
     * The input data was shorter than TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes
     */
    TOX_ERR_DECRYPTION_INVALID_LENGTH,
    /**
     * The input data is missing the magic number (i.e. wasn't created by this
     * module, or is corrupted)
     */
    TOX_ERR_DECRYPTION_BAD_FORMAT,
    /**
     * The crypto lib was unable to derive a key from the given passphrase,
     * which is usually a lack of memory issue. The functions accepting keys
     * do not produce this error.
     */
    TOX_ERR_DECRYPTION_KEY_DERIVATION_FAILED,
    /**
     * The encrypted byte array could not be decrypted. Either the data was
     * corrupt or the password/key was incorrect.
     */
    TOX_ERR_DECRYPTION_FAILED
};

#endif
