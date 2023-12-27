#include <limits.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/hash.h>
#include "bb_errors.h"
#include "bb_crypto.h"

#define AES_256_BLOCK_SIZE 32

bb_ret aes_128_cfb_enc(char *key, char *IV, char *in, size_t len, char *out)
{
    Aes aes;
    if (wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, IV, AES_ENCRYPTION) != 0)
        return AES_SET_KEY_ERROR;

    if (wc_AesCfbEncrypt(&aes, out, in, len) != 0)
        return AES_CFB_ENCRYPT_ERROR;
    return ALL_GOOD;
}

bb_ret aes_128_cfb_dec(char *key, char *IV, char *in, size_t len, char *out)
{
    Aes aes;
    if (wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, IV, AES_ENCRYPTION) != 0)
        return AES_SET_KEY_ERROR;

    if (wc_AesCfbDecrypt(&aes, out, in, len) != 0)
        return AES_CFB_DECRYPT_ERROR;
    return ALL_GOOD;
}

bb_ret bb_sha256(char *buf, size_t len, char *hash)
{
    if (wc_Sha256Hash(buf, len, hash)!= 0)
        return SHA256_ERROR;
}

bb_ret bb_md5(char *buf, size_t len, char *hash)
{
    if (wc_Md5Hash(buf, len, hash) != 0)
        return HASH_MD5_FAILED;
    return ALL_GOOD;
}

bb_ret aes_256_cbc_dec(char *key, char *IV, char *in, size_t len, char *out)
{
    Aes aes;
    if (wc_AesSetKey(&aes, key, AES_256_BLOCK_SIZE, IV, AES_DECRYPTION) != 0)
        return AES_SET_KEY_ERROR;

    if (wc_AesCbcDecrypt(&aes, out, in, len) != 0)
        return AES_CBC_DECRYPT_ERROR;
    return ALL_GOOD;
}

bb_ret get_random_bytes(char *buf, int size)
{
    WC_RNG rng;

    if (wc_InitRng(&rng) != 0)
        return RANDOM_INIT_ERROR;

    if (wc_RNG_GenerateBlock(&rng, buf, size) != 0)
        return RANDOM_GENERATING_RANDOM_BLOCK_ERROR;

    if (wc_FreeRng(&rng) != 0)
        return RANDOM_FREEING_ERROR;
}

bb_ret aes_256_cbc_enc(char *key, char *IV, char *in, size_t len, char *out)
{
    Aes aes;

    if (wc_AesSetKey(&aes, key, AES_256_BLOCK_SIZE, IV, AES_ENCRYPTION) != 0)
        return AES_SET_KEY_ERROR;

    if (wc_AesCbcEncrypt(&aes, out, in, len) != 0)
        return AES_CBC_ENCRYPT_ERROR;
    return ALL_GOOD;
}
