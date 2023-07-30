#include <limits.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/hash.h>

#include <bb_errors.h>
#include <bb_crypto.h>

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

bb_ret md5(char *buf, size_t len, char *hash)
{
    if (wc_Md5Hash(buf, len, hash) != 0)
        return HASH_MD5_FAILED;
    return ALL_GOOD;
}
