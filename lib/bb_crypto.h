#ifndef BB_CRYPTO_H
#define BB_CRYPTO_H

#include <stdint.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/random.h>

#include <bb_errors.h>

#define MD5_LEN WC_MD5_DIGEST_SIZE

bb_ret bb_md5(char *buf, size_t len, char *hash);
bb_ret bb_sha256(char *buf, size_t len, char *hash);
bb_ret aes_128_cfb_dec(char *key, char *IV, char *in, size_t len,
    char *output);
bb_ret aes_128_cfb_enc(char *key, char *IV, char *in, size_t len,
    char *output);
bb_ret aes_256_cbc_dec(char *key, char *IV, char *in, size_t len, char *out);
bb_ret aes_256_cbc_enc(char *key, char *IV, char *in, size_t len, char *out);
bb_ret get_random_bytes(char *buf, int size);

#endif
