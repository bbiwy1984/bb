#ifndef BB_CRYPTO_H
#define BB_CRYPTO_H

#include <stdint.h>
#include <wolfssl/wolfcrypt/md5.h>

#include <bb_errors.h>

#define MD5_LEN WC_MD5_DIGEST_SIZE

bb_ret md5(char *buf, size_t len, char *hash);
bb_ret aes_128_cfb_dec(char *key, char *IV, char *in, size_t len, char *output);
bb_ret aes_128_cfb_enc(char *key, char *IV, char *in, size_t len, char *output);
#endif
