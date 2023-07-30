#ifndef BB_ERRORS_H
#define BB_ERRORS_H

#include <stdint.h>

typedef uint64_t bb_ret;

#define ALL_GOOD                                    0x000000000
#define CANNOT_WRITE_USB_RELAY                      0x000000001
#define CANNOT_OPEN_USB_RELAY                       0x000000002
#define CANT_CREATE_ELEMENT                         0x000000010
#define CANT_CREATE_PIPELINE                        0x000000020
#define CANT_LINK_ELEMENT                           0x000000030
#define CANT_CREATE_SOCKET                          0x000000100
#define CANT_RESOLVE_HOST                           0x000000101
#define CANT_CONNECT_TO_HOST                        0x000000102
#define CANT_BIND_FD                                0x000000103
#define CANT_LISTEN_FD                              0x000000104
#define CANT_LOOKUP_HOSTNAME                        0x000000105
#define MAX_CONNECT_ATTEMPTS_EXCEEDED               0x000000106
#define CANT_RECONNECT                              0x000000107
#define CANT_ACCEPT_NEW_CLIENT                      0x000000108
#define NO_MORE_MEMORY                              0x000001000
#define ERROR_INSERTING_INTO_AVL_TREE               0x000001001
#define DEST_BUF_TOO_SMALL                          0x000001002
#define DEST_BUF_NOT_EMPTY                          0x000001003
#define SOMETHING_WENT_WRONG_WITH_STRS              0x000001004
#define INVALID_OR_NO_SSL_SERVER_METHOD             0x000010000
#define INVALID_CERT_FILE                           0x000010001
#define INVALID_PRIVATE_KEY_FILE                    0x000010002
#define CANT_LOAD_TRUST_PEER_CERT                   0x000010003
#define CANT_SEED                                   0x000010004
#define CANT_SSL_CONF_DEFAULT                       0x000010005
#define CANT_SET_SSL_HOSTNAME                       0x000010006
#define CANT_CONF_OWN_CERT                          0x000010007
#define CANT_SETUP_SSL                              0x000010008
#define SSL_VERIFICATION_FAILED                     0x000010009
#define INIT_MD5_FAILED                             0x000100000
#define UPDATE_MD5_FAILED                           0x000200000
#define FINAL_MD5_FAILED                            0x000300000
#define HASH_MD5_FAILED                             0x000400000
#define AES_CFB_DECRYPT_ERROR                       0x000500000
#define AES_SET_KEY_ERROR                           0x000600000
#define AES_CFB_ENCRYPT_ERROR                       0x000700000
#define NEXT_STATE_NOT_ALLOWED                      0x001000000
#define REO_DATA_RECV_LEN_TOO_SMALL                 0x010000000
#define REO_MAGIC_WRONG                             0x020000000
#define REO_MSG_ID_WRONG                            0x030000000
#define REO_ENC_OFFSET_WRONG                        0x040000000
#define REO_UNK_WRONG                               0x050000000
#define REO_LEGACY_MSG_CLASS_WRONG                  0x060000000
#define REO_ENC_WRONG                               0x070000000
#define REO_LENGTH_MISMATCH                         0x080000000
#define REO_PAYLOAD_OFF_WRONG                       0x090000000
#define REO_STATUS_CODE_WRONG                       0x0A0000000
#define REO_STATE_NOT_SUPPORTED                     0x0B0000000
#define REO_STATE_NOT_ENABLED                       0x0C0000000
#define WIRE_LIBRE_INIT_FAIL                        0x100000000
#define CONFIG_CANNOT_OPEN_FILE                     0x1000000000
#define CONFIG_PARSING_ERROR                        0x2000000000
#define CONFIG_CANNOT_FIND_DOORBELL_CONF            0x3000000000
#define CONFIG_CANNOT_FIND_DOOR                     0x4000000000
#define CONFIG_TOO_MANY_DOORBELLS                   0x5000000000
#define CONFIG_PARSING_DOOR_ERROR                   0x6000000000
#define CONFIG_NO_LAYER_OR_RELAY                    0x7000000000
#define CONFIG_TYPE_KEYWORD_NOT_FOUND               0x8000000000
#define CONFIG_DOORBELL_SHOULD_ALWAYS_BE_TOP_LAYER  0x9000000000
#define CONFIG_REOLINK_UNSUPPORTED_OPTION           0xA000000000
#define CONFIG_TCP_CANNOT_BE_THE_TOP_LAYER          0xB000000000
#define CONFIG_UNKNOWN_CONNECTION_TYPE              0xC000000000
#define CONFIG_RELAY_UNSUPPORTED_OPTION             0xD000000000
#define XML_CANT_FIND_ELEMENT                       0x10000000000
#define XML_CANT_SET_TEXT                           0x20000000000
#define FATAL                                       0xFFFFFFFFFFF

/*
struct bladiebla
{
    char in[BUFSIZE];
    char out[BUFSIZE];
    size_t in_len;
    size_t out_len;
    void (*write_func)(char *buf, size_t len);
    void (*read_func)(char *buf, size_t len);
};
*/

#endif