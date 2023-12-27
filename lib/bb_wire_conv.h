#ifndef BB_WIRE_CONV_H
#define BB_WIRE_CONV_H

void otr_add_msg_cb(struct engine_conv *conv,
                    struct engine_user *from,
                    const struct ztime *timestamp,
                    const uint8_t *cipher, size_t cipher_len,
                    const char *sender, const char *recipient,
                    void *arg);

void conv_added_cb(struct engine_conv *conv, void *arg);

#endif
