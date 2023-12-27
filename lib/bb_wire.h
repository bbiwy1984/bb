#ifndef BB_WIRE_H
#define BB_WIRE_H

#include <avs.h>
#include <bb_layer.h>
#include <bb_errors.h>

struct wire_session
{
    char *user;
    char *pass;
    char *req_url;
    char *not_url;
    char *store_dir;
    char *storage_dir;

    bb_ret error;
    struct bb_message_channel_top bbmct;
    struct iv_event_raw wire_init_ev;
    struct iv_event_raw wire_deinit_ev;
    struct iv_event_raw wire_send_msg_ev;
    struct iv_event_raw wire_send_file_ev;
    struct iv_event_raw wire_send_pic_from_buf_ev;
};

void wire_init(void *object);
void wire_deinit(void *object);
void wire_send_msg(void *object);
void wire_send_file(void *object);
void wire_send_pic_from_buf(void *object);

#endif

