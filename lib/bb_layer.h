#ifndef BB_LAYER_H
#define BB_LAYER_H

#include <stddef.h>
#include <sys/types.h>
#include <iv_event_raw.h>

#include <bb_av.h>
#include <bb_errors.h>
#include <bb_common.h>
#include <bb_usb_relay.h>

struct doorbell
{
    char *ring_msg;
    char *pir_msg;
    char *mov_msg;

    struct bb_message_channel_top *bbmct;
    struct relay *r;
    struct av_data *avd;
    struct wire_session *ws;
};

struct bb_message_channel
{
    ssize_t len_read;
    ssize_t to_read;

    volatile ssize_t len_write;
    char buf_read[BUFSIZE];
    char buf_write[BUFSIZE];

    struct bb_message_channel *bbmc_up;
    struct bb_message_channel *bbmc_down; 
    
    ssize_t (*write_cf)(struct bb_message_channel *bbmc);
    void (*init_cf)(struct bb_message_channel *bbmc);
    void (*deinit_cf)(struct bb_message_channel *bbmc);
    void (*cleanup_client_cf)(struct bb_message_channel *bbmc);
    void (*reconnect_cf)(struct bb_message_channel *bbmc);
    void (*read_cb)(struct bb_message_channel *bbmc);
    void (*write_cb)(struct bb_message_channel *bbmc);
    void (*disconn_cb)(struct bb_message_channel *bbmc);
    void (*error_cb)(struct bb_message_channel *bbmc, bb_ret error);
    void *(*new_client_cb)(struct bb_message_channel *bbmc);
    void (*init_success_cb)(struct bb_message_channel *bbmc);
};

struct bb_message_channel_top
{
    struct bb_message_channel bbmc;

    //we use event_raw because perhaps somebody wants to isolate this
    //in a seperate process
    struct iv_event_raw error_ev;
    struct iv_event_raw login_success_ev;
    struct iv_event_raw init_success_ev;
    struct iv_event_raw disconnect_ev;
    struct iv_event_raw talk_init_success_ev;
    struct iv_event_raw get_audio_frame_ev;

    //alarms we can get from the doorbell
    struct iv_event_raw motion_detect_stop_ev;
    struct iv_event_raw motion_detect_start_ev;
    struct iv_event_raw doorbell_press_ev;
    struct iv_event_raw pir_alarm_ev;

    //functions we need to call inside the doorbell
    struct iv_event_raw init_ev;
    struct iv_event_raw talk_ev;
    struct iv_event_raw login_ev;

    //function we can get from wire
    struct iv_event_raw wire_init_success_ev;
    struct iv_event_raw wire_sent_success_ev;
    struct iv_event_raw wire_deinit_success_ev;
};

#endif
