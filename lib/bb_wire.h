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
    char *snapshot_command;

    char *snapshot_buf;

    struct bb_message_channel bbmc;

    bb_ret error;

    //Wire has its own (socket) IO library, meaning calling events from
    //another process to trigger Wire functions, doesn't work. 
    //The trick is to implement part of ivykis in Wire, and register that 
    //function with the Wire IO library. For this, we need the FDs
    int fd_init;
    int fd_deinit;
    int fd_send_msg;
    int fd_send_file;
    int fd_send_snapshot;

    //events we need to call from within wire to notify the layer above
    struct iv_event_raw wire_error_ev;
    struct iv_event_raw wire_init_success_ev;
    struct iv_event_raw wire_deinit_success_ev;
    struct iv_event_raw wire_sent_msg_success_ev;
    struct iv_event_raw wire_sent_file_success_ev;
    struct iv_event_raw wire_sent_snapshot_success_ev;    
    //this one is called when a certain msg is received and the db needs to be
    //instructed to take a screenshot
    struct iv_event_raw wire_take_snapshot_ev;
};

void wire_init(void *object);
void wire_deinit(void *object);
void wire_send_msg(void *object);
void wire_send_file(void *object);
void wire_send_snapshot(void *object);

#endif

