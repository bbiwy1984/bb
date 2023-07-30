#ifndef BB_REOLINK_H
#define BB_REOLINK_H

#include <stddef.h>
#include <iv_event_raw.h>

#include <bb_layer.h>
#include <bb_errors.h>

#define DEFAULT_REO_PORT 9000

struct reo_session
{
    char *user;
    char *pass;
    int ping_interval;
    bb_ret error;

    struct bb_message_channel *bbmc_down;
    struct bb_message_channel_top bbmct;
};

//supported protocol functionality

/* Logs into the Reolink doorbell. It tries do a legacy login, followed by
 * a modern login. If something goes wrong while logging in, the error is
 * sent via the protocol_error_ev and the appropriate value is set. 
 */
void reo_login(void *object);

/* Inits a and starts a "talking" session. Subject to change in the future 
 * when audio communication will be properly implemented  
 */
void reo_talk(void *object);

/* Deinits the reolink layer (and the subsequent layers below)
 */
void reo_deinit(void *object);

/* Inits the reolink layer, setups a connection, etc)
 */
void reo_init(void *object);

//callback functions
void reo_read(struct bb_message_channel *bbmc);
void reo_error_cb(struct bb_message_channel *bbmc, bb_ret error);
void reo_init_success_cb(struct bb_message_channel *bbmc);
void reo_disconn_cb(struct bb_message_channel *bbmc);
void reo_write_cb(struct bb_message_channel *bbmc);

#endif
