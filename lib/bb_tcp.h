#ifndef BB_TCP_H
#define BB_TCP_H

#include <iv.h>
#include <iv_avl.h>
#include <iv_event.h>
#include <stdatomic.h>
#include <stdint.h>
#include <netinet/in.h>

#include <bb_layer.h>

struct tcp_struct
{
    char type;
    char *host;
    int timeout;
    uint16_t port;
    atomic_flag cleaning_up;
    struct sockaddr_in addr;

    struct iv_fd fd;
    struct iv_timer disconnect_timeout;
    
    struct bb_message_channel bbmc;
};

/* Inits the tcp struct, set up a socket and stars listening or connect to a
 * server. Upon success, the upper layer is called via the init_success_cb. 
 * In case an error is encountered, the fatal_cb function is used with the 
 * appropriate error
 */
void tcp_init(struct bb_message_channel *bbmc);

/* Cleans up the connection (deregister timers, unregister fds, etc).
 * In case of a client, free() is called for the tcp_struct
 */
void tcp_deinit(struct bb_message_channel *bbmc);

/* In case a problem was encountered, e.g. time out whatever, we reconnect to
 * the server. If successful a init_success_cb is called, while upon failure
 * fatal_cb is used with the appriopriate error code.
 */
void tcp_reconnect(struct bb_message_channel *bbmc);

/* If the upper layer encounters a problem, this function should be called.
 * It deregisters fd, timers, etc. 
 */
void tcp_cleanup_client(struct bb_message_channel *bbmc);


/* Acts like a blocking socket, meaning all data is written before it returns
 * (unless an error occurs of course).
 * Returns the length written upon succes, else 0 is returned
 */
ssize_t tcp_write(struct bb_message_channel *bbmc);

#endif
