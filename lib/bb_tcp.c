#include <bb_tcp.h>
#include <bb_errors.h>

#include <iv.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

inline static void tcp_reset_timer(struct bb_message_channel *bbmc)
{
    struct tcp_struct *ts;

    ts = container_of(bbmc, struct tcp_struct, bbmc);

    iv_timer_unregister(&(ts->disconnect_timeout));
    iv_validate_now();

    ts->disconnect_timeout.expires = iv_now;
    ts->disconnect_timeout.expires.tv_sec += ts->timeout;
    
    iv_timer_register(&(ts->disconnect_timeout));
}

static void tcp_cleanup_connection(struct bb_message_channel *bbmc)
{
    struct tcp_struct *ts;

    ts = container_of(bbmc, struct tcp_struct, bbmc);

    //first make sure we are not already cleaning up (this function is not 
    //called twice (prevent race conditions)
    if (atomic_flag_test_and_set(&(ts->cleaning_up)) == true)
        return;
    
    //first deregister fds
    iv_fd_unregister(&(ts->fd));

    close(ts->fd.fd);
    bbmc->disconn_cb(bbmc);

    //if it is about a client, unregister the timer
    if (ts->type == SERVER) 
    {
        if (iv_timer_registered(&(ts->disconnect_timeout)) != 0)
            iv_timer_unregister(&(ts->disconnect_timeout));
        free(ts);
    }
}

ssize_t tcp_write(struct bb_message_channel *bbmc)
{
    ssize_t offset;
    ssize_t wlen;
    struct tcp_struct *ts;

    ts = container_of(bbmc, struct tcp_struct, bbmc);

    //cut it, no notification, nothing, who codes like this
    //should be punished anyway
    if (bbmc->len_write > INT_MAX)
        bbmc->len_write = INT_MAX;

    //write it like this makes it more or less blocking
    //we only return when all the data has been written
    offset = 0;
    while (bbmc->len_write != 0)
    {
        wlen = write(ts->fd.fd, bbmc->buf_write + offset, bbmc->len_write);
        if (wlen < 0)
        {
            if (errno == EAGAIN)
                continue;
            else //cleanup
            {
                tcp_cleanup_connection(bbmc);
                return 0;
            }
        }
        offset += wlen;
        bbmc->len_write -= wlen;  
    }

    bbmc->write_cb(bbmc);

    //we only have a timeout when we are a server and the other
    //party is not sending anything
    if (ts->type == SERVER)
        tcp_reset_timer(bbmc);

    bbmc->len_write = 0;

    return offset;
}

static void tcp_read(void *object)
{
    size_t to_read;
    ssize_t len_read;
    struct tcp_struct *ts;
    struct bb_message_channel *bbmc;
    
    bbmc = (struct bb_message_channel*)object;
    ts = container_of(bbmc, struct tcp_struct, bbmc);

    //this is to prevent the case where the FD's are registered but the 
    //client isn't fully initialized by the upper layers
    if (bbmc->read_cb == NULL)
        goto out;

    //only read if buf is empty
    if (bbmc->len_read == 0 || bbmc->to_read != 0)
    {
        to_read = bbmc->to_read > 0 ? bbmc->to_read : sizeof(bbmc->buf_read);
        len_read = read(ts->fd.fd, bbmc->buf_read + bbmc->len_read, to_read);
            
        if (len_read <= 0)
        {
            if (errno == EAGAIN)
                goto out;
            else //cleanup
            {
                tcp_cleanup_connection(object);
                return;
            }
        }
        
        bbmc->to_read -= len_read;
        bbmc->len_read += len_read;

        bbmc->read_cb(bbmc);
    }
out:
    //we don't set a time out for when we are the client
    if (ts->type == SERVER)
        tcp_reset_timer(bbmc);
}

static void tcp_client_timeout_expired(void *object)
{
    struct bb_message_channel *bbmc;

    bbmc = (struct bb_message_channel*)object;
    bbmc->disconn_cb(bbmc);
}

void tcp_cleanup_client(struct bb_message_channel *bbmc)
{
    struct tcp_struct *ts;

    ts = container_of(bbmc, struct tcp_struct, bbmc);

    //first make sure we are not already cleaning up (this function is not 
    //called twice (prevent race conditions)
    if (atomic_flag_test_and_set(&(ts->cleaning_up)) == true)
        return;
 
    //first deregister everything
    iv_fd_unregister(&(ts->fd));
    close(ts->fd.fd);

    if (iv_timer_registered(&(ts->disconnect_timeout)) != 0)
        iv_timer_unregister(&(ts->disconnect_timeout));
}

/* Calls init_success_cb when a new client is successfully created. In case 
 * there is no more memory (malloc() returns NULL) or other errors, 
 * nothing happens (well the errors are forwarded but that's it).
 */
static void tcp_listening_socket_handler(void *object)
{
    int fd;
    socklen_t addrlen;
    struct sockaddr_in addr;
    struct bb_message_channel *bbmc;
    struct tcp_struct *ts;
    struct tcp_struct *ts_new;

    bbmc = (struct bb_message_channel*)object;
    ts = container_of(bbmc, struct tcp_struct, bbmc);
    addrlen = sizeof(addr);

    fd = accept(ts->fd.fd, (struct sockaddr *)&addr, &addrlen);

    if (fd < 0)
    {
        if (errno == EAGAIN)
            return;
        else
        {
            bbmc->error_cb(bbmc, CANT_ACCEPT_NEW_CLIENT);
            return;
        }    
    }

    if ((ts_new = (struct tcp_struct*)malloc(sizeof(*ts_new))) == NULL)
    {
        bbmc->error_cb(bbmc, NO_MORE_MEMORY);
        close(fd);
        return;
    }

    //we have a new connection
    IV_FD_INIT(&ts_new->fd);

    ts_new->fd.fd = fd;
    ts_new->fd.cookie = &(ts->bbmc);
    ts_new->fd.handler_in = tcp_read;

    iv_fd_register(&(ts_new->fd));

    //for connection timeouts
    IV_TIMER_INIT(&(ts_new->disconnect_timeout));
    iv_validate_now();

    ts_new->disconnect_timeout.cookie = &(ts->bbmc);
    ts_new->disconnect_timeout.handler = tcp_client_timeout_expired;
    ts_new->disconnect_timeout.expires = iv_now;
    ts_new->disconnect_timeout.expires.tv_sec += ts_new->timeout;

    iv_timer_register(&(ts_new->disconnect_timeout));

    //initing of the function pointers in ts->bbmc should be done by the upper
    //layer
    bbmc->init_success_cb(&(ts->bbmc));
}

void tcp_reconnect(struct bb_message_channel *bbmc)
{
    int fd;
    struct tcp_struct *ts;

    ts = container_of(bbmc, struct tcp_struct, bbmc);
    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
    {
        bbmc->error_cb(bbmc, CANT_CREATE_SOCKET);
        return;
    }

    if (connect(fd, (struct sockaddr *)&(ts->addr), sizeof(ts->addr)) < 0)
    {
        bbmc->error_cb(bbmc, CANT_CONNECT_TO_HOST);
        return;
    }

    IV_FD_INIT(&(ts->fd));

    ts->fd.fd = fd;
    ts->fd.cookie = bbmc;
    ts->fd.handler_in = tcp_read;

    iv_fd_register(&(ts->fd));

    atomic_flag_clear(&(ts->cleaning_up));

    //notify uppper layer of successfull initialization
    bbmc->init_success_cb(bbmc);
}

void tcp_deinit(struct bb_message_channel *bbmc)
{
    tcp_cleanup_connection(bbmc);
}

void tcp_init(struct bb_message_channel *bbmc)
{
    int fd;
    static uint32_t ret;
    struct tcp_struct *ts;
    struct addrinfo *res;
    struct addrinfo hints;

    ts = container_of(bbmc, struct tcp_struct, bbmc);

    //first init structures
    ts->addr.sin_family = AF_INET;
    ts->addr.sin_port = htons(ts->port);

    atomic_flag_clear(&(ts->cleaning_up));

    memset(&hints, 0x00, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(ts->host, NULL, &hints, &res) != 0)
    {
        bbmc->error_cb(bbmc, CANT_LOOKUP_HOSTNAME);
        return;
    }

    ts->addr.sin_addr.s_addr = 
        ((struct sockaddr_in*)(res->ai_addr))->sin_addr.s_addr;

    freeaddrinfo(res);

    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
    {
        bbmc->error_cb(bbmc, CANT_CREATE_SOCKET);
        return;
    }

    if (ts->type == SERVER)
    {
        if (bind(fd, (struct sockaddr *)&(ts->addr), sizeof(ts->addr)) < 0)
        {
            bbmc->error_cb(bbmc, CANT_BIND_FD);
            return;
        }

        if (listen(fd, 4) < 0)
        {
            bbmc->error_cb(bbmc, CANT_LISTEN_FD);
            return;
        }
    }
    else
    {
        if (connect(fd, (struct sockaddr *)&(ts->addr), sizeof(ts->addr)) < 0)
        {
            bbmc->error_cb(bbmc, CANT_CONNECT_TO_HOST);
            return;
        }
    }

    IV_FD_INIT(&(ts->fd));

    ts->fd.fd = fd;
    ts->fd.cookie = bbmc;

    if (ts->type == SERVER)
        ts->fd.handler_in = tcp_listening_socket_handler;    
    else
        ts->fd.handler_in = tcp_read;

    bbmc->init_success_cb(bbmc);

    iv_fd_register(&(ts->fd));
}



