#ifndef BB_WIRE_PRIV_H
#define BB_WIRE_PRIV_H

#include <re.h>
#include <avs.h>
#ifndef WUSER_HANDLE
#include <avs_wcall.h>
#endif
#include <iv_avl.h>
#include <iv_list.h>

#include <bb_common.h>

#define IV_SIZE 16
#define SHA2_SIZE 32
#define AES_KEY_SIZE 32

//taken from wire_avs/src/engine/engine.h
enum engine_state {
    ENGINE_STATE_LOGIN,     /* currently logging in  */
    ENGINE_STATE_STARTUP,   /* starting up after successful login  */
    ENGINE_STATE_ACTIVE,    /* engine up and running  */
    ENGINE_STATE_SYNC,  /* engine up and running and syncing  */
    ENGINE_STATE_SHUTDOWN,  /* engine shutting down  */
    ENGINE_STATE_DEAD       /* shutdown finished  */
};

struct engine {
    /* Engine state and loaded modules
     */
    enum engine_state state;
    bool need_sync;           /* ... once we reach active  */
    bool clear_cookies;       /* ... once we logged in */
    struct list modulel;

    /* Configuration
     */
    char *request_uri;
    char *notification_uri;
    char *email;
    char *password;         /* will be NULL once login started.  */
    char *user_agent;

    /* Services we use.
     */
    struct store *store;
    struct dnsc *dnsc;
    struct http_cli *http;
    struct http_cli *http_ws;
    struct rest_cli *rest;
    struct login *login;

    /* Handlers
     */
    engine_ping_h *readyh;
    engine_status_h *errorh;
    engine_ping_h *shuth;
    void *arg;

    /* Listener list
     */
    struct list lsnrl;

    /* Module data
     */
    struct engine_event_data *event;
    struct engine_user_data *user;
    struct engine_conv_data *conv;
    struct engine_call_data *call;

    struct list syncl;  /* struct engine_sync_step */
    uint64_t ts_start;

    struct trace *trace;
    bool destroyed;
};

struct wire_priv
{
    char *conv_id;
    char client_id[BUFSIZE];
    bool event_estab;
    bool pending_nw_change;
    struct store *store;
    struct cryptobox *cbox;
    struct engine *engine;
    struct engine_conv *conv;
    struct engine_lsnr e_lsnr;

    //calling related variables
    int vid_state;
    struct engine_user *eu;
    struct http_cli *http_cli;
    WUSER_HANDLE wu_handle;
    
    struct wire_session *ws;
    struct iv_list_head list;
    struct iv_avl_node an;
};

struct conv_list
{
    struct engine_conv *conv;
    struct iv_list_head list;
};

struct asset_up
{
    char *asset_id;
    char *domain;
    char key[AES_KEY_SIZE];
    char *asset_plain;
    size_t asset_plain_len;
    char *asset_enc;
    size_t asset_enc_len;
    struct wire_priv *wp;
};

struct asset_data
{
    char key[AES_KEY_SIZE];
    char *asset_id;
    char *asset_token;
    char *ext;

    struct wire_priv *wp;
};

struct mem_str
{
    char *memory;
    size_t size;
};

#endif
