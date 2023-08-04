#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#include <stdio.h>
#include <stdint.h>

#include <re.h>
#include <avs.h>
#include <avs_wcall.h>

#include <iv.h>
#include <iv_list.h>
#include <iv_event_raw.h>
#include <bb_wire.h>
#include <bb_wire_priv.h>
#include <bb_wire_conv.h>
#include <bb_common.h>

static struct iv_avl_tree wire_avl;

//forward decl
static void wire_re_init(int flags, void *arg);

static int comp(const struct iv_avl_node *_a, const struct iv_avl_node *_b)
{
    struct wire_priv *a;
    struct wire_priv *b;

    a = iv_container_of(_a, struct wire_priv, an);
    b = iv_container_of(_b, struct wire_priv, an);

    if (a->ws < b->ws) return -1;
    if (a->ws > b->ws) return 1;

    return 0;
}

static struct wire_priv *get_wp_from_avl(struct wire_session *ws)
{
    struct wire_priv *wp;
    struct iv_avl_node *an;

    an = wire_avl.root;

    while (an != NULL)
    {
        wp = iv_container_of(an,struct wire_priv, an);

        if (ws == wp->ws)
            return wp;
        if (ws < wp->ws)
            an = an->left;
        else
            an = an->right;
    }

    return NULL;
}


static void channel_status_change_cb(bool status, void *arg)
{
    struct wire_priv *wp;

    wp = (struct wire_priv*)arg;

    iv_event_raw_post(&(wp->ws->bbmct.wire_init_success_ev));
}

static void sync_done_cb(void *arg)
{
    fprintf(stderr, "syncing done\n");
}

static void set_client_id(struct wire_priv *wp)
{
    int ret;
    char *str;
    struct sobject *so;

    if ((ret = store_user_open(&so, wp->store, "zcall", "clientid", "rb")) != 0)
    {
        wp->ws->error = WIRE_OPEN_USER_STORE_FAIL;
        iv_event_raw_post(&(wp->ws->bbmct.error_ev));
        return;
    }

    if ((ret = sobject_read_lenstr(&str, so)) != 0)
    {
        wp->ws->error = WIRE_READ_STRING_FROM_STORE_FAIL;
        iv_event_raw_post(&(wp->ws->bbmct.error_ev));
        goto out;
    }
    
    strncpy(wp->client_id, str, sizeof(wp->client_id));

out:
    mem_deref(str);
    mem_deref(so);
}

static void conv_init(struct wire_priv *wp)
{
    char *conv_id;
    struct sobject *so;
    struct conv_list *cl;

    struct iv_list_head *ilh;
    struct iv_list_head *ilh2;

    if (store_user_open(&so, wp->store, "zcall", "conv", "rb") != 0)
    {
        wp->ws->error = WIRE_OPEN_USER_STORE_FAIL;
        iv_event_raw_post(&(wp->ws->bbmct.error_ev));
        mem_deref(so);
        return;
    }

    if (sobject_read_lenstr(&conv_id, so) != 0)
    {
        wp->ws->error = WIRE_READ_STRING_FROM_STORE_FAIL;
        iv_event_raw_post(&(wp->ws->bbmct.error_ev));
        goto out;
    }

    iv_list_for_each_safe(ilh, ilh2, &(wp->list))
    {
        cl = iv_list_entry(ilh, struct conv_list, list);
        if (strcmp(cl->conv->id, conv_id) == 0)
            wp->conv = cl->conv;
    }

 out:
    mem_deref(conv_id);
    mem_deref(so);
}

//This callback is being called after all the conversations are sent
static void ready_cb(void *arg)
{
    struct wire_priv *wp;

    wp = (struct wire_priv*)arg;

    if (avs_start(engine_get_login_token(wp->engine)) != 0)
    {
        wp->ws->error = WIRE_ENGINE_START_FAIL;
        iv_event_raw_post(&(wp->ws->bbmct.error_ev));
    }

    //make sure we load the right conversation
	conv_init(wp);
    set_client_id(wp);
}


static void error_cb(int error, void *arg)
{
    struct wire_priv *wp;

    wp = (struct wire_priv*)arg;
    wp->ws->error = error;
    iv_event_raw_post(&(wp->ws->bbmct.error_ev));
}

static void shutdown_cb(void *arg)
{
    struct wire_priv *wp;

    wp = (struct wire_priv*)arg;
    iv_event_raw_post(&(wp->ws->bbmct.disconnect_ev));

	re_cancel();
}

void add_conv_cb(struct engine_conv *conv, void *arg)
{
    struct wire_priv *wp;
    struct conv_list *cl;

    wp = (struct wire_priv*)arg;

    if ((cl = malloc(sizeof(*cl))) == NULL)
    {
        wp->ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(wp->ws->bbmct.error_ev));
        return;
    }

    memset(cl, 0x00, sizeof(*cl));

    cl->conv = conv;
    
    //adding to the list
    iv_list_add_tail(&(cl->list), &(wp->list));
}

static void signal_cb(int sig)
{
}

static void otr_read_cb(int err, void *arg)
{
    struct wire_priv *wp;

    wp = (struct wire_priv*)arg;
    
    if (err == 0)
        iv_event_raw_post(&(wp->ws->bbmct.wire_sent_success_ev));
    else
    {
        wp->ws->error = WIRE_OTR_READ_FAIL;
        iv_event_raw_post(&(wp->ws->bbmct.error_ev));
        return;
    }
}

void wire_send_msg(void *object)
{
    int ret;
    size_t len;
    char buf[BUFSIZE * 2];
    struct wire_session *ws;
    struct wire_priv *wp;

    len = sizeof(buf);
    ws = (struct wire_session*)object;
    wp = get_wp_from_avl(ws);

    if ((protobuf_encode_text(buf, &len, ws->bbmct.bbmc.buf_write)) != 0)
    {
        ws->error = WIRE_PROTOBUF_ENCODING_FAIL;
        iv_event_raw_post(&(ws->bbmct.error_ev));
        return;
    }

    ret = engine_send_otr_message(wp->engine, wp->cbox, wp->conv, NULL, 0,
         wp->client_id, buf, len, false, false, otr_read_cb, wp);
    if (ret != 0)
    {
        ws->error = WIRE_SENDING_OTR_FAIL;
        iv_event_raw_post(&(ws->bbmct.error_ev));
        return;
    }
}

void wire_deinit(void *object)
{
    struct wire_priv *wp;
    struct wire_session *ws;
    struct iv_list_head *ilh;
    struct conv_list *cl;

    ws = (struct wire_session*)object;
    wp = get_wp_from_avl(ws);

    //TODO should we free cl->conv as well?
    while (!iv_list_empty(&wp->list))
    {
        ilh = wp->list.next;
        cl = iv_list_entry(ilh, struct conv_list, list);

        iv_list_del(ilh);
        free(cl);
    }

    iv_event_raw_unregister(&(ws->wire_init_ev));
    iv_event_raw_unregister(&(ws->wire_deinit_ev));
    iv_event_raw_unregister(&(ws->wire_send_msg_ev));

    engine_shutdown(wp->engine);

	mem_deref(wp->engine);
	mem_deref(wp->store);

	wp->cbox = mem_deref(wp->cbox);
 
    engine_lsnr_unregister(&(wp->e_lsnr));
	engine_close();
	avs_close();
    re_cancel();
	libre_close();
    free(wp);

    iv_event_raw_post(&(ws->bbmct.wire_deinit_success_ev));
}

void wire_re_send_msg(int flags, void *arg)
{
    char buf[BUFSIZE];
    ssize_t len;
    ssize_t rlen;

    struct wire_session *ws;
    ws = (struct wire_session*)arg;

    //empty the buffer first
    do 
    {
        len = read(ws->wire_send_msg_ev.event_rfd.fd, buf, sizeof(buf));
        rlen += len;
    } while (len < 0 && errno == EINTR);

    wire_send_msg(arg);
}

void wire_re_deinit(int flags, void *arg)
{
    char buf[BUFSIZE];
    ssize_t len;
    ssize_t rlen;

    struct wire_session *ws;
    ws = (struct wire_session*)arg;

    //empty the buffer first
    do 
    {
        len = read(ws->wire_deinit_ev.event_rfd.fd, buf, sizeof(buf));
        rlen += len;
    } while (len < 0 && errno == EINTR);

    wire_deinit(arg);
}

void wire_init(void *object)
{
	int ret = 0;
	char msys[64] = "voe";
    char user_store[BUFSIZE];

    struct sobject *so;
    struct wire_session *ws;
    struct wire_priv *wp;

    ws = (struct wire_session*)object;

    //first alloc a wire_private struct and store it in the tree
    if ((wp = malloc(sizeof(*wp))) == NULL)
    {
        ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(ws->bbmct.error_ev));
        return;
    }

    memset(wp, 0x00, sizeof(*wp));

    INIT_IV_LIST_HEAD(&(wp->list));
    //store it in the AVL tree
    if (iv_avl_tree_empty(&wire_avl) == 1)
        INIT_IV_AVL_TREE(&wire_avl, comp);

    iv_avl_tree_insert(&wire_avl, &wp->an);

    //TODO in the future we might need to add more callback
    wp->ws = ws;
    wp->e_lsnr.arg = wp;
    wp->e_lsnr.estabh = channel_status_change_cb;
    wp->e_lsnr.syncdoneh = sync_done_cb;
    wp->e_lsnr.addconvh = add_conv_cb;
    //wp->e_lsnr.otraddmsgh = otr_add_msg_cb;

    //create the directory where all the info is
    memset(user_store, 0x00, sizeof(user_store));
    snprintf(user_store, sizeof(user_store), "%s/%s", ws->store_dir, ws->user);

    //start initializing the connection
    if ((ret = libre_init()) != 0)
    {
        ws->error = WIRE_LIBRE_INIT_FAIL;
        iv_event_raw_post(&(ws->bbmct.error_ev));
        return;
    }

    if ((ret = avs_init(AVS_FLAG_EXPERIMENTAL)) != 0)
    {
        ws->error = WIRE_AVS_INIT_FAIL;
        iv_event_raw_post(&(ws->bbmct.error_ev));
        return;
    }

	//sys_coredump_set(true);
    if ((ret = engine_init(msys)) != 0)
    {
        ws->error = WIRE_ENGINE_INIT_FAIL;
        iv_event_raw_post(&(ws->bbmct.error_ev));
        return;
    }

    if ((ret = msystem_enable_datachannel(flowmgr_msystem(), true)) != 0)
    {
        ws->error = WIRE_DATACHANNEL_ENABLE_FAIL;
        iv_event_raw_post(&(ws->bbmct.error_ev));
        return;
    }

    if ((ret = msystem_enable_datachannel(flowmgr_msystem(), true)) != 0)
    {
        ws->error = WIRE_DATACHANNEL_ENABLE_FAIL;
        iv_event_raw_post(&(ws->bbmct.error_ev));
        return;
    }

    //init the store where credentials are stored
    if ((ret = store_alloc(&(wp->store), ws->store_dir)) != 0)
    {
        ws->error = WIRE_CREATE_STORE_FAIL;
        iv_event_raw_post(&(ws->bbmct.error_ev));
        return;
    }

    if ((ret = cryptobox_alloc(&(wp->cbox), user_store)) != 0)
    {
        ws->error = WIRE_CRYPTOBOX_ALLOC_FAIL;
        iv_event_raw_post(&(ws->bbmct.error_ev));
        return;
    }

    ret = engine_alloc(&(wp->engine), ws->req_url, ws->not_url, ws->user, 
        ws->pass, wp->store, false, false, "zcall/", ready_cb, error_cb, 
        shutdown_cb, wp);

    if (ret != 0)
    {
        ws->error = WIRE_ENGINE_ALLOC_FAIL;
        iv_event_raw_post(&(ws->bbmct.error_ev));
        return;
    }

    //register callback functions
    if (ws->wire_send_msg_ev.cookie != NULL)
        fd_listen(ws->wire_send_msg_ev.event_rfd.fd, FD_READ, wire_re_send_msg, 
            ws->wire_send_msg_ev.cookie);    
    if (ws->wire_init_ev.cookie != NULL)
        fd_listen(ws->wire_init_ev.event_rfd.fd, FD_READ, wire_re_init, 
            ws->wire_init_ev.cookie);
    if (ws->wire_deinit_ev.cookie != NULL)
        fd_listen(ws->wire_deinit_ev.event_rfd.fd, FD_READ, wire_re_deinit, 
            ws->wire_deinit_ev.cookie);

	engine_lsnr_register(wp->engine, &(wp->e_lsnr));
	re_main(signal_cb);
}

static void wire_re_init(int flags, void *arg)
{
    char buf[BUFSIZE];
    ssize_t len;
    ssize_t rlen;

    struct wire_session *ws;
    ws = (struct wire_session*)arg;

    //empty the buffer first
    do 
    {
        len = read(ws->wire_init_ev.event_rfd.fd, buf, sizeof(buf));
        rlen += len;
    } while (len < 0 && errno == EINTR);

    wire_init(arg);
}


