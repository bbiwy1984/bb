#ifndef BB_WIRE_PRIV_H
#define BB_WIRE_PRIV_H

#include <re.h>
#include <avs.h>
#include <iv_avl.h>
#include <iv_list.h>

#include <bb_common.h>

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
    
    struct wire_session *ws;
    struct iv_list_head list;
    struct iv_avl_node an;
};

struct conv_list
{
    struct engine_conv *conv;
    struct iv_list_head list;
};

#endif
