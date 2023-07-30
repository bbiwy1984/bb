#include <string.h>
#include <stdlib.h>
#include <toml.h>

#include <bb_tcp.h>
#include <bb_common.h>
#include <bb_config.h>
#include <bb_reolink.h>

static struct bb_message_channel bbmc_tmp;

static bb_ret parse_reolink(toml_table_t *tl, struct doorbell *db)
{
    int i;
    char *t;
    struct reo_session *rs;
    toml_datum_t str;

    if ((rs = malloc(sizeof(*rs))) == NULL)
        return NO_MORE_MEMORY;
    
    memset(rs, 0x00, sizeof(*rs));

    if (db->bbmct != NULL)
        return CONFIG_DOORBELL_SHOULD_ALWAYS_BE_TOP_LAYER;
    
    db->bbmct = &(rs->bbmct);
    
    for (i = 0; i < toml_table_nkval(tl); i++)
    {
        t = (char*)toml_key_in(tl, i);
 
        if (strncmp(t, "user", strlen("user")) == 0)
        { 
            str = toml_string_in(tl, t); 
            rs->user = str.u.s; 
        }
        else if (strncmp(t, "pass", strlen("pass")) == 0)
        { 
            str = toml_string_in(tl, t); 
            rs->pass = str.u.s; 
        }
        else if (strncmp(t, "ping_interval", strlen("ping_interval")) == 0)
        {
            str = toml_int_in(tl, t);
            rs->ping_interval = str.u.i;
        }
        else if (strncmp(t, "type", strlen("type")) != 0)
            return CONFIG_REOLINK_UNSUPPORTED_OPTION;
    }    

    //it is a little ugly, but since we don't know what layer is below here,
    //we use a temp message channel to store the callback pointers
    //so they can be set properly
    bbmc_tmp.read_cb = reo_read;
    bbmc_tmp.write_cb = reo_write_cb;
    bbmc_tmp.disconn_cb = reo_disconn_cb;
    bbmc_tmp.error_cb = reo_error_cb;
    bbmc_tmp.init_success_cb = reo_init_success_cb;

    return ALL_GOOD;
}

static bb_ret parse_tcp(toml_table_t *tl, struct doorbell *db)
{
    int i;
    char *t;
    struct tcp_struct *ts;
    struct bb_message_channel *it;

    toml_datum_t str;

    if ((ts = malloc(sizeof(*ts))) == NULL)
        return NO_MORE_MEMORY;
    
    memset(ts, 0x00, sizeof(*ts));

    //See where we need to link this one to. Typically tcp is below ssl
    //or below the doorbell protocol. 
    if (db->bbmct == NULL)
    {
        free(ts);
        return CONFIG_TCP_CANNOT_BE_THE_TOP_LAYER;
    }
    
    it = (struct bb_message_channel*)(db->bbmct); //->msg_channel_down;
    while (it->bbmc_down != NULL)
        it = it->bbmc_down;

    //it is now the msg channel link the previous message channel to the tcp one
    it->bbmc_down = &(ts->bbmc);
    ts->bbmc.bbmc_up = it;
    
    //we need to set the pointers in the message channel of the tcp struct
    //recall that these are being called from the layer above (e.g. ssl,
    //reolink, whatever).
    ts->bbmc.write_cf = tcp_write;
    ts->bbmc.init_cf = tcp_init;
    ts->bbmc.deinit_cf = tcp_deinit;
    ts->bbmc.cleanup_client_cf = tcp_cleanup_client;

    //set the callback pointers
    ts->bbmc.read_cb = bbmc_tmp.read_cb;
    ts->bbmc.write_cb = bbmc_tmp.write_cb;
    ts->bbmc.disconn_cb = bbmc_tmp.disconn_cb;
    ts->bbmc.error_cb = bbmc_tmp.error_cb;
    ts->bbmc.new_client_cb = bbmc_tmp.new_client_cb;
    ts->bbmc.init_success_cb = bbmc_tmp.init_success_cb;
     
    for (i = 0; i < toml_table_nkval(tl); i++)
    {
        t = (char*)toml_key_in(tl, i);
 
        if (strncmp(t, "host", strlen("host")) == 0)
        { 
            str = toml_string_in(tl, t); 
            ts->host = str.u.s; 
        }
        else if (strncmp(t, "connection_type", strlen("connection_type")) == 0)
        { 
            str = toml_string_in(tl, t); 
            if (strncmp(str.u.s, "client", strlen("client")) == 0)
                ts->type = CLIENT;
            else if (strncmp(str.u.s, "server", strlen("server")) == 0)
                ts->type = SERVER;
            else 
                return CONFIG_UNKNOWN_CONNECTION_TYPE;
            free(str.u.s);
        }
        else if (strncmp(t, "port", strlen("port")) == 0)
        {
            str = toml_int_in(tl, t);
            ts->port = str.u.i;
        }
        else if (strncmp(t, "type", strlen("type")) != 0)
        {
            return CONFIG_REOLINK_UNSUPPORTED_OPTION;
        }
    }    

    return ALL_GOOD;
}

static bb_ret parse_layer(toml_array_t *a, struct doorbell *db)
{
    int i;
    int j;
    toml_array_t *l;
    toml_table_t *t;
    toml_table_t *tl;
    toml_datum_t td;
    
    t = toml_table_at(a, 0);

    for (i = 0; i < toml_table_narr(t); i++)
    {
        l = toml_array_in(t, toml_key_in(t,i));
        tl = toml_table_at(l, 0);
       
        //we want to find out the type
        if (toml_key_exists(tl, "type") == 0)
            return CONFIG_TYPE_KEYWORD_NOT_FOUND;

        td = toml_string_in(tl, "type");

        if (strncmp(td.u.s, "reolink", strlen("reolink")) == 0)
            parse_reolink(tl, db);
        else if (strncmp(td.u.s, "tcp", strlen("tcp")) == 0)
            parse_tcp(tl, db);
    }

    return ALL_GOOD;
}

static bb_ret parse_relay(toml_array_t *a, struct doorbell *db)
{
    int i;
    char *s;
    toml_datum_t str;
    toml_table_t *t;
    struct relay *r;

    t = toml_table_at(a, 0);

    if ((r = malloc(sizeof(*r))) == NULL)
        return NO_MORE_MEMORY;
    
    memset(r, 0x00, sizeof(*r));

    for (i = 0; i < toml_table_nkval(t); i++)
    {
        s = (char*)toml_key_in(t, i);

        if (strncmp(s, "offset", strlen("offset")) == 0)
        { 
            str = toml_int_in(t, s); 
            r->offset = str.u.i;
        }
        else if (strncmp(s, "on_value", strlen("on_value")) == 0)
        { 
            str = toml_int_in(t, s); 
            r->offset = str.u.i;
        }
        else if (strncmp(s, "off_value", strlen("off_value")) == 0)
        {
            str = toml_int_in(t, s);
            r->off_value = str.u.i;
        }
        else if (strncmp(s, "on_time", strlen("on_time")) == 0)
        {
            str = toml_int_in(t, s);
            r->on_time = str.u.i;
        }
        else if (strncmp(s, "device", strlen("device")) == 0)
        {
            str = toml_string_in(t, s);
            r->device = str.u.s;
        }
        else
            return CONFIG_RELAY_UNSUPPORTED_OPTION;
    }    

    db->r = r;
 
    return ALL_GOOD;
}

static bb_ret parse_door(toml_array_t *door, struct doorbell *db)
{
    int i;
    int j;
    bb_ret ret;
    toml_table_t *t;
    toml_array_t *a;   

    t = toml_table_at(door, 0);

    for (i = 0; i < toml_table_narr(t); i++)
    {
        a = toml_array_in(t, toml_key_in(t, i));
        if (strncmp(toml_key_in(t, i), "layers", strlen("layers")) == 0)
        {
            if ((ret = parse_layer(a, db)) != ALL_GOOD)
                return ret;
        }
        else if (strncmp(toml_key_in(t,i), "relay", strlen("relay")) == 0)
        {
            if ((ret = parse_relay(a, db)) != ALL_GOOD)
                return ret;
        }
        else
            return CONFIG_NO_LAYER_OR_RELAY;
    }

    if (toml_table_narr(t) < 1)
        return CONFIG_NO_LAYER_OR_RELAY;

    return ALL_GOOD;
}

bb_ret conf_parse(char *file, int *n_doors, struct doorbell **db)
{
    int i;
    char errbuf[BUFSIZE];

    FILE *fp;
    bb_ret ret;
    toml_table_t *conf;
    toml_table_t *dt;   //doorbell table
    toml_array_t *da;   //doorbell array
    toml_array_t *dda;  //doorbel.X array

    ret = ALL_GOOD;

    if ((fp = fopen(file, "r")) == NULL)
    {
        ret = CONFIG_CANNOT_OPEN_FILE;
        goto out;
    }

    if ((conf = toml_parse_file(fp, errbuf, sizeof(errbuf))) == NULL)
    {
        ret = CONFIG_PARSING_ERROR;
        goto close_fp;
    }

    if ((da = toml_array_in(conf, "doorbell")) == NULL)
    {
        ret = CONFIG_CANNOT_FIND_DOORBELL_CONF;
        goto close_fp;
    }

    //we should get the number of doorbells here, so we know how many
    //to make and to parse
    if ((dt = toml_table_at(da,0)) == NULL)
    {
        ret = CONFIG_CANNOT_FIND_DOOR;
        goto close_fp;
    }

    *n_doors = toml_table_narr(dt);

    //arbitrary number to prevent overflows, who has more than 10 doorbells
    //anyway
    if (*n_doors > 10)
    {
        ret = CONFIG_TOO_MANY_DOORBELLS;
        goto close_fp;
    }

    //alloc mem for the number of doorbells we have
    if ((*db = calloc(*n_doors, sizeof(struct doorbell))) == NULL)
    {
        ret = NO_MORE_MEMORY;
        goto close_fp;
    }

    for (i = 0; i < *n_doors; i++)
    {
        dda = toml_array_in(dt, toml_key_in(dt, i));
        if (parse_door(dda, db[i]) != ALL_GOOD)
        {
            ret = CONFIG_PARSING_DOOR_ERROR;
            goto close_fp;
        }
    }

close_fp:
    fclose(fp);
    
out:
    return ret;    
}

