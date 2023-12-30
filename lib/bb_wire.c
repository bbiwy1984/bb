#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>

#include <gd.h>
#include <iv.h>
#include <iv_list.h>
#include <iv_event_raw.h>
#include <magic.h>
#include <curl/curl.h>

#include <re.h>
#include <avs.h>
#include <avs_wcall.h>

#include <bb_wire.h>
#include <bb_crypto.h>
#include <bb_wire_priv.h>
#include <bb_wire_conv.h>
#include <bb_common.h>

static struct iv_avl_tree wire_avl;

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

static void json_cb(int err, const struct http_msg *msg, struct mbuf *mb,
    struct json_object *jobj, void *arg)
{
    struct wire_priv *wp;

    wp = (struct wire_priv*)arg;
    //fprintf(stderr, "got code: %d\n", msg->scode);
    //fprintf(stderr, "and data: %s\n", (char*)mbuf_buf(mb));
}

//for future use
static void get_api_version(struct wire_priv *wp)
{
    int ret;
    
    ret = rest_get(NULL, wp->engine->rest, 0, json_cb, wp, "/api-version");
    if (ret != 0)
    {
        wp->ws->error = WIRE_ERROR_GETTING_API_VERSION;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        return;
    }
}

static void channel_status_change_cb(bool status, void *arg)
{
    char *data;
    struct wire_priv *wp;

    wp = (struct wire_priv*)arg;

    iv_event_raw_post(&(wp->ws->wire_init_success_ev));
}

static void sync_done_cb(void *arg)
{
}

static void set_client_id(struct wire_priv *wp)
{
    int ret;
    char *str;
    struct sobject *so;

    if ((ret = store_user_open(&so, wp->store, "zcall", "clientid", "rb")) != 0)
    {
        wp->ws->error = WIRE_OPEN_USER_STORE_FAIL;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        return;
    }

    if ((ret = sobject_read_lenstr(&str, so)) != 0)
    {
        wp->ws->error = WIRE_READ_STRING_FROM_STORE_FAIL;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
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
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        mem_deref(so);
        return;
    }

    if (sobject_read_lenstr(&conv_id, so) != 0)
    {
        wp->ws->error = WIRE_READ_STRING_FROM_STORE_FAIL;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
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
        iv_event_raw_post(&(wp->ws->wire_error_ev));
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
    iv_event_raw_post(&(wp->ws->wire_error_ev));
}

//Should be called after a deinit(), no need to notify anybody else about this
static void shutdown_cb(void *arg)
{
    struct wire_priv *wp;

    wp = (struct wire_priv*)arg;

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
        iv_event_raw_post(&(wp->ws->wire_error_ev));
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

static void otr_img_read_cb(int err, void *arg)
{
    struct wire_priv *wp;

    wp = (struct wire_priv*)arg;
    
    if (err == 0)
    {
        memset(wp->ws->snapshot_buf, 0x00, SNAPSHOT_SIZE);
        iv_event_raw_post(&(wp->ws->wire_sent_snapshot_success_ev));
    }
    else
    {
        wp->ws->error = WIRE_OTR_READ_FAIL;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
    }
}

static void otr_read_cb(int err, void *arg)
{
    struct wire_priv *wp;

    wp = (struct wire_priv*)arg;
    
    if (err == 0)
        iv_event_raw_post(&(wp->ws->wire_sent_msg_success_ev));
    else
    {
        wp->ws->error = WIRE_OTR_READ_FAIL;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
    }
}

static void asset_up_destructor(void *arg)
{
    struct asset_up *au;

    au = (struct asset_up*) arg;

    free(au->asset_plain);
    free(au->asset_enc);
    free(au->asset_id);
    free(au->domain);
}

static void get_image_dimensions(char *img, size_t img_len, char *ftype, 
    uint32_t *width, uint32_t *height)
{
    gdImagePtr im;

    if (strstr(ftype, "png") != NULL)
        im = gdImageCreateFromPngPtr(img_len, img);
    else if (strstr(ftype, "jpeg") != NULL)
        im = gdImageCreateFromJpegPtr(img_len, img);
    else 
    {
        *width = 0;
        *height = 0;
        return;
    }

    *width = gdImageSX(im);
    *height = gdImageSY(im);

    gdImageDestroy(im);
}

static void protobuf_encode_asset_image(struct asset_up *au, char *ftype, 
    char *key, char *domain, char *pbuf, size_t *pbuf_len)
{
    char sha256[SHA2_SIZE];
    size_t len;

    GenericMessage msg;
    Asset asset;
    Asset__Original ao;
    Asset__ImageMetaData ai;
    Asset__RemoteData ar;

    generic_message__init(&msg);
    asset__init(&asset);
    asset__original__init(&ao);
    asset__remote_data__init(&ar);
    asset__image_meta_data__init(&ai);

    msg.content_case = GENERIC_MESSAGE__CONTENT_ASSET;
    msg.asset = &asset;

    uuid_v4(&msg.message_id);
    bb_sha256(au->asset_enc, au->asset_enc_len, sha256);

    //set asset
    asset.original = &ao;
    asset.preview = NULL;
    asset.status_case = ASSET__STATUS_UPLOADED;
    asset.uploaded = &ar;

    //set remotedata
    ar.otr_key.len = AES_KEY_SIZE;
    ar.otr_key.data = au->key;
    ar.sha256.len = SHA2_SIZE;
    ar.sha256.data = sha256;
    ar.asset_id = au->asset_id;
    ar.asset_token = NULL; //with V3 we dont have a token
    ar.has_encryption = 1;
    ar.asset_domain = au->domain;
    
    //set asset original
    ao.mime_type = ftype;
    ao.name = "x.jpg";
    ao.size = au->asset_plain_len; 
    ao.meta_data_case = ASSET__ORIGINAL__META_DATA_IMAGE;
    ao.image = &ai;

    //set the image metadata
    get_image_dimensions(au->asset_plain, au->asset_plain_len, ftype, 
        &(ai.width), &(ai.height));

    len = generic_message__get_packed_size(&msg);

    if (len > *pbuf_len)
    {
        au->wp->ws->error = WIRE_PROTOBUF_BUF_TOO_SMALL;
        iv_event_raw_post(&(au->wp->ws->wire_error_ev));
        return;
    }    

    if ((len = generic_message__pack(&msg, pbuf)) == 0)
    {
        au->wp->ws->error = WIRE_ERROR_PACKING_PROTOBUF;
        iv_event_raw_post(&(au->wp->ws->wire_error_ev));
        return;
    }

    *pbuf_len = len;
}

static void upload_asset_cb(int err, const struct http_msg *msg, 
    struct mbuf *mb, struct json_object *jobj, void *arg)
{
    int ret;
    char *key;
    char *domain;
    char *ftype;
    char *j_str;
    char pbuf[BUFSIZE * 2];
    size_t pbuf_len;

    struct asset_up *au;
    struct magic_set *magic;

    au = (struct asset_up*)arg;

    //do we have an error?
    if (err != 0)
    {
        au->wp->ws->error = WIRE_CANNOT_POST_ASSET;
        iv_event_raw_post(&(au->wp->ws->wire_error_ev));
        goto out;
    }

    //check http code
    if (msg->scode != 201)
    {
        au->wp->ws->error = WIRE_INVALID_STATUS_CODE_RECEIVED;
        iv_event_raw_post(&(au->wp->ws->wire_error_ev));
        goto out;
    }

    //parse response
    key = domain = NULL;
    if (jobj != NULL)
    {
        key = (char*)jzon_str(jobj, "key");
        domain = (char*)jzon_str(jobj, "domain");
    }

    //save data in struct
    if ((au->asset_id = malloc(strlen(key) + 1)) == NULL)
    {
        au->wp->ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(au->wp->ws->wire_error_ev));
        goto out;
    }

    if ((au->domain = malloc(strlen(domain) + 1)) == NULL)
    {
        au->wp->ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(au->wp->ws->wire_error_ev));
        goto out;
    }

    strcpy(au->domain, domain);
    strcpy(au->asset_id, key);

    //get file type of asset
    magic = magic_open(MAGIC_MIME_TYPE);
    
    magic_load(magic, NULL);

    ftype = (char*)magic_buffer(magic, au->asset_plain, au->asset_plain_len);

    //construct asset
    pbuf_len = sizeof(pbuf);

    memset(pbuf, 0x00, sizeof(pbuf));
    
    if (strncmp(ftype, "image", strlen("image")) == 0)
        protobuf_encode_asset_image(au, ftype, key, domain, pbuf, &pbuf_len);
    else
    {
        au->wp->ws->error = WIRE_INVALID_ASSET_TYPE;
        iv_event_raw_post(&(au->wp->ws->wire_error_ev));
        goto close_magic;
    }

    //send asset to channel
    ret = engine_send_otr_message(au->wp->engine, au->wp->cbox, au->wp->conv, 
        NULL, 0, au->wp->client_id, pbuf, pbuf_len, false, false, 
        otr_img_read_cb, au->wp);
    if (ret != 0)
    {
        au->wp->ws->error = WIRE_SENDING_OTR_FAIL;
        iv_event_raw_post(&(au->wp->ws->wire_error_ev));
        goto close_magic;
    }

close_magic:
    magic_close(magic);
out:
    mem_deref(au);
}

static void wire_upload_asset(struct wire_priv *wp, char *plain_buf, 
    size_t plain_len)
{
    int err;
    char IV[IV_SIZE];
    char *enc_buf;
    char *body;
    char key[AES_KEY_SIZE];
    char body_head[BUFSIZE];
    char md5_hash[MD5_SIZE];
    char md5_b64[MD5_SIZE * 2 + 1];
    size_t enc_len;
    size_t md5_b64_len;

    struct rest_req *rr;
    struct asset_up *au;

    bb_ret ret;

    char *json = "{\r\n\"public\": true,\r\n\"retention\": \"persistent\"\r\n}";
    char *body_footer = "\r\n--frontier--\r\n";

    enc_len = plain_len + IV_SIZE;

    if ((enc_buf = malloc(enc_len)) == NULL)
    {
        wp->ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        return;
    }
    
    //get the key, iv and add it
    //TODO is this secure enough?
    get_random_bytes(key, sizeof(key));
    get_random_bytes(IV, sizeof(IV));
    memcpy(enc_buf, IV, sizeof(IV));

    //start constructing the request
    if ((au = mem_zalloc(sizeof(*au), asset_up_destructor)) ==  NULL)
    {
        wp->ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }

    if ((au->asset_plain = malloc(plain_len)) == NULL)
    {
        wp->ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }

    if ((au->asset_enc = malloc(enc_len)) == NULL)
    {
        wp->ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }

    //encrypt the data
    if ((ret = aes_256_cbc_enc(key, IV, plain_buf, plain_len, enc_buf + 
        sizeof(IV))) != ALL_GOOD)
    {
        wp->ws->error = ret;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }

    //this data is later needed in the callback when we send the asset
    //to the group chat
    au->wp = wp;
    au->asset_enc_len = enc_len;
    au->asset_plain_len = plain_len;
    memcpy(au->asset_plain, plain_buf, plain_len);
    memcpy(au->asset_enc, enc_buf, enc_len);
    memcpy(au->key, key, 32);

    //start constructing the request
    rr = NULL;

    if ((err = rest_req_alloc(&rr, upload_asset_cb, au, "POST", 
        "/assets/v3")) != 0)
    {
        wp->ws->error = WIRE_ERROR_CREATING_REQUEST;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }
    
    md5_b64_len = sizeof(md5_b64);

    bb_md5(enc_buf, enc_len, md5_hash);
    memset(md5_b64, 0x00, sizeof(md5_b64));
    base64_encode(md5_hash, sizeof(md5_hash), md5_b64, &md5_b64_len);

    md5_b64[sizeof(md5_b64)] = '\0';

    memset(body_head, 0x00, sizeof(body_head));
    snprintf(body_head, sizeof(body_head), 
        "--frontier\r\n" \
        "Content-Type: application/json;charset=utf-8\r\n" \
        "Content-length: %ld\r\n" \
        "\r\n" \
        "%s\r\n" \
        "--frontier\r\n" \
        "Content-Type: application/octet-stream\r\n" \
        "Content-length: %ld\r\n" \
        "Content-MD5: %s" \
        "\r\n\r\n",
        strlen(json),
        json,
        enc_len,
        md5_b64);

    if ((body = malloc(strlen(body_head) + enc_len + strlen(body_footer) + 1))
        == NULL)
    {
        wp->ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }
    
    memcpy(body, body_head, strlen(body_head));
    memcpy(body + strlen(body_head), enc_buf, enc_len);
    memcpy(body + strlen(body_head) + enc_len, body_footer,strlen(body_footer));
    body[strlen(body_head) + enc_len + strlen(body_footer)] = '\0';
    
    if ((err = rest_req_add_body_raw(rr, "multipart/mixed; boundary=frontier",
        body, strlen(body_head) + enc_len + strlen(body_footer) + 1)) != 0)
    {
        wp->ws->error = WIRE_CANNOT_ADD_BODY;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out_body;
    }

    if ((err = rest_req_start(NULL, rr, wp->conv->engine->rest, 0)) != 0)
    {
        wp->ws->error = WIRE_ERROR_STARTING_REQUEST;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
    }

out_body:
    free(body);
out:
    free(enc_buf);
}

void wire_send_snapshot(void *object)
{
    int i;
    int dif;
    char *plain_buf;
    size_t snap_len;
    size_t plain_len;

    struct wire_session *ws;
    struct wire_priv *wp;

    ws = (struct wire_session*)object;
    wp = get_wp_from_avl(ws);

    //padd it first
    memcpy(&snap_len, ws->snapshot_buf, sizeof(snap_len));   

    plain_len = snap_len + (snap_len % 32 == 0 ? 0 : 32 - (snap_len % 32));

    if (plain_len + sizeof(snap_len) > SNAPSHOT_SIZE)
    {
        ws->error = WIRE_BUF_TOO_SMALL_FOR_PADDING;
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }

    dif = plain_len - snap_len;

    //padding
    for (i = 0; i < dif; i++)
        ws->snapshot_buf[snap_len + sizeof(snap_len) + i] = dif;
    
    wire_upload_asset(wp, ws->snapshot_buf + sizeof(snap_len), plain_len);
}

void wire_send_file(void *object)
{
    int i;
    char dif;
    char *file_type;
    char *file_buf;
    size_t plain_len;

    FILE *fp;
    struct stat st;
    struct wire_session *ws;
    struct wire_priv *wp;

    ws = (struct wire_session*)object;
    wp = get_wp_from_avl(ws);
 
    if ((fp = fopen(ws->bbmc.buf_write, "rb")) == NULL)
    {
        ws->error = WIRE_CANNOT_OPEN_SRC_FILE;
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }

    //alloc enough space to store the file in mem
    stat(ws->bbmc.buf_write, &st);

    plain_len = st.st_size + (st.st_size % 32 == 0 ? 0 : 32 -(st.st_size % 32));

    if ((file_buf = malloc(plain_len)) == NULL)
    {
        ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }

    fread(file_buf, 1, st.st_size, fp);
    fclose(fp);

    dif = plain_len - st.st_size;

    //padding
    for (i = 0; i < dif; i++)
        file_buf[st.st_size + i] = dif;

    wire_upload_asset(wp, file_buf, plain_len);

    free(file_buf);
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

    if ((protobuf_encode_text(buf, &len, ws->bbmc.buf_write)) != 0)
    {
        ws->error = WIRE_PROTOBUF_ENCODING_FAIL;
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }

    ret = engine_send_otr_message(wp->engine, wp->cbox, wp->conv, NULL, 0,
         wp->client_id, buf, len, false, false, otr_read_cb, wp);
    if (ret != 0)
    {
        ws->error = WIRE_SENDING_OTR_FAIL;
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }
}

static void asset_data_destructor(void *arg)
{
    struct asset_data *ad;

    ad = (struct asset_data*) arg;

    mem_deref(ad->asset_id);
    mem_deref(ad->asset_token);
}

static size_t write_file_to_mem(void *contents, size_t size, size_t nmemb, 
    void *userp)
{
  size_t realsize = size * nmemb;
  struct mem_str *mem = (struct mem_str *)userp;
 
  char *ptr = realloc(mem->memory, mem->size + realsize + 1);

  if(!ptr) {
    /* out of memory! */
    return 0;
  }
 
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;    
}

//we use curl because the wire-avs libs don't work well here
static void asset_loc_handler(int err, const struct http_msg *msg,
                  struct mbuf *mb, struct json_object *jobj,
                  void *arg)
{
    int i;
    char *ext;
    char *ftype;
    char *t_str;
    char *dec_buf;
    char *location;
    char file_loc[BUFSIZE];
    struct asset_data *ad;
    struct rest_req *rr;
    const struct http_hdr *hdr;
    struct mem_str chunk;
    struct magic_set *magic;

    bb_ret ret;
    time_t tt;
    FILE *fp;
    CURL *curl_handle;
    CURLcode res;

    char *unk = ".unk";

    ad = (struct asset_data*)arg;

    //see if we can get the location
    if (err != 0)
    {
        ad->wp->ws->error = WIRE_CANNOT_FETCH_ASSET;
        iv_event_raw_post(&(ad->wp->ws->wire_error_ev));
        goto out;
    }

    if (msg->scode != 302) 
    {
        ad->wp->ws->error = WIRE_NO_302_RECEIVED;
        iv_event_raw_post(&(ad->wp->ws->wire_error_ev));
        goto out;
    }

    if ((hdr = http_msg_hdr(msg, HTTP_HDR_LOCATION)) == NULL)
    {
        ad->wp->ws->error = WIRE_NO_REDIRECT_FOUND;
        iv_event_raw_post(&(ad->wp->ws->wire_error_ev));
        goto out;
    }       
            
    if ((err = pl_strdup(&location, &hdr->val)) != 0)
    {
        ad->wp->ws->error = WIRE_CANNOT_PARSE_ASSET_LOCATION;
        iv_event_raw_post(&(ad->wp->ws->wire_error_ev));
        goto out;
    }

    //get the file and store it in memory
    if ((chunk.memory = malloc(1)) == NULL)
    {
        ad->wp->ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(ad->wp->ws->wire_error_ev));
        goto cleanup_loc;
    }

    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);

    curl_handle = curl_easy_init();

    curl_easy_setopt(curl_handle, CURLOPT_URL, location);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_file_to_mem);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void*)&chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "bb/0.01");

    if ((res = curl_easy_perform(curl_handle)) != CURLE_OK)
    {
        ad->wp->ws->error = WIRE_CANNOT_DOWNLOAD_ASSET;
        iv_event_raw_post(&(ad->wp->ws->wire_error_ev));
        goto cleanup_loc;
    }

    //let's decrypt the file
    if ((dec_buf = malloc(chunk.size)) == NULL)
    {
        ad->wp->ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(ad->wp->ws->wire_error_ev));
        goto cleanup_curl;
    }
    
    if ((ret = aes_256_cbc_dec(ad->key, chunk.memory, chunk.memory + 16, 
        chunk.size - 16, dec_buf)) != ALL_GOOD)
    {
        ad->wp->ws->error = ret;
        iv_event_raw_post(&(ad->wp->ws->wire_error_ev));
        goto cleanup_dec_buf;
    }

    //let's save the data
    time(&tt);
    //get file type of asset
    magic = magic_open(MAGIC_MIME_TYPE);
    
    magic_load(magic, NULL);

    ftype = (char*)magic_buffer(magic, dec_buf, chunk.size - 16);
    ext = strstr(ftype, "/");
    t_str = ctime(&tt); 

    if (ext == NULL)
        ext = unk;
    else
        ext++;

    snprintf(file_loc, sizeof(file_loc), "%s/%.24s%s", ad->wp->ws->storage_dir,
        t_str, ext);
    
 
    for (i = 0; i < strlen(file_loc); i++)
    {
        if (file_loc[i] == ' ' || file_loc[i] == ':')
            file_loc[i] = '_';
    }

    if ((fp = fopen(file_loc, "wb")) == NULL)
    {
        ad->wp->ws->error = WIRE_CANNOT_OPEN_DEST_FILE;
        iv_event_raw_post(&(ad->wp->ws->wire_error_ev));
        goto close_magic;
    }

    fwrite(dec_buf, chunk.size, 1, fp);
    fclose(fp);

close_magic:
    magic_close(magic);
cleanup_dec_buf:
    free(dec_buf);
cleanup_curl:
    curl_easy_cleanup(curl_handle);
    free(chunk.memory);
    curl_global_cleanup();
cleanup_loc:
    mem_deref(location);
out:
    mem_deref(ad);
} 

//with v3 requests asset token is not needed
//we ignore the sha2 sum
static void get_v3_asset(struct wire_priv *wp, Asset *asset)
{
    int err;
    char *ext;
    char **tmp;
    struct rest_req *rr;
    struct asset_data *ad;
    
    bb_ret ret;
    
    err = 0;
    ret = ALL_GOOD;    

    //check if all the fields that we need are set
    if (asset->uploaded != NULL)
    {
        if (asset->uploaded->asset_id == NULL)
            ret = WIRE_ASSET_ID_NOT_SET;
        else if (asset->uploaded->otr_key.len != 32)
            ret = WIRE_ASSET_KEY_NOT_SET;
    }
    
    if (ret != ALL_GOOD)
    {
        wp->ws->error = ret;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }

    //start constructing the request
    if ((ad = mem_zalloc(sizeof(*ad), asset_data_destructor)) ==  NULL)
    {
        wp->ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }

    ad->wp = wp;

    str_dup(&ad->asset_id, asset->uploaded->asset_id);
    memcpy(ad->key, asset->uploaded->otr_key.data, 32);

    err = rest_req_alloc(&rr, asset_loc_handler, ad, "GET", "/assets/v3/%s", 
        asset->uploaded->asset_id);

    if (err != 0)
    {
        wp->ws->error = WIRE_ERROR_CREATING_REQUEST;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }

    if ((err = rest_req_start(NULL, rr, wp->engine->rest, 0)) != 0)
    {
        wp->ws->error = WIRE_ERROR_STARTING_REQUEST;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }
 out:

    if (err)
        mem_deref(rr);
}

//with v4 requests asset token is needed
//we ignore the sha2 sum
static void get_v4_asset(struct wire_priv *wp, Asset *asset)
{
    int err;
    char *ext;
    char **tmp;
    struct rest_req *rr;
    struct asset_data *ad;
    
    bb_ret ret;

    err = 0;
    ret = ALL_GOOD;    

    //check if all the fields that we need are set
    if (asset->uploaded != NULL)
    {
        if (asset->uploaded->asset_id == NULL)
            ret = WIRE_ASSET_ID_NOT_SET;
        else if (asset->uploaded->asset_domain == NULL)
            ret = WIRE_ASSET_DOMAIN_NOT_SET;
        else if (asset->uploaded->asset_token == NULL)
            ret = WIRE_ASSET_TOKEN_NOT_SET;
        else if (asset->uploaded->otr_key.len != AES_KEY_SIZE)
            ret = WIRE_ASSET_KEY_NOT_SET;
    }
    
    if (ret != ALL_GOOD)
    {
        wp->ws->error = ret;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }

    //start constructing the request
    if ((ad = mem_zalloc(sizeof(*ad), asset_data_destructor)) ==  NULL)
    {
        wp->ws->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }

    ad->wp = wp; 

    str_dup(&ad->asset_id, asset->uploaded->asset_id);
    str_dup(&ad->asset_token, asset->uploaded->asset_token);
    memcpy(ad->key, asset->uploaded->otr_key.data, AES_KEY_SIZE);

    err = rest_req_alloc(&rr, asset_loc_handler, ad, "GET", 
        "/assets/v4/%s/%s?asset_token=%s", asset->uploaded->asset_domain,
        asset->uploaded->asset_id, asset->uploaded->asset_token);

    if (err != 0)
    {
        wp->ws->error = WIRE_ERROR_CREATING_REQUEST;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }

    if ((err = rest_req_add_header(rr, "Asset-Token: %s\r\n", 
        asset->uploaded->asset_token)) != 0)
    {
        wp->ws->error = WIRE_ERROR_SETTING_ASSET_TOKEN;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }

    if ((err = rest_req_start(NULL, rr, wp->engine->rest, 0)) != 0)
    {
        wp->ws->error = WIRE_ERROR_STARTING_REQUEST;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        goto out;
    }

 out:
    if (err)
        mem_deref(rr);
}

static void otr_msg_cb(struct engine_conv *conv, struct engine_user *from,
    const struct ztime *ts, const uint8_t *cipher, size_t len, 
    const char *sender, const char *receiver, void *arg)
{
    int ret;
    char buf[BUFSIZE *2];
    size_t buf_len;
    struct wire_priv *wp;

    Text *text;
    Asset *asset;
    Asset__RemoteData *ar;

    struct session *ses;
    struct protobuf_msg *msg;
    
    wp = (struct wire_priv*)arg;

    //we can also get otr message for others when we are in a group chat so
    //ignore those
    if (strncmp(receiver, wp->client_id, strlen(wp->client_id)) != 0)
        return;
    
    if ((ses = cryptobox_session_find(wp->cbox, from->id, sender, receiver)) 
        == NULL)
    {
        //should never happen
        wp->ws->error = WIRE_CBOX_FIND_FAIL;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        return;
    }

    buf_len = sizeof(buf);

    if ((ret = cryptobox_session_decrypt(wp->cbox, ses, buf, &buf_len, cipher,
        len)) != 0)
    {
        wp->ws->error = WIRE_CBOX_DECRYPT_FAIL;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        return;
    }
    
    ///get the msg 
    if ((ret = protobuf_decode(&msg, buf, buf_len)) != 0)
    {
        wp->ws->error = WIRE_DECODE_MSG_FAIL;
        iv_event_raw_post(&(wp->ws->wire_error_ev));
        return;
    }
    
    switch(msg->gm->content_case)
    {
        case GENERIC_MESSAGE__CONTENT_TEXT:
            text = msg->gm->text;
            
            if (strncasecmp(text->content, wp->ws->snapshot_command, 
                strlen(wp->ws->snapshot_command)) == 0)
            {
                iv_event_raw_post(&(wp->ws->wire_take_snapshot_ev));
            }
            break;
        case GENERIC_MESSAGE__CONTENT_ASSET:
            //for future purposes, we could save an image here, code is 
            //already present.
            break;
        default:
            break;
    }
    
    mem_deref(msg);
}

static void wire_re_send_snapshot(int flags, void *arg)
{
    char buf[BUFSIZE];
    ssize_t len;
    ssize_t rlen;

    struct wire_session *ws;
    ws = (struct wire_session*)arg;
    //empty the buffer first
    do 
    {
        len = read(ws->fd_send_snapshot, buf,sizeof(buf));
        rlen += len;
    } while (len < 0 && errno == EINTR);
    wire_send_snapshot(arg);
}

static void wire_re_send_file(int flags, void *arg)
{
    char buf[BUFSIZE];
    ssize_t len;
    ssize_t rlen;

    struct wire_session *ws;
    ws = (struct wire_session*)arg;

    //empty the buffer first
    do 
    {
        len = read(ws->fd_send_file, buf, sizeof(buf));
        rlen += len;
    } while (len < 0 && errno == EINTR);

    wire_send_file(arg);
}

static void wire_re_send_msg(int flags, void *arg)
{
    char buf[BUFSIZE];
    ssize_t len;
    ssize_t rlen;

    struct wire_session *ws;
    ws = (struct wire_session*)arg;

    //empty the buffer first
    do 
    {
        len = read(ws->fd_send_msg, buf, sizeof(buf));
        rlen += len;
    } while (len < 0 && errno == EINTR);

    wire_send_msg(arg);
}

static void wire_re_deinit(int flags, void *arg)
{
    char buf[BUFSIZE];
    ssize_t len;
    ssize_t rlen;
    
    struct wire_session *ws;
    ws = (struct wire_session*)arg;

    //empty the buffer first
    do 
    {
        len = read(ws->fd_deinit, buf, sizeof(buf));
        rlen += len;
    } while (len < 0 && errno == EINTR);

    wire_deinit(arg);
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
        len = read(ws->fd_init, buf, sizeof(buf));
        rlen += len;
    } while (len < 0 && errno == EINTR);

    wire_init(arg);
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

    iv_event_raw_post(&(ws->wire_deinit_success_ev));
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
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }

    memset(wp, 0x00, sizeof(*wp));

    INIT_IV_LIST_HEAD(&(wp->list));
    //INIT_IV_LIST_HEAD(&(wp->l_conf));
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
    wp->e_lsnr.otraddmsgh = otr_msg_cb;

    //create the directory where all the info is
    memset(user_store, 0x00, sizeof(user_store));
    snprintf(user_store, sizeof(user_store), "%s/%s", ws->store_dir, ws->user);

    //start initializing the connection
    if ((ret = libre_init()) != 0)
    {
        ws->error = WIRE_LIBRE_INIT_FAIL;
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }

    if ((ret = avs_init(AVS_FLAG_EXPERIMENTAL)) != 0)
    {
        ws->error = WIRE_AVS_INIT_FAIL;
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }

    if ((ret = engine_init(msys)) != 0)
    {
        ws->error = WIRE_ENGINE_INIT_FAIL;
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }

    if ((ret = msystem_enable_datachannel(flowmgr_msystem(), true)) != 0)
    {
        ws->error = WIRE_DATACHANNEL_ENABLE_FAIL;
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }

    if ((ret = msystem_enable_datachannel(flowmgr_msystem(), true)) != 0)
    {
        ws->error = WIRE_DATACHANNEL_ENABLE_FAIL;
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }

    //init the store where credentials are stored
    if ((ret = store_alloc(&(wp->store), ws->store_dir)) != 0)
    {
        ws->error = WIRE_CREATE_STORE_FAIL;
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }

    if ((ret = cryptobox_alloc(&(wp->cbox), user_store)) != 0)
    {
        ws->error = WIRE_CRYPTOBOX_ALLOC_FAIL;
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }

    ret = engine_alloc(&(wp->engine), ws->req_url, ws->not_url, ws->user, 
        ws->pass, wp->store, false, false, "zcall/", ready_cb, error_cb, 
        shutdown_cb, wp);

    if (ret != 0)
    {
        ws->error = WIRE_ENGINE_ALLOC_FAIL;
        iv_event_raw_post(&(ws->wire_error_ev));
        return;
    }

    //register callback functions
    if (ws->fd_init != 0)
        fd_listen(ws->fd_init, FD_READ, wire_re_init, ws);
    if (ws->fd_deinit != 0)
        fd_listen(ws->fd_deinit, FD_READ, wire_re_deinit, ws);
    if (ws->fd_send_msg != 0)
        fd_listen(ws->fd_send_msg, FD_READ, wire_re_send_msg, ws);
    if (ws->fd_send_file != 0)
        fd_listen(ws->fd_send_file, FD_READ, wire_re_send_file, ws);
    if (ws->fd_send_snapshot != 0)
        fd_listen(ws->fd_send_snapshot, FD_READ, wire_re_send_snapshot, ws);

    engine_lsnr_register(wp->engine, &(wp->e_lsnr));
    re_main(signal_cb);
}


