#include <stdio.h> //for NULL needed by iv_avl.h
#include <iv_avl.h>
#include <iv_list.h>

#include <fcntl.h>
#include <sys/stat.h>

#include <bb_xml.h>
#include <bb_crypto.h>
#include <bb_errors.h>
#include <bb_reolink.h>
#include <bb_reolink_priv.h>

//yes we assume only 1 doorbell per thread
static struct iv_avl_tree reo_avl;

static int comp(const struct iv_avl_node *_a, const struct iv_avl_node *_b)
{
    struct reo_priv *a;
    struct reo_priv *b;

    a = iv_container_of(_a, struct reo_priv, an);
    b = iv_container_of(_b, struct reo_priv, an);

    if (a->rs < b->rs) return -1;
    if (a->rs > b->rs) return 1;
    
    return 0;
}

static struct reo_priv *get_rp_from_avl(struct reo_session *rs)
{
    struct reo_priv *rp;
    struct iv_avl_node *an;

    an = reo_avl.root;
    
    while (an != NULL)
    {
        rp = iv_container_of(an,struct reo_priv, an);
        
        if (rs == rp->rs)
            return rp;
        if (rs < rp->rs)
            an = an->left;
        else
            an = an->right;
    }

    return NULL;
}

static inline void reo_md5(char *buf, unsigned char *hash)
{
    sprintf(buf, 
            "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], 
            hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13],
            hash[14], hash[15]);
    
    buf[(MD5_LEN*2) -1] = 0x00;
}

static inline void reo_xor(char *in, size_t len)
{
    char c;
    size_t i;

    for (i = 0; i < len; i++)
    {
        c = in[i] ^ reo_xor_key[i % sizeof(reo_xor_key)];
        in[i] = c;
    }
}

static inline __uint128_t get_state_from_reply(struct bb_message_channel *bbmc)
{
    uint32_t state;
    uint32_t message_id;

    memcpy(&message_id, bbmc->buf_read + MESSAGE_ID_OFFSET, sizeof(uint32_t));
    state = msg_id_to_state[message_id & 0x000000FF];

    if (state_msg_id[state] != message_id)
        return ST_ID_NOT_SUPPORTED;
    return state;
}

//this timer is used to keep the connection alive, the reset should be called
//after each write to the layer below and after each write and read.
static void reo_reset_ping_timer(struct bb_message_channel *bbmc)
{
    struct reo_priv *rp;
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);
  
    if (iv_timer_registered(&(rp->ping_timeout)) != 0)
        iv_timer_unregister(&(rp->ping_timeout));

    iv_validate_now();
    
    rp->ping_timeout.expires = iv_now;
    rp->ping_timeout.expires.tv_sec += rs->ping_interval;

    iv_timer_register(&(rp->ping_timeout));
}

//constructs a ping message, we use LinkType for this
static void reo_ping(void *object)
{
    struct bb_message_channel *bbmc;
        
    bbmc = (struct bb_message_channel*)object;
     
    memcpy(bbmc->buf_write, ping_header, MODERN_HEADER_SIZE);
    
    bbmc->len_write = MODERN_HEADER_SIZE;

    bbmc->write_cf(bbmc);
    reo_reset_ping_timer(bbmc);
}


//Function only checks if the received data has a valid magic value and then
//passes it on the right read function (which is state dependend).
void reo_read(struct bb_message_channel *bbmc)
{
    __uint128_t state;
    struct node *n;
    struct reo_priv *rp;
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    if (bbmc->len_read < sizeof(header_magic))
    {
        rs->error = REO_DATA_RECV_LEN_TOO_SMALL;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }

    if (memcmp(bbmc->buf_read, header_magic, sizeof(header_magic)) != 0)
    {
        rs->error= REO_MAGIC_WRONG;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }

    //first check if the state that we receive is known to us
    if ((state = get_state_from_reply(bbmc)) == ST_ID_NOT_SUPPORTED)
    {
        rs->error = REO_STATE_NOT_SUPPORTED;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }
    
    //state is known, let's see if we can actually go there
    //there is one exception here, the alarm_event_list, that we can always
    //receive, even between messages
    if (state_to_state_id[state] & rp->state != state_to_state_id[state])
    {
        rs->error = REO_STATE_NOT_ENABLED;
        iv_event_raw_post(&bbmct->error_ev);
        return;
    }

    //we can go there, reset the ping timer
    reo_reset_ping_timer(bbmc);

    //call the parser function of that state
    st_fp_table[state]->st_read(bbmc);    
}   

//writes a legacy login header
static void legacy_login_write(struct bb_message_channel *bbmc)
{
    unsigned char hash[MD5_LEN];
    size_t header_len;

    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    
    //clears the buffer and copies the header
    memset(bbmc->buf_write, 0x00, sizeof(bbmc->buf_write));
    memcpy(bbmc->buf_write, login_header, sizeof(login_header));

    //calculates the hash of the user
    if ((rs->error = bb_md5(rs->user, strlen(rs->user), hash)) != ALL_GOOD)
    {
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }
    
    //calculates the special reo md5 needed for authentication
    reo_md5(bbmc->buf_write + sizeof(login_header), hash);   
   
    if ((rs->error = bb_md5(rs->pass, strlen(rs->pass), hash)) != ALL_GOOD)
    {
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }
    
    reo_md5(bbmc->buf_write + sizeof(login_header) + (MD5_LEN*2), hash);   

    bbmc->len_write = ODD_LEGACY_LOGIN_LEN;
    bbmc->write_cf(bbmc);

    //reset ping timer
    reo_reset_ping_timer(bbmc);
}

static bb_ret check_legacy_header(char *buf, ssize_t len, int *payload_len)
{
    int offset;

    offset = sizeof(header_magic);

    //does the buffer contain enough data to hold the header?
    if (len < LEGACY_HEADER_SIZE)
        return REO_DATA_RECV_LEN_TOO_SMALL;

    //check the login message id (01 00 00 00)
    if (memcmp(buf + offset, legacy_login_msg_id, MSG_ID_LEN) != 0)
        return REO_MSG_ID_WRONG;

    //copy the payload length and check if the buffer size matches
    offset += MSG_ID_LEN;
    memcpy(payload_len, buf + offset, PAYLOAD_LEN);
    if (len - LEGACY_HEADER_SIZE != *payload_len)
        return REO_LENGTH_MISMATCH;

    //check the enc value (01)
    //TODO reply might be (02) as well, in which case we need to use AES
    offset += PAYLOAD_LEN;
    
    if (memcmp(buf + offset, legacy_enc_offset, ENC_OFFSET_LEN) != 0)
        return REO_ENC_WRONG;

    offset += ENC_OFFSET_LEN;
    //unknown weird valeu (dd iirc)
    if (memcmp(buf + offset, enc_mode_aes, sizeof(enc_mode_aes)) != 0)
        return REO_ENC_WRONG;

    offset += sizeof(enc_mode_aes);
    if (memcmp(buf + offset, legacy_unknown_rep,sizeof(legacy_unknown_rep)) 
        != 0)
    {
        return REO_ENC_WRONG;
    }
   
    //finally check the message class 14 166
    offset += sizeof(legacy_unknown_rep);
    if (memcmp(buf + offset, legacy_msg_class_rep, 
        LEGACY_MSG_CLASS_REP_LEN) != 0)
    {
        return REO_LEGACY_MSG_CLASS_WRONG;
    }

    return ALL_GOOD;
}

static void legacy_login_read(struct bb_message_channel *bbmc)
{
    char *nonce;
    char hash[MD5_LEN];
    char tmp_buf[4096];
    void *object;
    int payload_len;

    bb_ret ret;
    struct reo_priv *rp;
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    //Both the legacy login and modern login have the same message id
    //as we look everything up by message id, it can be that we get here
    //after we wrote a modern login request.
    //By checking if the nonce != NULL we know whether we should actually
    //call the read function from the modern login or not
    if (rp->nonce != NULL)
    {
        modern_login_read(bbmc);
        return;
    }

    //Ok, we are in legacy header, please continue
    //first check the header
    if ((ret = check_legacy_header(bbmc->buf_read, bbmc->len_read, 
        &payload_len)) != ALL_GOOD)
    {
        rs->error = ret;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }

    //dexor the payload so we can parse it
    reo_xor(bbmc->buf_read + LEGACY_HEADER_SIZE, payload_len);

    //parse the xml and extract the nonce
    object = init_xml(bbmc->buf_read + LEGACY_HEADER_SIZE, payload_len);
    nonce = get_node_value(object, REO_XML_NONCE);

    if ((rp->nonce = malloc(strlen(nonce) + 1)) == NULL)
    {
        rs->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(bbmct->error_ev));
        return; 
    }
    
    strcpy(rp->nonce, nonce);

    //create the key
    memset(tmp_buf, 0x00, sizeof(tmp_buf));
    if (strlen(rp->nonce) + strlen(rs->pass) + 2 > sizeof(tmp_buf))
    {
        rs->error = DEST_BUF_TOO_SMALL;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }
    
    //because the above can still int wrap, we use snprintf
    //worst case, reply is malformed and we get an error
    snprintf(tmp_buf, sizeof(tmp_buf), "%s-%s", rp->nonce, rs->pass);
    bb_md5(tmp_buf, strlen(tmp_buf), hash);
    sprintf(rp->key, "%02X%02X%02X%02X%02X%02X%02X%02X", 
        (unsigned char)hash[0], (unsigned char)hash[1],
        (unsigned char)hash[2], (unsigned char)hash[3],
        (unsigned char)hash[4], (unsigned char)hash[5],
        (unsigned char)hash[6], (unsigned char)hash[7]);

    //release the xml object now that we are really done with it
    free_xml(object);

    //set the buffer len to 0 so we can read again
    bbmc->len_read = 0;
    memset(bbmc->buf_read, 0x00, sizeof(bbmc->buf_read));

    //transit to the next stage
    rp->state |= ST_ID_MODERN_LOGIN;
    rp->state &= ~ST_ID_LEGACY_LOGIN;
    st_fp_table[ST_MODERN_LOGIN]->st_write(bbmc);
}

static void modern_login_write(struct bb_message_channel *bbmc)
{
    void *xml;
    char *xml_str;
    char tmp_buf[BUFSIZE];
    uint32_t out_len;
    unsigned char hash_hex[(MD5_LEN * 2) + 1];
    unsigned char hash[MD5_LEN];

    bb_ret ret;
    struct reo_session *rs;
    struct reo_priv *rp;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    //the standard out len should work
    memcpy(&out_len, modern_login_msg_len, sizeof(out_len));
    memset(bbmc->buf_write, 0x00, sizeof(bbmc->buf_write));
    
    if (sizeof(bbmc->buf_write) < out_len)
    {
        rs->error = DEST_BUF_TOO_SMALL;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }

    memcpy(bbmc->buf_write, login_modern_header, sizeof(login_modern_header));
    rp->enc_offset++;
    memcpy(bbmc->buf_write + ENC_SYNC_OFFSET, &(rp->enc_offset), 1);
    
    //start creating the xml document
    xml = init_xml(REO_MODERN_LOGIN_XML, sizeof(REO_MODERN_LOGIN_XML));
    
    memset(tmp_buf, 0x00, sizeof(tmp_buf));
    if ((strlen(rp->nonce) + 1 + (MD5_LEN * 2) - 1) > BUFSIZE)
    {
        rs->error = DEST_BUF_TOO_SMALL;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }
    
    //we need to set the <userName></userName> in the xml
    strcat(tmp_buf, rs->user);
    strcat(tmp_buf, rp->nonce);
    
    if ((ret = bb_md5(tmp_buf, strlen(tmp_buf), hash)) != ALL_GOOD)
        goto out;
    
    reo_md5(hash_hex, hash);
    set_node_value(xml, "userName", hash_hex);
 
    //calculate the password and put it in the xml
    memset(tmp_buf, 0x00, sizeof(tmp_buf));
    if ((strlen(rp->nonce) + 1 + (MD5_LEN * 2) - 1) > BUFSIZE)
        goto out;
    
    //we need to set the <password></password> in the xml
    strcat(tmp_buf, rs->pass);
    strcat(tmp_buf, rp->nonce);
     
    if ((ret = bb_md5(tmp_buf, strlen(tmp_buf), hash)) != ALL_GOOD)
        goto out;

    reo_md5(hash_hex, hash);
    set_node_value(xml, "password", hash_hex);

    //save the xml to the outbuf
    xml_to_str(xml, bbmc->buf_write + sizeof(login_modern_header), 
        sizeof(bbmc->buf_write) - sizeof(login_modern_header));

    //set the proper length of the payload
    out_len = strlen(bbmc->buf_write + sizeof(login_modern_header));
    memcpy(bbmc->buf_write + 8, &out_len, 4);

    //xor the payload
    reo_xor(bbmc->buf_write + MODERN_HEADER_SIZE, out_len);

    //write it
    bbmc->len_write = out_len + MODERN_HEADER_SIZE;
    bbmc->write_cf(bbmc);

out:
    free_xml(xml);    

    if (ret != ALL_GOOD)
    {
        rs->error = DEST_BUF_TOO_SMALL;
        iv_event_raw_post(&(bbmct->error_ev));
    }

    //reset ping timer
    reo_reset_ping_timer(bbmc);
}

static bb_ret check_modern_header(char *buf, ssize_t len, char *msg_id, 
    char *enc_offset, char *msg_class, char *status_code, uint32_t *payload_len)
{
    int offset;

    offset = sizeof(header_magic);

    //does the buffer contain enough data to hold the header?
    if (len < MODERN_HEADER_SIZE)
        return REO_DATA_RECV_LEN_TOO_SMALL;

    //check the login message id (01 00 00 00)
    if (memcmp(buf + offset, msg_id, MSG_ID_LEN) != 0)
        return REO_MSG_ID_WRONG;

    //copy the payload length and check if the buffer size matches
    offset += MSG_ID_LEN;
    memcpy(payload_len, buf + offset, PAYLOAD_LEN);

    if (len - MODERN_HEADER_SIZE != *payload_len)
        return REO_LENGTH_MISMATCH;

    offset += PAYLOAD_LEN;
    //Ignore because the enc_offset can be out of order (in theory). We solved
    //this issue by applying states so replies can arrive out of order anyway.
    /*
    if (memcmp(buf + offset, enc_offset, ENC_OFFSET_LEN) != 0)
        return REO_ENC_WRONG;
    */
    offset += ENC_OFFSET_LEN;
    if (memcmp(buf + offset, status_code, STATUS_CODE_LEN) != 0)
        return REO_STATUS_CODE_WRONG;

    //check the message class
    offset += STATUS_CODE_LEN;
    if (memcmp(buf + offset, msg_class, MSG_CLASS_LEN) != 0)
        return REO_LEGACY_MSG_CLASS_WRONG;

    //check the payload offset
    if (memcmp(buf + offset, modern_payload_offset, PAYLOAD_OFF_SIZE) != 0)
        return REO_PAYLOAD_OFF_WRONG;

    return ALL_GOOD;
}

static void modern_login_read(struct bb_message_channel *bbmc)
{
    uint32_t ret;
    int payload_len;
    struct reo_priv *rp;
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    //first check the header
    if ((ret = check_modern_header(bbmc->buf_read, bbmc->len_read, 
        modern_login_msg_id, modern_enc_offset, modern_msg_class_rep, 
        modern_stat_code_rep, &payload_len)) != ALL_GOOD)
    {
        rs->error = ret;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }

    //dexor the payload so we can parse it
    //NOTE it is not needed to do this as we don't use this information
    reo_xor(bbmc->buf_read + MODERN_HEADER_SIZE, payload_len);

    //set the buffer len to 0 so we can read again
    bbmc->len_read = 0;
    memset(bbmc->buf_read, 0x00, sizeof(bbmc->buf_read));

    //next state would be wait and listen for now, now that we are logged in
    //set the states of, so we can no longer receive login messages
    rp->state &= ~ST_ID_MODERN_LOGIN;
    
    //notify the upper layer
    iv_event_raw_post(&(bbmct->login_success_ev));
}

static void not_supported_read(struct bb_message_channel *bbmc)
{
    char *offset;
    char dec[4096];
    uint32_t msg_id;
    ssize_t len;

    struct reo_priv *rp;
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    //do we have a ping reply?
    //note that we only check the message id, not the rest, who cares?
    if (bbmc->len_read == MODERN_HEADER_SIZE && 
        memcmp(bbmc->buf_read + MAGIC_LEN, ping_msg_id, MSG_ID_LEN) == 0)
    {
        goto out;
    }
 
    offset = bbmc->buf_read + 24;
    len = bbmc->len_read - 24;
    
    memcpy(&msg_id, bbmc->buf_read + MESSAGE_ID_OFFSET, sizeof(msg_id));
    
    memset(dec, 0x00, sizeof(dec));
    aes_128_cfb_dec(rp->key, reo_iv, offset, len, dec);

out:
    memset(bbmc->buf_read, 0x00, sizeof(bbmc->buf_read));
    bbmc->len_read = 0;

    //reset the timer so we now when to ping
    reo_reset_ping_timer(bbmc);
}

static void alarm_event_list_read(struct bb_message_channel *bbmc)
{
    char *offset;
    char *status;
    char *ai_type;
    char dec[4096];
    void *object;
    uint32_t len;
    uint32_t payload_len;
    static char motion_detected;    

    bb_ret ret;

    struct reo_priv *rp;
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    //first check the header
    if ((ret = check_modern_header(bbmc->buf_read, bbmc->len_read, 
        alarm_event_list_msg_id, alarm_enc_offset, modern_msg_class_rep, 
        modern_stat_code_rep, &payload_len)) != ALL_GOOD)
    {
        rs->error = ret;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }

    offset = bbmc->buf_read + MODERN_HEADER_SIZE;
    len = bbmc->len_read - MODERN_HEADER_SIZE;

    memset(dec, 0x00, sizeof(dec));
    aes_128_cfb_dec(rp->key, reo_iv, offset, len, dec);

    //parse the xml and extract the nonce
    object = init_xml(dec, len);
    status = get_node_value(object, REO_XML_STATUS);
    ai_type = get_node_value(object, REO_XML_AI_TYPE);

    if (strstr(ai_type, "people") != NULL)
        iv_event_raw_post(&(bbmct->pir_alarm_ev));
    else if ((strstr(status, "visitor") != NULL) && 
        (strstr(status, "MD") == NULL))
    {
        iv_event_raw_post(&(bbmct->doorbell_press_ev));
    }
    
    //movement can be detected with a doorbell press or (possibly) with a PIR
    //detection. We only alert when there is movement but no other event
    else if (strstr(status, "MD") != NULL)
    {
        motion_detected = 1;
        iv_event_raw_post(&(bbmct->motion_detect_start_ev));
    }

    //movement stopped detecting    
    else if ((strstr(status, "none") != NULL) && (motion_detected == 1))
    {
        motion_detected = 0;
        iv_event_raw_post(&(bbmct->motion_detect_stop_ev));
    }
    
    //release the xml object now that we are really done with it
    free_xml(object);

    //clear everything up
    memset(bbmc->buf_read, 0x00, sizeof(bbmc->buf_read));
    bbmc->len_read = 0;
}

static void not_implemented_read(struct bb_message_channel *bbmc)
{
    not_supported_read(bbmc);
}

//should never be called
static void not_supported_write(struct bb_message_channel *bbmc)
{
}

//should never be called
static void not_implemented_write(struct bb_message_channel *bbmc)
{
}

static void talk_ability_write(struct bb_message_channel *bbmc)
{
    int out_len;
    uint32_t ret;
    char tmp_buf[BUFSIZE];
    struct reo_session *rs;
    struct reo_priv *rp;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    //set the out_len
    out_len = sizeof(talk_ability_header) + sizeof(REO_TALK_ABILITY);

    memset(bbmc->buf_write, 0x00, sizeof(bbmc->buf_write));
    
    if (sizeof(bbmc->buf_write) < out_len)
    {
        rs->error = DEST_BUF_TOO_SMALL;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }
    memcpy(bbmc->buf_write, talk_ability_header, sizeof(talk_header));

    rp->enc_offset++;
    memcpy(bbmc->buf_write + ENC_SYNC_OFFSET, &(rp->enc_offset), 1);
 
    //below could be optimized out
    memset(tmp_buf, 0x00, sizeof(tmp_buf));
    if (sizeof(tmp_buf) < sizeof(REO_TALK_ABILITY))
    {
        rs->error = DEST_BUF_TOO_SMALL;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }

    //set the msg length
    memcpy(bbmc->buf_write + LEN_OFFSET, &out_len, PAYLOAD_LEN);
    memcpy(bbmc->buf_write + PAYLOAD_OFFSET, &out_len, PAYLOAD_LEN);

    //encrypt the payload
    aes_128_cfb_enc(rp->key, reo_iv, talk_ability, sizeof(REO_TALK_ABILITY),
        tmp_buf);
    
    //copy the payload to the destination
    memcpy(bbmc->buf_write + sizeof(talk_header), tmp_buf, 
        sizeof(REO_TALK_ABILITY));

    //write it
    rp->state |= ST_ID_TALK_ABILITY;
    bbmc->len_write = out_len + MODERN_HEADER_SIZE;
 
    //reset the timer so we now when to ping
    reo_reset_ping_timer(bbmc);
    
    //send it
    bbmc->write_cf(bbmc);
}

static void talk_ability_read(struct bb_message_channel *bbmc)
{
    char *offset;
    char dec[4096];
    uint32_t len;
    uint32_t payload_len;

    bb_ret ret;

    struct reo_priv *rp;
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    //first check the header
    if ((ret = check_modern_header(bbmc->buf_read, bbmc->len_read, 
        talk_ability_msg_id, modern_enc_offset, modern_msg_class_rep, 
        modern_stat_code_rep, &payload_len)) != ALL_GOOD)
    {
        rs->error = ret;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }

    offset = bbmc->buf_read + MODERN_HEADER_SIZE;
    len = bbmc->len_read - MODERN_HEADER_SIZE;

    memset(dec, 0x00, sizeof(dec));
    aes_128_cfb_dec(rp->key, reo_iv, offset, len, dec);

    fprintf(stderr, "just received: %s\n", dec);

    //clear everything up
    memset(bbmc->buf_read, 0x00, sizeof(bbmc->buf_read));
    bbmc->len_read = 0;
    rp->state &= ~ST_ID_TALK_ABILITY;

    //reset the timer so we now when to ping
    reo_reset_ping_timer(bbmc);

    //transit to the next stage
    rp->state |= ST_ID_TALK_CONFIG;
    rp->state &= ~ST_ID_TALK_ABILITY;
    st_fp_table[ST_TALK_CONFIG]->st_write(bbmc);
}

static void talk_config_write(struct bb_message_channel *bbmc)
{
    int out_len;
    int offset;
    uint32_t ret;
    char tmp_buf[BUFSIZE];
    struct reo_session *rs;
    struct reo_priv *rp;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    //set the out_len
    out_len = sizeof(REO_TALK_CONFIG_BODY) + sizeof(REO_TALK_CONFIG_BIN);

    memset(bbmc->buf_write, 0x00, sizeof(bbmc->buf_write));
    
    if (sizeof(bbmc->buf_write) < out_len)
    {
        rs->error = DEST_BUF_TOO_SMALL;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }

    memcpy(bbmc->buf_write, talk_config_header, sizeof(talk_config_header));

    rp->enc_offset++;
    memcpy(bbmc->buf_write + ENC_SYNC_OFFSET, &(rp->enc_offset), 1);
 
    //below could be optimized out
    memset(tmp_buf, 0x00, sizeof(tmp_buf));
    if (sizeof(tmp_buf) < sizeof(REO_TALK_CONFIG_BODY))
    {
        rs->error = DEST_BUF_TOO_SMALL;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }

    //set the msg length
    memcpy(bbmc->buf_write + LEN_OFFSET, &out_len, PAYLOAD_LEN);

    offset = sizeof(REO_TALK_CONFIG_BODY);
    memcpy(bbmc->buf_write + PAYLOAD_OFFSET, &offset, PAYLOAD_LEN);

    //encrypt the payload
    aes_128_cfb_enc(rp->key, reo_iv, REO_TALK_CONFIG_BODY, 
        sizeof(REO_TALK_CONFIG_BODY), tmp_buf);
    
    //copy the payload to the destination
    memcpy(bbmc->buf_write + sizeof(talk_config_header), tmp_buf, 
        sizeof(REO_TALK_CONFIG_BODY));

    //now we are off to the second part
    memset(tmp_buf, 0x00, sizeof(tmp_buf));
    if (sizeof(tmp_buf) < sizeof(REO_TALK_CONFIG_BIN))
    {
        rs->error = DEST_BUF_TOO_SMALL;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }

    //encrypt the payload
    aes_128_cfb_enc(rp->key, reo_iv, REO_TALK_CONFIG_BIN, 
        sizeof(REO_TALK_CONFIG_BIN), tmp_buf);
    
    //copy the payload to the destination
    memcpy(bbmc->buf_write + sizeof(talk_config_header) + 
        sizeof(REO_TALK_CONFIG_BODY), tmp_buf, sizeof(REO_TALK_CONFIG_BIN));

    //write it
    rp->state |= ST_ID_TALK_CONFIG;
    bbmc->len_write = out_len + MODERN_HEADER_SIZE;
 
    //reset the timer so we now when to ping
    reo_reset_ping_timer(bbmc);
    
    //send it
    bbmc->write_cf(bbmc);
}

static void talk_config_read(struct bb_message_channel *bbmc)
{
    char *offset;
    uint32_t len;
    uint32_t payload_len;

    bb_ret ret;

    struct reo_priv *rp;
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    //first check the header
    if ((ret = check_modern_header(bbmc->buf_read, bbmc->len_read, 
        talk_config_msg_id, modern_enc_offset, modern_msg_class_rep, 
        modern_stat_code_rep, &payload_len)) != ALL_GOOD)
    {
        rs->error = ret;
        iv_event_raw_post(&(bbmct->error_ev));
        return;
    }

    bbmc->len_read = 0;
    memset(bbmc->buf_read, 0x00, sizeof(bbmc->buf_read));

    //reset the timer so we now when to ping
    reo_reset_ping_timer(bbmc);

    //for now don't do anything
    rp->state &= ~ST_ID_TALK_CONFIG;
    rp->state |= ST_ID_TALK;
    st_fp_table[ST_TALK]->st_write(bbmc);
}

static void talk_write(struct bb_message_channel *bbmc)
{
    int tmp;
    int offset;
    static int out_len;
    uint32_t ret;
    char tmp_buf[BUFSIZE];
    static struct timespec ts;

    struct reo_session *rs;
    struct reo_priv *rp;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    //the header remains the same throughout different calls because of the
    //block size, so we set it only once
    //set the out_len
    if (out_len == 0)
    {
        out_len =  + sizeof(REO_TALK) + sizeof(adpcm_header) + 
            DVI_BLOCK_SIZE_DEC + 4;

        memset(bbmc->buf_write, 0x00, sizeof(bbmc->buf_write));

        if (sizeof(bbmc->buf_write) < out_len)
        {
            rs->error = DEST_BUF_TOO_SMALL;
            iv_event_raw_post(&(bbmct->error_ev));
            return;
        }
    
        ts.tv_sec = 0;
        ts.tv_nsec = SLEEP_TIME;
    
        //write the reolink header
        memcpy(bbmc->buf_write, talk_header, sizeof(talk_header));
    
        rp->enc_offset++;
        memcpy(bbmc->buf_write + ENC_SYNC_OFFSET, &(rp->enc_offset), 1);
     
        //below could be optimized out
        memset(tmp_buf, 0x00, sizeof(tmp_buf));
        if (sizeof(tmp_buf) < sizeof(REO_TALK))
        {
            rs->error = DEST_BUF_TOO_SMALL;
            iv_event_raw_post(&(bbmct->error_ev));
            return;
        }

        //set the msg length (length total payload ex header)
        memcpy(bbmc->buf_write + LEN_OFFSET, &out_len, PAYLOAD_LEN);

        //set the offset to the adpcm header
        offset = sizeof(REO_TALK);
        memcpy(bbmc->buf_write + PAYLOAD_OFFSET, &offset, PAYLOAD_LEN);

        //encrypt the payload
        aes_128_cfb_enc(rp->key, reo_iv, REO_TALK, sizeof(REO_TALK), tmp_buf);

        //copy the payload to the destination
        memcpy(bbmc->buf_write + sizeof(talk_header), tmp_buf, 
            sizeof(REO_TALK));

        //tmp is used an offset as the sizeof() aligns wrong for 2 bytes
        tmp = DVI_BLOCK_SIZE_DEC + 4;
        memcpy(bbmc->buf_write + sizeof(talk_header) + sizeof(REO_TALK), 
                adpcm_header, sizeof(adpcm_header));
        memcpy(bbmc->buf_write + sizeof(talk_header) + sizeof(REO_TALK) + 
                sizeof(ADPCM_MAGIC_1), &tmp, sizeof(ADPCM_PAYLOAD_LEN));
        memcpy(bbmc->buf_write + sizeof(talk_header) + sizeof(REO_TALK) + 
                sizeof(ADPCM_MAGIC_1) + ADPCM_PAYLOAD_LEN_OFFSET, &tmp, 
                ADPCM_PAYLOAD_LEN_DEC);
    }

    tmp = sizeof(talk_header) + sizeof(REO_TALK) + sizeof(adpcm_header);
    iv_event_raw_post(&(bbmct->get_audio_frame_ev));

    while (bbmct->bbmc.len_write == 0);

    //if the audio stream stops, stop the talk state and return
    if (bbmct->bbmc.len_write == -1)
    {
        rp->state &= ~ST_ID_TALK;
        return;
    }
    //copy the payload to the destination
    memcpy(bbmc->buf_write + tmp, bbmct->bbmc.buf_write, bbmct->bbmc.len_write);

    //set the offset
    rp->enc_offset++;
    memcpy(bbmc->buf_write + ENC_SYNC_OFFSET, &(rp->enc_offset), 1);

    //write it
    bbmc->len_write = out_len + sizeof(talk_header);

    //send it
    bbmc->write_cf(bbmc);
    
    //sleep so we are sure that we don't end up with gibberish
    nanosleep(&ts, &ts);

    //reset the timer so we now when to ping
    reo_reset_ping_timer(bbmc);
}

static void talk_read(struct bb_message_channel *bbmc)
{
    bbmc->len_read = 0;
    st_fp_table[ST_TALK]->st_write(bbmc);
}

void reo_init(void *object)
{
    struct reo_priv *rp;
    struct reo_session *rs;
    struct bb_message_channel *bbmc;
    struct bb_message_channel_top *bbmct;

    bbmc = (struct bb_message_channel*)object;
    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);

    //allocate a reo private session struct in which we can store session
    //information (e.g. key and such)
    if ((rp = malloc(sizeof(*rp))) == NULL)
    {
        rs->error = NO_MORE_MEMORY;
        iv_event_raw_post(&(bbmct->error_ev));
    }
    memset(rp, 0x00, sizeof(*rp));

    rp->rs = rs;

    //store it in the avl tree
    if (iv_avl_tree_empty(&reo_avl) == 1)
        INIT_IV_AVL_TREE(&reo_avl, comp);

    iv_avl_tree_insert(&reo_avl, &rp->an);

    //init the layers below
    bbmc->init_cf(bbmc);
}

void reo_disconn_cb(struct bb_message_channel *bbmc)
{
    struct reo_priv *rp;
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    reo_deinit(bbmc);

    //notify up that we have deinited everything
    iv_event_raw_post(&(bbmct->disconnect_ev));
}

void reo_deinit(void *object)
{
    struct reo_priv *rp;
    struct reo_session *rs;
    struct bb_message_channel *bbmc;
    struct bb_message_channel_top *bbmct;
    
    bbmc = (struct bb_message_channel*)object;
    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    //first cleanup the layers below
    bbmc->deinit_cf(bbmc);

    //delete the entry
    iv_avl_tree_delete(&reo_avl, &(rp->an)); 

    //if we got that far that we alloc'ed mem for a nonce, delete it
    if (rp->nonce != NULL)
        free(rp->nonce);

    //deregister timers
    if (iv_timer_registered(&(rp->ping_timeout)))
        iv_timer_unregister(&(rp->ping_timeout));

    free(rp);
}

void reo_login(void *object)
{
    struct reo_priv *rp;
    struct reo_session *rs;
    struct bb_message_channel *bbmc;
    struct bb_message_channel_top *bbmct;
    
    bbmc = (struct bb_message_channel*)object;
    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    //this resets all the other states, if we login then we really need to
    //start all over, except for receiving alarm event lists
    rp->state = ST_LEGACY_LOGIN;
    rp->state |= ST_ALARM_EVENT_LIST; 

    //start constructing the message
    st_fp_table[ST_LEGACY_LOGIN]->st_write(bbmc);
}

void reo_talk(void *object)
{
    struct bb_message_channel *bbmc;

    bbmc = (struct bb_message_channel*)object;
    
    talk_ability_write(bbmc);
}

void reo_write_cb(struct bb_message_channel *bbmc)
{
}

void reo_error_cb(struct bb_message_channel *bbmc, bb_ret error)
{
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;
    
    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rs->error = error;

    iv_event_raw_post(&(bbmct->error_ev));
}


//means the layer below, successfully connected to the server
void reo_init_success_cb(struct bb_message_channel *bbmc)
{
    struct reo_priv *rp;
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;

    bbmct = (struct bb_message_channel_top*)(bbmc->bbmc_up);
    rs = container_of(bbmct, struct reo_session, bbmct);
    rp = get_rp_from_avl(rs);

    //init the timer struct, but dont validate it yet
    IV_TIMER_INIT(&(rp->ping_timeout));

    rp->ping_timeout.cookie = bbmc;
    rp->ping_timeout.handler = reo_ping;

    //notify the upper layer that we succesfully opened a connection
    iv_event_raw_post(&(bbmct->init_success_ev));
}
