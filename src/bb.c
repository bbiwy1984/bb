#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <iv_thread.h>

#include <bb_av.h>
#include <bb_wire.h>
#include <bb_config.h>
#include <bb_reolink.h>

static void print_banner()
{
    fprintf(stderr, "Usage: ./bb -c config file\n");
}

static void wire_sent_msg_success_cb(void *object)
{
}

static void wire_sent_file_success_cb(void *object)
{
}

static void wire_sent_snapshot_success_cb(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;

    mtx_unlock(&(db->mtx_snapshot));
}

static void wire_init_success_cb(void *object)
{
}
 
static void wire_deinit_success_cb(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;

    iv_event_raw_unregister(&(db->wire_init_ev));
    iv_event_raw_unregister(&(db->wire_deinit_ev));
    iv_event_raw_unregister(&(db->wire_send_msg_ev));
    iv_event_raw_unregister(&(db->wire_send_file_ev));
    iv_event_raw_unregister(&(db->wire_send_snapshot_ev));
}

static void relay_timer_expired(void *object)
{
    bb_ret ret;
    struct relay *r;
    
    r = (struct relay*)object;

    if ((ret = turn_relay_off(r)) != ALL_GOOD)
        fprintf(stderr, "Got error operating relay: 0x%lx\n", ret);
}

static void error_cb(void *object)
{
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;
    struct doorbell *db;
    
    db = (struct doorbell*)object;
    bbmct = db->bbmct;
    rs = container_of(bbmct, struct reo_session, bbmct);

    fprintf(stderr, "We got error: %lx\n", rs->error);
}

static void login_success_cb(void *object)
{
}

static void init_success_cb(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;

    iv_event_raw_post(&(db->db_login_ev));
}

static void disconnect_cb(void *object)
{
    struct doorbell *db;
    
    db = (struct doorbell*)object;

    iv_event_raw_post(&(db->db_init_ev));
}

static void motion_detect_stop_cb(void *object)
{
}

static void wire_take_snapshot_cb(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;

    //lock the mem region so we are sure we send once 
    mtx_lock(&(db->mtx_snapshot));
    iv_event_raw_post(&(db->db_take_snapshot_ev));
}

static void motion_detect_start_cb(void *object)
{
     struct doorbell *db;
 
     db = (struct doorbell*)object;
 
     if (db->ws != NULL)
     {
        if (db->mov_msg != NULL)
        {
            strncpy(db->ws->bbmc.buf_write, db->mov_msg, 
                sizeof(db->ws->bbmc.buf_write));
            db->ws->bbmc.len_write = strlen(db->mov_msg);
            iv_event_raw_post(&(db->wire_send_msg_ev));
        }

        if (db->mov_alert_send_snapshot == true)
            wire_take_snapshot_cb(object);
     }
}

static void doorbell_press_cb(void *object)
{
    bb_ret ret;
    struct doorbell *db;

    db = (struct doorbell*)object;

    if (iv_timer_registered(&(db->r->timer)) != 0)
        return;

    if (db->ws != NULL)
    {
        if (db->ring_msg != NULL)
        {
            strncpy(db->ws->bbmc.buf_write, db->ring_msg, 
                sizeof(db->ws->bbmc.buf_write));
            db->ws->bbmc.len_write = strlen(db->ring_msg);
            iv_event_raw_post(&(db->wire_send_msg_ev));
        }
        if (db->ring_alert_send_snapshot == true)
            wire_take_snapshot_cb(object);
    }

    iv_validate_now();

    if (db->r != NULL)
    {
        db->r->timer.expires = iv_now;
        db->r->timer.expires.tv_sec += db->r->on_time;
    
        if ((ret = turn_relay_on(db->r)) != ALL_GOOD)
            fprintf(stderr, "Error while turning relay on: 0x%lx\n", ret);
    
        iv_timer_register(&(db->r->timer));
    }
}

static void pir_alarm_cb(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;

    if (db->ws != NULL)
    {
        if (db->pir_msg != NULL)
        {
            strncpy(db->ws->bbmc.buf_write, db->pir_msg, 
                sizeof(db->ws->bbmc.buf_write));
            db->ws->bbmc.len_write = strlen(db->pir_msg);
            iv_event_raw_post(&(db->wire_send_msg_ev));
        }

        if (db->pir_alert_send_snapshot == true)
            wire_take_snapshot_cb(object);
    }
}

static void wire_snapshot_success_cb(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;
    
    //unlock the mem region so we are sure we send once 
    mtx_unlock(&(db->mtx_snapshot));
}

//we have taken a snapshot, pass it on to wire
static void take_snapshot_success_cb(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;
    iv_event_raw_post(&(db->wire_send_snapshot_ev));
}

void start_reo_thread(void *object)
{
    struct doorbell *db;
    struct bb_message_channel *bbmc;

    db = (struct doorbell *)object;
    bbmc = (struct bb_message_channel*)(db->bbmct);    

    db->bbmct->snapshot_buf = db->snapshot_buf;

    iv_init();
    IV_EVENT_RAW_INIT(&(db->db_login_ev));
    IV_EVENT_RAW_INIT(&(db->db_init_ev));
    IV_EVENT_RAW_INIT(&(db->db_take_snapshot_ev));
    
    db->db_login_ev.cookie = bbmc->bbmc_down;
    db->db_login_ev.handler = reo_login;
    db->db_init_ev.cookie = bbmc->bbmc_down;
    db->db_init_ev.handler = reo_init;
    db->db_take_snapshot_ev.cookie = bbmc->bbmc_down;
    db->db_take_snapshot_ev.handler = reo_take_snapshot;

    iv_event_raw_register(&(db->db_login_ev));
    iv_event_raw_register(&(db->db_init_ev));
    iv_event_raw_register(&(db->db_take_snapshot_ev));

    reo_init((void*)bbmc->bbmc_down);
    
    iv_main();
}

void start_wire_thread(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;
    
    db->ws->snapshot_buf = db->snapshot_buf;

    iv_init();
    IV_EVENT_RAW_INIT(&(db->wire_init_ev));
    IV_EVENT_RAW_INIT(&(db->wire_deinit_ev));
    IV_EVENT_RAW_INIT(&(db->wire_send_msg_ev));
    IV_EVENT_RAW_INIT(&(db->wire_send_file_ev));
    IV_EVENT_RAW_INIT(&(db->wire_send_snapshot_ev));

    db->wire_init_ev.cookie = db;
    db->wire_init_ev.handler = wire_init;
    db->wire_deinit_ev.cookie = db;
    db->wire_deinit_ev.handler = wire_deinit;
    db->wire_send_msg_ev.cookie = db;
    db->wire_send_msg_ev.handler = wire_send_msg;
    db->wire_send_snapshot_ev.cookie = db;
    db->wire_send_snapshot_ev.handler = wire_send_snapshot;
    db->wire_send_file_ev.cookie = db;
    db->wire_send_file_ev.handler = wire_send_file;

    iv_event_raw_register(&(db->wire_init_ev));
    iv_event_raw_register(&(db->wire_deinit_ev));
    iv_event_raw_register(&(db->wire_send_msg_ev));
    iv_event_raw_register(&(db->wire_send_file_ev));
    iv_event_raw_register(&(db->wire_send_snapshot_ev));

    //set the fd in Wire so we can actually send events
    db->ws->fd_init = db->wire_init_ev.event_rfd.fd;    
    db->ws->fd_deinit = db->wire_deinit_ev.event_rfd.fd;    
    db->ws->fd_send_msg = db->wire_send_msg_ev.event_rfd.fd;    
    db->ws->fd_send_file = db->wire_send_file_ev.event_rfd.fd;    
    db->ws->fd_send_snapshot = db->wire_send_snapshot_ev.event_rfd.fd;    

    //start wire
    wire_init(db->ws);

    //cleaning up
    iv_deinit();
}

int main(int argc, char *argv[])
{
    int i;
    int opt;
    int n_doors;
    void *mem;
    char *config_file;
    struct doorbell *db;

    bb_ret ret;

    config_file = NULL;

    while ((opt = getopt(argc, argv, "c:")) != -1)
    {
        switch (opt)
        {
            case 'c':
                config_file = optarg;
                break;
            default:
                print_banner();
                return EXIT_FAILURE;
        }
    }
    
    if (config_file == NULL)
    {
        fprintf(stderr, "Please specify config file\n");
        return EXIT_FAILURE;
    }

    //we only use the first doorbell, we do not test all of them at once
    //who does that anyway?
    if ((ret = conf_parse(config_file, &n_doors, &db)) != ALL_GOOD)
    {
        fprintf(stderr, "Error parsing configuration: %lX\n", ret);
        return EXIT_FAILURE;
    }

    //setup functions and such
    iv_init();
    
    //untested functionality, I only own one doorbell
    for (i = 0; i < n_doors; i++)
    {
        mtx_init(&(db[i].mtx_snapshot), mtx_plain);

        IV_EVENT_RAW_INIT(&(db[i].bbmct->error_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->login_success_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->init_success_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->disconnect_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->take_snapshot_success_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->motion_detect_stop_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->motion_detect_start_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->doorbell_press_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->pir_alarm_ev));

        db[i].bbmct->error_ev.cookie = &db[i]; 
        db[i].bbmct->login_success_ev.cookie = &db[i];
        db[i].bbmct->init_success_ev.cookie = &db[i];
        db[i].bbmct->disconnect_ev.cookie = &db[i];
        db[i].bbmct->take_snapshot_success_ev.cookie = &db[i];
        db[i].bbmct->motion_detect_start_ev.cookie = &db[i];
        db[i].bbmct->motion_detect_stop_ev.cookie = &db[i];
        db[i].bbmct->doorbell_press_ev.cookie = &db[i];
        db[i].bbmct->pir_alarm_ev.cookie = &db[i];
       
        db[i].bbmct->error_ev.handler = error_cb;
        db[i].bbmct->login_success_ev.handler = login_success_cb;
        db[i].bbmct->init_success_ev.handler = init_success_cb;
        db[i].bbmct->disconnect_ev.handler = disconnect_cb;
        db[i].bbmct->take_snapshot_success_ev.handler =take_snapshot_success_cb;
        db[i].bbmct->motion_detect_start_ev.handler = motion_detect_start_cb;
        db[i].bbmct->motion_detect_stop_ev.handler = motion_detect_stop_cb;
        db[i].bbmct->doorbell_press_ev.handler = doorbell_press_cb;
        db[i].bbmct->pir_alarm_ev.handler = pir_alarm_cb;
       
        iv_event_raw_register(&(db[i].bbmct->error_ev));
        iv_event_raw_register(&(db[i].bbmct->login_success_ev));
        iv_event_raw_register(&(db[i].bbmct->init_success_ev));
        iv_event_raw_register(&(db[i].bbmct->disconnect_ev));
        iv_event_raw_register(&(db[i].bbmct->take_snapshot_success_ev));
        iv_event_raw_register(&(db[i].bbmct->motion_detect_stop_ev));
        iv_event_raw_register(&(db[i].bbmct->motion_detect_start_ev));
        iv_event_raw_register(&(db[i].bbmct->doorbell_press_ev));
        iv_event_raw_register(&(db[i].bbmct->pir_alarm_ev));

        //create shared memory regions for easy sharing of pictures and 
        //video related data
        if ((mem = mmap(NULL, SNAPSHOT_SIZE * sizeof(char), PROT_READ | 
            PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0)) == MAP_FAILED)
        {
            fprintf(stderr, "Cannot mmap snapshot memory\n");
            return EXIT_FAILURE;
        }

        db->snapshot_buf = (char*)mem;

        if ((mem = mmap(NULL, VIDEO_FRAME_SIZE * sizeof(char), PROT_READ | 
            PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0)) == MAP_FAILED)
        {
            fprintf(stderr, "Cannot mmap video frames memory\n");
            return EXIT_FAILURE;
        }

        db->video_frames_buf = mem;

        if (db[i].r != NULL)
        {
            IV_TIMER_INIT(&(db[i].r->timer));
            db[i].r->timer.cookie = db[i].r;
            db[i].r->timer.handler = relay_timer_expired;
        }

        if (db[i].ws != NULL)
        {
            IV_EVENT_RAW_INIT(&(db[i].ws->wire_error_ev));
            IV_EVENT_RAW_INIT(&(db[i].ws->wire_init_success_ev));
            IV_EVENT_RAW_INIT(&(db[i].ws->wire_deinit_success_ev));
            IV_EVENT_RAW_INIT(&(db[i].ws->wire_sent_msg_success_ev));
            IV_EVENT_RAW_INIT(&(db[i].ws->wire_sent_file_success_ev));
            IV_EVENT_RAW_INIT(&(db[i].ws->wire_sent_snapshot_success_ev));
            IV_EVENT_RAW_INIT(&(db[i].ws->wire_take_snapshot_ev));

            db[i].ws->wire_error_ev.cookie = &db[i];
            db[i].ws->wire_error_ev.handler = error_cb;
            db[i].ws->wire_init_success_ev.cookie = &db[i];
            db[i].ws->wire_init_success_ev.handler = wire_init_success_cb;
            db[i].ws->wire_deinit_success_ev.cookie = &db[i];
            db[i].ws->wire_deinit_success_ev.handler = wire_deinit_success_cb;
            db[i].ws->wire_sent_msg_success_ev.cookie = &db[i];
            db[i].ws->wire_sent_msg_success_ev.handler = 
                wire_sent_msg_success_cb;
            db[i].ws->wire_sent_file_success_ev.cookie = &db[i];
            db[i].ws->wire_sent_file_success_ev.handler =
                wire_sent_file_success_cb;
            db[i].ws->wire_sent_snapshot_success_ev.cookie = &db[i];
            db[i].ws->wire_sent_snapshot_success_ev.handler = 
                wire_sent_snapshot_success_cb;
            db[i].ws->wire_take_snapshot_ev.cookie = &db[i];
            db[i].ws->wire_take_snapshot_ev.handler = wire_take_snapshot_cb;

            iv_event_raw_register(&(db[i].ws->wire_error_ev));
            iv_event_raw_register(&(db[i].ws->wire_init_success_ev));
            iv_event_raw_register(&(db[i].ws->wire_deinit_success_ev));
            iv_event_raw_register(&(db[i].ws->wire_sent_msg_success_ev));
            iv_event_raw_register(&(db[i].ws->wire_sent_file_success_ev));
            iv_event_raw_register(&(db[i].ws->wire_sent_snapshot_success_ev));
            iv_event_raw_register(&(db[i].ws->wire_take_snapshot_ev));

            iv_thread_create("wire_protocol", start_wire_thread, (void*)&db[i]);
        }

        iv_thread_create("reo_protocol", start_reo_thread, (void*)&db[i]);
    }

    iv_main();
    iv_deinit();

    munmap(db->snapshot_buf, SNAPSHOT_SIZE);
    munmap(db->video_frames_buf, VIDEO_FRAME_SIZE);

    //never reached
    return EXIT_SUCCESS;
}
