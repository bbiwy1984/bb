#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <iv_thread.h>

#include <bb_av.h>
#include <bb_config.h>
#include <bb_reolink.h>

static void print_banner()
{
    fprintf(stderr, "Usage: ./bb -c config file\n");
}

static void relay_timer_expired(void *object)
{
    bb_ret ret;
    struct relay *r;
    
    r = (struct relay*)object;

    fprintf(stderr, "Turning off timer\n");    

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

    fprintf(stderr, "We got error: %ld\n", rs->error);
}

static void login_success_cb(void *object)
{
}

static void init_success_cb(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;

    iv_event_raw_post(&(db->bbmct->login_ev));
}

static void disconnect_cb(void *object)
{
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;
    struct doorbell *db;
    
    db = (struct doorbell*)object;
    bbmct = db->bbmct;
    
    iv_event_raw_post(&(bbmct->init_ev));
}

static void motion_detect_stop_cb(void *object)
{
    fprintf(stderr, "Object movement stopped\n");
}

static void motion_detect_start_cb(void *object)
{
    fprintf(stderr, "Detected object movement\n");
}

static void doorbell_press_cb(void *object)
{
    bb_ret ret;
    struct doorbell *db;

    db = (struct doorbell*)object;


    if (iv_timer_registered(&(db->r->timer)) != 0)
        return;

    fprintf(stderr, "Somebody pressed the doorbell, turning timer on\n");

    iv_validate_now();

    db->r->timer.expires = iv_now;
    db->r->timer.expires.tv_sec += db->r->on_time;
    
    if ((ret = turn_relay_on(db->r)) != ALL_GOOD)
        fprintf(stderr, "Error while turning relay on: 0x%lx\n", ret);
    
    iv_timer_register(&(db->r->timer));    
}

static void pir_alarm_cb(void *object)
{
    fprintf(stderr, "PIR alarm, somebody is at your door\n");
}

void start_reo_thread(void *object)
{
    struct doorbell *db;
    struct bb_message_channel *bbmc;

    db = (struct doorbell *)object;
    bbmc = (struct bb_message_channel*)(db->bbmct);    

    iv_init();
    IV_EVENT_RAW_INIT(&(db->bbmct->talk_ev));
    IV_EVENT_RAW_INIT(&(db->bbmct->login_ev));
    IV_EVENT_RAW_INIT(&(db->bbmct->init_ev));
    
    db->bbmct->talk_ev.cookie = bbmc->bbmc_down;
    db->bbmct->talk_ev.handler = reo_talk;
    db->bbmct->login_ev.cookie = bbmc->bbmc_down;
    db->bbmct->login_ev.handler = reo_login;
    db->bbmct->init_ev.cookie = bbmc->bbmc_down;
    db->bbmct->init_ev.handler = reo_init;

    iv_event_raw_register(&(db->bbmct->talk_ev));
    iv_event_raw_register(&(db->bbmct->login_ev));
    iv_event_raw_register(&(db->bbmct->init_ev));

    reo_init((void*)bbmc->bbmc_down);
    
    iv_main();
}

int main(int argc, char *argv[])
{
    int i;
    int opt;
    int n_doors;
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
        fprintf(stderr, "Error parsing configuration: %ld\n", ret);
        return EXIT_FAILURE;
    }

    //setup functions and such
    iv_init();
    
    //untested functionality, I only own one doorbell
    for (i = 0; i < n_doors; i++)
    {
        IV_EVENT_RAW_INIT(&(db[i].bbmct->error_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->login_success_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->init_success_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->disconnect_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->motion_detect_stop_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->motion_detect_start_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->doorbell_press_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->pir_alarm_ev));
        IV_EVENT_RAW_INIT(&(db[i].bbmct->talk_init_success_ev));

        db[i].bbmct->error_ev.cookie = &db[i];
        db[i].bbmct->login_success_ev.cookie = &db[i];
        db[i].bbmct->init_success_ev.cookie = &db[i];
        db[i].bbmct->disconnect_ev.cookie = &db[i];
        db[i].bbmct->motion_detect_start_ev.cookie = &db[i];
        db[i].bbmct->motion_detect_stop_ev.cookie = &db[i];
        db[i].bbmct->doorbell_press_ev.cookie = &db[i];
        db[i].bbmct->pir_alarm_ev.cookie = &db[i];
        db[i].bbmct->talk_init_success_ev.cookie = &db[i];
        
        db[i].bbmct->error_ev.handler = error_cb;
        db[i].bbmct->login_success_ev.handler = login_success_cb;
        db[i].bbmct->init_success_ev.handler = init_success_cb;
        db[i].bbmct->disconnect_ev.handler = disconnect_cb;
        db[i].bbmct->motion_detect_stop_ev.handler = motion_detect_stop_cb;
        db[i].bbmct->motion_detect_start_ev.handler = motion_detect_start_cb;
        db[i].bbmct->doorbell_press_ev.handler = doorbell_press_cb;
        db[i].bbmct->pir_alarm_ev.handler = pir_alarm_cb;
        
        iv_event_raw_register(&(db[i].bbmct->error_ev));
        iv_event_raw_register(&(db[i].bbmct->login_success_ev));
        iv_event_raw_register(&(db[i].bbmct->init_success_ev));
        iv_event_raw_register(&(db[i].bbmct->disconnect_ev));
        iv_event_raw_register(&(db[i].bbmct->motion_detect_stop_ev));
        iv_event_raw_register(&(db[i].bbmct->motion_detect_start_ev));
        iv_event_raw_register(&(db[i].bbmct->doorbell_press_ev));
        iv_event_raw_register(&(db[i].bbmct->pir_alarm_ev));
        iv_event_raw_register(&(db[i].bbmct->talk_init_success_ev));

        if (db[i].r != NULL)
        {
            IV_TIMER_INIT(&(db[i].r->timer));
            db[i].r->timer.cookie = db[i].r;
            db[i].r->timer.handler = relay_timer_expired;
        }

        iv_thread_create("reo_protocol", start_reo_thread, (void*)&db[i]);
    }

    iv_main();

    //never reached
    return EXIT_SUCCESS;
}
