#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <iv_thread.h>

#include <bb_av.h>
#include <bb_config.h>
#include <bb_reolink.h>

char wait_and_listen;
char *audio_file;
struct bb_message_channel *bbmc;

void print_banner()
{
    fprintf(stderr, "Usage: ./test_reo -c config file -w [wait and listen] \
            -a <send audio file>\n");
}

void error_cb(void *object)
{
    struct reo_session *rs;
    struct bb_message_channel_top *bbmct;
    struct doorbell *db;
    
    db = (struct doorbell*)object;
    bbmct = db->bbmct;
    rs = container_of(bbmct, struct reo_session, bbmct);

    fprintf(stderr, "got an error, investigate manually: %ld\n", rs->error);
}

void get_audio_frame_cb(void *object)
{
    ssize_t len;
    struct doorbell *db;

    db = (struct doorbell*)object;
    memset(db->bbmct->bbmc.buf_write, 0x00, BUFSIZE);
    db->bbmct->bbmc.len_write = get_audio_frame(db->avd, 
        db->bbmct->bbmc.buf_write, 516);
}

void login_success_cb(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;

    //And here it becomes a bit tricky, we have a thread audio_test
    //that is not doing anything yet. We want to call a function inside the 
    //thread (start_audio). The only way that is possible is by using 
    //iv_event_raw_post. 
    fprintf(stderr, "Sending audio\n");

    if (audio_file != NULL)
        iv_event_raw_post(&(db->avd->start_audio_ev));
}

void init_success_cb(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;

    fprintf(stderr, "Initialized everything successfully\n");
    iv_event_raw_post(&(db->bbmct->login_ev));
}

void disconnect_cb(void *object)
{
    fprintf(stderr, "Got disconnected\n");
}

void motion_detect_stop_cb(void *object)
{
    fprintf(stderr, "Object movement stopped\n");
}

void motion_detect_start_cb(void *object)
{
    fprintf(stderr, "Detected object movement\n");
}

void doorbell_press_cb(void *object)
{
    fprintf(stderr, "Somebody pressed the doorbell\n");
}

void pir_alarm_cb(void *object)
{
    fprintf(stderr, "PIR alarm, somebody is at your door\n");
}

void audio_ready_cb(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;

    iv_event_raw_post(&(db->bbmct->talk_ev));
}

void start_audio_thread(void *object)
{
    struct doorbell *db;
    
    db = (struct doorbell*)object;
    
    iv_init();
    IV_EVENT_RAW_INIT(&(db->avd->start_audio_ev));

    db->avd->start_audio_ev.cookie = db;
    db->avd->start_audio_ev.handler = start_audio;
    
    iv_event_raw_register(&(db->avd->start_audio_ev));
    iv_main();
}

void start_reo_thread(void *object)
{
    struct doorbell *db;

    db = (struct doorbell *)object;
    bbmc = (struct bb_message_channel*)(db->bbmct);    

    iv_init();
    IV_EVENT_RAW_INIT(&(db->bbmct->talk_ev));
    IV_EVENT_RAW_INIT(&(db->bbmct->login_ev));
    
    db->bbmct->talk_ev.cookie = bbmc->bbmc_down;
    db->bbmct->talk_ev.handler = reo_talk;
    db->bbmct->login_ev.cookie = bbmc->bbmc_down;
    db->bbmct->login_ev.handler = reo_login;

    iv_event_raw_register(&(db->bbmct->talk_ev));
    iv_event_raw_register(&(db->bbmct->login_ev));

    reo_init(bbmc->bbmc_down);
    
    iv_main();
}

int main(int argc, char *argv[])
{
    int opt;
    int n_doors;
    char *config_file;
    struct doorbell *db;

    bb_ret ret;

    wait_and_listen = 0;
    config_file = audio_file = NULL;

    while ((opt = getopt(argc, argv, "c:wra:")) != -1)
    {
        switch (opt)
        {
            case 'c':
                config_file = optarg;
                break;
            case 'a':
                audio_file = optarg;
                break;
            case 'w':
                wait_and_listen = 1;
                break;
            default:
                print_banner();
                return EXIT_FAILURE;
        }
    }
    
    if (((wait_and_listen == 0 && audio_file == NULL)) ||
        (wait_and_listen == 1 && audio_file != NULL))
    {
        fprintf(stderr, "Please use either [wait and listen] or <send audio" \
            " file>\n");
        return EXIT_FAILURE;
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

    if (audio_file != NULL)
    {
        if ((db->avd = (struct av_data*)malloc(sizeof(struct av_data))) == NULL)
        {
            fprintf(stderr, "No more memory\n");
            return EXIT_FAILURE;
        }
    
        av_init(db->avd, SOURCE_FILE, DEST_BUFFER);
        av_set_input(db->avd, audio_file);
        av_set_audio_filter(db->avd, 16000, 1);
        av_set_adpcm(db->avd, 516, "dvi");
        av_set_sink_caps(db->avd, 16000, 1, "dvi", 516);
    }
    //setup functions and such
    iv_init();
 
    IV_EVENT_RAW_INIT(&(db->bbmct->error_ev));
    IV_EVENT_RAW_INIT(&(db->bbmct->login_success_ev));
    IV_EVENT_RAW_INIT(&(db->bbmct->init_success_ev));
    IV_EVENT_RAW_INIT(&(db->bbmct->disconnect_ev));
    IV_EVENT_RAW_INIT(&(db->bbmct->motion_detect_stop_ev));
    IV_EVENT_RAW_INIT(&(db->bbmct->motion_detect_start_ev));
    IV_EVENT_RAW_INIT(&(db->bbmct->doorbell_press_ev));
    IV_EVENT_RAW_INIT(&(db->bbmct->pir_alarm_ev));
    IV_EVENT_RAW_INIT(&(db->bbmct->talk_init_success_ev));
    IV_EVENT_RAW_INIT(&(db->bbmct->get_audio_frame_ev));

    db->bbmct->get_audio_frame_ev.cookie = db;
    db->bbmct->error_ev.cookie = db;
    db->bbmct->login_success_ev.cookie = db;
    db->bbmct->init_success_ev.cookie = db;
    db->bbmct->disconnect_ev.cookie = db;
    db->bbmct->motion_detect_start_ev.cookie = db;
    db->bbmct->motion_detect_stop_ev.cookie = db;
    db->bbmct->doorbell_press_ev.cookie = db;
    db->bbmct->pir_alarm_ev.cookie = db;
    db->bbmct->talk_init_success_ev.cookie = db;
    
    db->bbmct->get_audio_frame_ev.handler = get_audio_frame_cb;
    db->bbmct->error_ev.handler = error_cb;
    db->bbmct->login_success_ev.handler = login_success_cb;
    db->bbmct->init_success_ev.handler = init_success_cb;
    db->bbmct->disconnect_ev.handler = disconnect_cb;
    db->bbmct->motion_detect_stop_ev.handler = motion_detect_stop_cb;
    db->bbmct->motion_detect_start_ev.handler = motion_detect_start_cb;
    db->bbmct->doorbell_press_ev.handler = doorbell_press_cb;
    db->bbmct->pir_alarm_ev.handler = pir_alarm_cb;
    
    iv_event_raw_register(&(db->bbmct->get_audio_frame_ev));
    iv_event_raw_register(&(db->bbmct->error_ev));
    iv_event_raw_register(&(db->bbmct->login_success_ev));
    iv_event_raw_register(&(db->bbmct->init_success_ev));
    iv_event_raw_register(&(db->bbmct->disconnect_ev));
    iv_event_raw_register(&(db->bbmct->motion_detect_stop_ev));
    iv_event_raw_register(&(db->bbmct->motion_detect_start_ev));
    iv_event_raw_register(&(db->bbmct->doorbell_press_ev));
    iv_event_raw_register(&(db->bbmct->pir_alarm_ev));
    iv_event_raw_register(&(db->bbmct->talk_init_success_ev));

    IV_EVENT_RAW_INIT(&(db->avd->audio_ready_ev));
    
    db->avd->audio_ready_ev.cookie = db;
    db->avd->audio_ready_ev.handler = audio_ready_cb;    
    
    iv_event_raw_register(&(db->avd->audio_ready_ev));
   
    iv_thread_create("reo_protocol", start_reo_thread, (void*)db);
    
    if (audio_file != NULL)
        iv_thread_create("audio_test", start_audio_thread, (void*)db);

    iv_main();
    return EXIT_SUCCESS;
}
