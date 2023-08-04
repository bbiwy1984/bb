#include <iv.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <iv_thread.h>

#include <bb_wire.h>
#include <bb_config.h>

static void print_banner()
{
    fprintf(stderr, "Usage: ./test_wire -c config file -m [send message]\n");
}

void error_cb(void *object)
{
    struct doorbell *db;
    
    db = (struct doorbell*)object;

    fprintf(stderr, "Got error: 0x%lx\n", db->ws->error); 
}

void wire_sent_success(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;
    
    //we are going to clean everything up from here
    iv_event_raw_post(&(db->ws->wire_deinit_ev));
}

void wire_init_success(void *object)
{
    struct doorbell *db;
    
    db = (struct doorbell*)object;

    iv_event_raw_post(&(db->ws->wire_send_msg_ev));
}

void wire_deinit_success(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;

    iv_event_raw_unregister(&(db->ws->bbmct.wire_init_success_ev));
    iv_event_raw_unregister(&(db->ws->bbmct.wire_sent_success_ev));
    iv_event_raw_unregister(&(db->ws->bbmct.wire_deinit_success_ev));
    iv_event_raw_unregister(&(db->ws->bbmct.error_ev));
}

void start_wire_thread(void *object)
{
    struct doorbell *db;

    db = (struct doorbell*)object;

    iv_init();
    IV_EVENT_RAW_INIT(&(db->ws->wire_init_ev));
    IV_EVENT_RAW_INIT(&(db->ws->wire_deinit_ev));
    IV_EVENT_RAW_INIT(&(db->ws->wire_send_msg_ev));

    db->ws->wire_init_ev.cookie = db->ws;
    db->ws->wire_deinit_ev.cookie = db->ws;
    db->ws->wire_init_ev.handler = wire_init; 
    db->ws->wire_deinit_ev.handler = wire_deinit; 
    db->ws->wire_send_msg_ev.cookie = db->ws;
    db->ws->wire_send_msg_ev.handler = wire_send_msg; 

    iv_event_raw_register(&(db->ws->wire_init_ev));
    iv_event_raw_register(&(db->ws->wire_deinit_ev));
    iv_event_raw_register(&(db->ws->wire_send_msg_ev));

    wire_init(db->ws);   

    //cleaning up
    iv_deinit();
}

int main(int argc, char *argv[])
{
    int opt;
    int n_doors;
    char *message;
    char *config_file;
    struct doorbell *db;

    bb_ret ret;
    
    message = NULL;

    while ((opt = getopt(argc, argv, "c:m:")) != -1)
    {
        switch (opt)
        {
            case 'c':
                config_file = optarg;
                break;
            case 'm':
                message = optarg;
                break;
            default:
                print_banner();
                return EXIT_FAILURE;
        }
    }

    if (message == NULL || config_file == NULL)
    {
        fprintf(stderr, "you need to specify a message and a config file\n");
        print_banner();
        return EXIT_FAILURE;
    }

    //we only use the first doorbell, we do not test all of them at once
    //who does that anyway?
    if ((ret = conf_parse(config_file, &n_doors, &db)) != ALL_GOOD)
    {
        fprintf(stderr, "Error parsing configuration: %ld\n", ret);
        return EXIT_FAILURE;
    }

    strncpy(db->ws->bbmct.bbmc.buf_write, message, 
        sizeof(db->ws->bbmct.bbmc.buf_write));

    db->ws->bbmct.bbmc.len_write = strlen(message);

    iv_init();

    IV_EVENT_RAW_INIT(&(db->ws->bbmct.error_ev));
    IV_EVENT_RAW_INIT(&(db->ws->bbmct.wire_init_success_ev));
    IV_EVENT_RAW_INIT(&(db->ws->bbmct.wire_sent_success_ev));
    IV_EVENT_RAW_INIT(&(db->ws->bbmct.wire_deinit_success_ev));
    
    db->ws->bbmct.wire_init_success_ev.cookie = db;
    db->ws->bbmct.wire_deinit_success_ev.cookie = db;
    db->ws->bbmct.wire_init_success_ev.handler = wire_init_success;
    db->ws->bbmct.wire_deinit_success_ev.handler = wire_deinit_success;
    db->ws->bbmct.wire_sent_success_ev.cookie = db;
    db->ws->bbmct.wire_sent_success_ev.handler = wire_sent_success;
    db->ws->bbmct.error_ev.cookie = db;
    db->ws->bbmct.error_ev.handler = error_cb;
   
    iv_event_raw_register(&(db->ws->bbmct.error_ev));
    iv_event_raw_register(&(db->ws->bbmct.wire_init_success_ev));
    iv_event_raw_register(&(db->ws->bbmct.wire_sent_success_ev));
    iv_event_raw_register(&(db->ws->bbmct.wire_deinit_success_ev));

    iv_thread_create("wire_protocol", start_wire_thread, (void*)db);
    iv_main();
    iv_deinit();
}
