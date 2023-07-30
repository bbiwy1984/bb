#ifndef BB_USB_RELAY
#define BB_USB_RELAY

#include <iv.h>
#include <stdint.h>

struct relay
{
    int offset;
    int on_value;
    int off_value;
    int on_time;
    char *device;
    struct iv_timer timer;
};

bb_ret print_all_relays();
bb_ret turn_relay_on(struct relay *rel);
bb_ret turn_relay_off(struct relay *rel);

#endif
