#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <hidapi/hidapi.h>

#include <bb_errors.h>
#include <bb_usb_relay.h>

#define BUFSIZE 4096

bb_ret print_all_relays()
{
    struct hid_device_info *hdi_head, *it;

    hdi_head = it = hid_enumerate(0, 0);

    while (it != NULL)
    {
        char tmp[BUFSIZE];
        wcstombs(tmp, it->serial_number, sizeof(tmp) / 2);
        printf("tmp: %s\n", tmp);

        printf("Product string: %S\n", it->product_string);
        printf("\tPath: %s\n", it->path);
        printf("\tVendor id: %hu\n", it->vendor_id);
        printf("\tProduct id: %hu\n", it->product_id);
        printf("\tSerial number: %ls\n", it->serial_number);
        printf("\tRelease number: %hu\n", it->release_number);
        printf("\tManufacturer: %ls\n", it->manufacturer_string);
        printf("\tUsage page: %hu\n", it->usage_page);
        printf("\tUsage: %hu\n", it->usage);
        printf("\tItnerface number: %d\n", it->interface_number);

        it = it->next;
    }

    hid_free_enumeration(hdi_head);

    return ALL_GOOD;
}

static bb_ret set_relay_board_state(char *path, unsigned char state, 
    unsigned char relay_offset)
{
    uint32_t ret = ALL_GOOD;
    unsigned char buf[9];

    hid_device *handle;

    if ((handle = hid_open_path(path)) == NULL)
    {
        ret = CANNOT_OPEN_USB_RELAY;
        goto out;
    }

    memset(buf, 0x00, sizeof(buf));

    buf[1] = state;
    buf[2] = relay_offset;

    if (hid_write(handle, buf, sizeof(buf)) <= 0)
    {
        ret = CANNOT_WRITE_USB_RELAY;
        goto out;
    }

out:
    hid_close(handle);

    return ret;
}

bb_ret turn_relay_on(struct relay *rel)
{
    return set_relay_board_state(rel->device, rel->on_value, rel->offset);
}

bb_ret turn_relay_off(struct relay *rel)
{
    return set_relay_board_state(rel->device, rel->off_value, rel->offset);
}


