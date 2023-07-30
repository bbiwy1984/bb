#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include <bb_errors.h>
#include <bb_usb_relay.h>

#define DIE(x) {fprintf(stderr, "Got ret value: %ld\n",x); exit(EXIT_FAILURE);}

int main(int argc, char **argv)
{
    bb_ret ret;
    if ((ret = print_all_relays()) != ALL_GOOD)
        DIE(ret);
   
    return EXIT_SUCCESS;
}
