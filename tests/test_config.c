#include <stdio.h>

#include <bb_config.h>

int main(int argc, char *argv[])
{
    int n;
    struct doorbell *db;
    bb_ret x = conf_parse(argv[1], &n, &db);
    fprintf(stderr, "got value: %ld\n", x);
    return 0;
}
