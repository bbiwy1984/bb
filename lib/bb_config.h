#ifndef BB_CONFIG_H
#define BB_CONFIG_H

#include <stdint.h>

#include <bb_layer.h>
#include <bb_errors.h>

//other values not supported for now
#define DB_REO_PROTOCOL 0
#define DB_TCP 1

bb_ret conf_parse(char *file, int *n, struct doorbell **db);

#endif
