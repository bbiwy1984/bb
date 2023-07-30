#ifndef BB_FSM_H
#define BB_FSM_H

#include <bb_layer.h>
#include <bb_errors.h>

struct state_fp
{
    void (*st_read)(struct bb_message_channel *bbmc);
    void (*st_write)(struct bb_message_channel *bbmc);
};


/*
inline int can_transit_to_next_state(long long int next_st, struct state *st)
{
    if ((next_st & st->next_states) != 0)
        return ALL_GOOD;
    return NEXT_STATE_NOT_ALLOWED;
}
*/

#endif
