#ifndef NOTIFY_H
#define NOTIFY_H

#include "sender.h"

typedef enum {REF_INC, REF_PLUS2, REF_DEC, REF_MINUS2} ref_change;

int init_gc(sender_state_t *state, char *gc_queue);
// TODO: Add proper type for obj.
int notify_gc(sender_state_t state, char *obj, ref_change change);

#endif /* NOTIFY_H */
