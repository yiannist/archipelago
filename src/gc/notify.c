#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "notify.h"
#include "sender.h"

char* ref_change2str(ref_change change) {
    char *buf;

    switch(change) {
        case REF_INC:
            buf = "+1";
            break;
        case REF_PLUS2:
            buf = "+2";
            break;
        case REF_DEC:
            buf = "-1";
            break;
        case REF_MINUS2:
            buf = "-2";
            break;
    }

    return buf;
}

// XXX: Maybe this abstraction is too much
int init_gc(sender_state_t *state, char *gc_queue) {

    init_state(state, gc_queue);

    return 0;
}

int notify_gc(sender_state_t state, char *obj_name, ref_change change) {
    char *buf = calloc(256, sizeof(char)); // TODO: Fix hardcoded size
    char *ref_change_str;
    message_t message;

    strlcpy(buf, obj_name, 256);
    ref_change_str = ref_change2str(change);
    strlcat(buf, ref_change_str, 256);

    prepare_message(&message, buf, strlen(buf));
    send_message(state, message);

    return 0;
}
