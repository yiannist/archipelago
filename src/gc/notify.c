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

int notify_gc(char *obj_name, ref_change change) {
    char *buf = (char *) malloc(100); //TODO: Fix hardcoded size
    char *ref_change_str;
    sender_state_t state;
    message_t message;

    strlcpy(buf, obj_name, sizeof(buf));
    ref_change_str = ref_change2str(change);
    strlcat(buf, ref_change_str, 100);

    init_state(&state);
    prepare_message(&message, buf, strlen(buf));
    send_message(state, message);

    return 0;
}
