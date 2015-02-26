#ifndef SENDER_H
#define SENDER_H

#include <stdlib.h>

typedef void* sender_state_t;
typedef void* message_t;

int init_state(sender_state_t *state, char *gc_queue);
int prepare_message(message_t *message, char* buf, size_t len);
int send_message(sender_state_t state, message_t message);

#endif /* SENDER_H */
