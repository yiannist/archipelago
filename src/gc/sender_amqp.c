#include <stdlib.h>
#include <amqp.h>
#include <amqp_framing.h>
#include <amqp_tcp_socket.h>
#include <lz4.h>
#include <logger.h>

#include "peer.h"
#include "sender.h"
#include "utils.h"

Logger_t *logger;

struct amqp_state {
    amqp_connection_state_t conn;
    amqp_bytes_t queuename;
    LZ4_stream_t* lz4_stream; /* Compression stream */
};

struct amqp_message {
    amqp_bytes_t data;
};

int init_state(sender_state_t *state, char *gc_queue) {
    amqp_connection_state_t conn;
    amqp_socket_t *socket = NULL;
    amqp_bytes_t queuename = amqp_cstring_bytes(gc_queue);
    struct amqp_state *amqp_state;
    int status;

    // Init LOG4CPLUS logger
    logger = logger_new("/etc/archipelago/logging.conf", "log_amqp_sender");
    if (!logger) {
        XSEGLOG2(&lc, E, "Could not initialize Log4cplus logger."
                 "GC logging will not work.\n");
    }

    flogger_info(logger, "Initializing sender's state");

    conn = amqp_new_connection();

    socket = amqp_tcp_socket_new(conn);
    if (!socket) {
        flogger_error(logger, "Creating TCP socket");
        exit(1);
    }

    status = amqp_socket_open(socket, "localhost", 5672);
    if (status) {
        flogger_error(logger, "Opening TCP socket");
        exit(1);
    }

    die_on_amqp_error(amqp_login(conn, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN,
                                 "guest", "guest"), "Logging in");
    amqp_channel_open(conn, 1);
    die_on_amqp_error(amqp_get_rpc_reply(conn), "Opening channel");

    // Declare queue to make sure that it exists
    amqp_queue_declare(conn, 1, queuename, 0, 1 /* Durable */, 0, 0,
                       AMQP_EMPTY_TABLE);
    die_on_amqp_error(amqp_get_rpc_reply(conn), "Declaring archipelago queue");

    // Batch the state
    amqp_state = malloc(sizeof(struct amqp_state));
    amqp_state->conn = conn;
    amqp_state->queuename = queuename;
    amqp_state->lz4_stream = LZ4_createStream();

    *state = (sender_state_t) amqp_state;

    return 0;
}

int prepare_message(sender_state_t state, message_t *message, char *buffer,
                    size_t len) {
    struct amqp_state *amqp_state = (struct amqp_state*) state;
    LZ4_stream_t *const lz4_stream = amqp_state->lz4_stream;
    struct amqp_message *amqp_message = malloc(sizeof(struct amqp_message));
    char *compression_buf = malloc(LZ4_COMPRESSBOUND(COMPR_BUF_SIZE));
    int compressed_bytes;

    flogger_info(logger, "Preparing message: '%s' for sending", buffer);

    // Compress buffer and create a message_t message
    compressed_bytes = LZ4_compress_continue(lz4_stream, buffer,
                                             compression_buf, len);

    amqp_message->data.bytes = compression_buf;
    amqp_message->data.len = compressed_bytes;

    *message = (message_t) amqp_message;

    return 0;
}

int send_message(sender_state_t state, message_t message) {
    struct amqp_state *amqp_state = (struct amqp_state*) state;
    amqp_connection_state_t conn = amqp_state->conn;
    amqp_bytes_t queuename = amqp_state->queuename;
    struct amqp_message *amqp_message = (struct amqp_message*) message;
    amqp_bytes_t data = amqp_message->data;
    amqp_basic_properties_t props;

    props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
    props.content_type = amqp_cstring_bytes("lz4");
    props.delivery_mode = 2; // persistent delivery mode

    flogger_info(logger, "Sending message to AMQP queue");

    die_on_error(amqp_basic_publish(conn, 1, amqp_cstring_bytes(""), queuename,
                                    0, 0, &props, data),
                 "Publishing");

    return 0;
}

// XXX: Not used yet
int finalize(sender_state_t state) {
    struct amqp_state *amqp_state = (struct amqp_state*) state;
    amqp_connection_state_t conn = amqp_state->conn;

    // Close AMQP channel and connection
    die_on_amqp_error(amqp_channel_close(conn, 1, AMQP_REPLY_SUCCESS),
                      "Closing channel");
    die_on_amqp_error(amqp_connection_close(conn, AMQP_REPLY_SUCCESS),
                      "Closing connection");
    die_on_error(amqp_destroy_connection(conn), "Ending connection");

    // Free the LZ4 compression stream
    LZ4_freeStream(amqp_state->lz4_stream);

    return 0;
}
