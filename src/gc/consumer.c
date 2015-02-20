#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <amqp.h>
#include <amqp_framing.h>
#include <lz4.h>

#include "utils.h"

int main(int argc, char const *const *argv)
{
    int status;
    amqp_connection_state_t conn;
    amqp_bytes_t queuename;
    amqp_socket_t *socket = NULL;
    LZ4_streamDecode_t* const lz4_stream_decode = LZ4_createStreamDecode();

    if (argc < 2) {
        printf("Usage: ./consumer <queuename>\n");
        exit(1);
    }

    queuename = amqp_cstring_bytes(argv[1]);

    // AMQP stuff
    conn = amqp_new_connection();

    socket = amqp_tcp_socket_new(conn);
    if (!socket) {
        die("Creating TCP socket");
    }

    status = amqp_socket_open(socket, "localhost", 5672);
    if (status) {
        die("Opening socket");
    }

    die_on_amqp_error(amqp_login(conn, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN,
                                 "guest", "guest"),
                      "Loggin in");
    amqp_channel_open(conn, 1);
    die_on_amqp_error(amqp_get_rpc_reply(conn), "Opening channel");

    amqp_queue_declare(conn,
                       1,
                       queuename,
                       0,
                       1, // durable
                       0,
                       0,
                       amqp_empty_table);
    die_on_amqp_error(amqp_get_rpc_reply(conn), "Declaring queue");

    amqp_basic_consume(conn,
                       1,
                       queuename,
                       amqp_empty_bytes,
                       0,
                       1,
                       0,
                       amqp_empty_table);
    die_on_amqp_error(amqp_get_rpc_reply(conn), "Consuming");

    printf(" [*] Waiting for messages. To exit press CTRL+C\n");

    while (1) {
        char *cmpBuf;
        int cmpBytes, message_bytes, is_compressed;
        amqp_rpc_reply_t res;
        amqp_envelope_t envelope;
        char *message;

        amqp_maybe_release_buffers(conn);
        res = amqp_consume_message(conn, &envelope, NULL, 0);
        if (AMQP_RESPONSE_NORMAL != res.reply_type) {
            break;
        }

        cmpBuf = (char *) envelope.message.body.bytes;
        cmpBytes = (int) envelope.message.body.len;
        printf(" --> Received raw data: ");
        print_hex_buffer(cmpBuf, cmpBytes);
        printf(" with size %d\n", cmpBytes);

        if (envelope.message.properties._flags & AMQP_BASIC_CONTENT_TYPE_FLAG) {
            is_compressed =
                !strcmp("lz4", envelope.message.properties.content_type.bytes);
            if (is_compressed) {
                printf(" --> Data is LZ4-compressed. Trying to uncompress"
                       "...\n");
                message = malloc(LZ4_COMPRESSBOUND(100));
                message_bytes = LZ4_decompress_safe_continue(lz4_stream_decode,
                                                             cmpBuf, message,
                                                             cmpBytes, 100);
            } else {
                message_bytes = cmpBytes;
                message = cmpBuf;
            }
        }
        printf(" [x] Received '%s' with size %d\n", message, message_bytes);

        if (is_compressed) {
            free(message);
        }
        amqp_destroy_envelope(&envelope);
    }

    die_on_amqp_error(amqp_channel_close(conn, 1, AMQP_REPLY_SUCCESS),
                      "Closing channel");
    die_on_amqp_error(amqp_connection_close(conn, AMQP_REPLY_SUCCESS),
                      "Closing connection");
    die_on_error(amqp_destroy_connection(conn), "Ending connection");

    LZ4_freeStreamDecode(lz4_stream_decode);

    return 0;
}
