#include <zmq.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int receive_and_log_payload_with_zero_copy(void *socket, FILE* log_file) {
    zmq_msg_t msg;

    // Receive the message from the socket
    if (zmq_msg_init(&msg) != 0) {
        perror("Failed to initialize ZeroMQ message");
        return -1;
    }

    int rc = zmq_msg_recv(&msg, socket, 0);
    if (rc == -1) {
        perror("Failed to receive ZeroMQ message");
        zmq_msg_close(&msg);
        return -1;
    }

    // Access the data directly (zero-copy)
    char *received_payload = (char *)zmq_msg_data(&msg);
    size_t received_payload_len = zmq_msg_size(&msg);
    
    // Check if the message starts with "Details: "
    if (received_payload_len >= 9 && strncmp(received_payload, "Details: ", 9) == 0) {
        // If it starts with "Details:", print it as is
        fprintf(log_file, "%.*s\n", (int)received_payload_len, received_payload);
    } else {
        // Otherwise, print with "PAYLOAD: " prefix
        fprintf(log_file,"Payload (hex): ");
        for (size_t i = 0; i < received_payload_len; i++) {
            fprintf(log_file,"%02x ", (unsigned char)received_payload[i]);
            if ((i + 1) % 16 == 0) {
                fprintf(log_file,"\n");
            }
        }
        fprintf(log_file,"\n\n");
        // print payload on terminal aswell
        printf("Payload (hex): ");
        for (size_t i = 0; i < received_payload_len; i++) {
            printf("%02x ", (unsigned char)received_payload[i]);
            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }
        printf("\n\n");
    }


    // Clean up
    zmq_msg_close(&msg);
    return 0;
}

int main() {

    FILE *log_file = fopen("collector.log", "w+");
    if (!log_file) {
        perror("Failed to open log file");
        return -1;
    }
    // Create ZeroMQ context
    void *context = zmq_ctx_new();
    if (!context) {
        perror("Failed to create ZeroMQ context");
        return -1;
    }

    // Create ZeroMQ socket
    void *socket = zmq_socket(context, ZMQ_PULL);
    if (!socket) {
        perror("Failed to create ZeroMQ socket");
        zmq_ctx_destroy(context);
        return -1;
    }

    // Bind to a port to receive results
    int bind_result = zmq_bind(socket, "tcp://127.0.0.1:5555");
    if (bind_result != 0) {
        perror("Failed to bind ZeroMQ socket");
        zmq_close(socket);
        zmq_ctx_destroy(context);
        return -1;
    }

    printf("Socket bound to tcp://127.0.0.1:5555\n");

    while (1) {
        if(receive_and_log_payload_with_zero_copy(socket,log_file) == -1)
        {
            printf("ERROR: unable to recv msg correctly\n");
        }
    }

    // Cleanup
    zmq_close(socket);
    zmq_ctx_destroy(context);
    return 0;
}
