#include <zmq.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> // For ntohl
#include "uthash.h"

#define MAX_BINARIES 3

// Structure to store details messages for a binary
typedef struct {
    char binary_name[16];  // Binary name (e.g., ./b1)
    char details_msg[256]; // Details message
    size_t payload_length;   
    int is_active;         // Flag to indicate active message
} DetailsEntry;

// Array to hold up to 3 active details entries
DetailsEntry active_details[MAX_BINARIES] = {0};

// File pointers for the log files
FILE *log_files[MAX_BINARIES] = {NULL};

// Initialize log files
void initialize_log_files() {
    log_files[0] = fopen("collector_b1.log", "w+");
    log_files[1] = fopen("collector_b2.log", "w+");
    log_files[2] = fopen("collector_b3.log", "w+");

    if (!log_files[0] || !log_files[1] || !log_files[2]) {
        perror("Failed to open log files");
        exit(EXIT_FAILURE);
    }
}

// Cleanup log files
void cleanup_log_files() {
    for (int i = 0; i < MAX_BINARIES; i++) {
        if (log_files[i]) {
            fclose(log_files[i]);
        }
    }
}

// Function to find the index for a binary name
int get_binary_index(const char *binary_name) {
    if (strcmp(binary_name, "./b1") == 0) return 0;
    if (strcmp(binary_name, "./b2") == 0) return 1;
    if (strcmp(binary_name, "./b3") == 0) return 2;
    return -1; // Invalid binary name
}

// Function to handle received messages
int receive_and_log_payload_with_zero_copy(void *socket) {
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

    if (received_payload_len >= 9 && strncmp(received_payload, "Details: ", 9) == 0) {
        // Parse the "Details" message
        char binary_name[16];
        size_t payload_length;
        sscanf(received_payload + 9, "%15[^|]|%*[^|]|%*[^|]|%*u|%*u|%*[^|]|%zu", 
               binary_name, &payload_length);

        int index = get_binary_index(binary_name);

        if (index == -1) {
            fprintf(stderr, "Unknown binary name: %s\n", binary_name);
        } else {
            // Store the details message
            strncpy(active_details[index].binary_name, binary_name, 16);
            strncpy(active_details[index].details_msg, received_payload, received_payload_len);
            active_details[index].payload_length = payload_length;
            active_details[index].is_active = 1;
        }
    } else if (received_payload_len > 0) {
        // Use the payload length to find the matching details entry
        for (int i = 0; i < MAX_BINARIES; i++) {
            // printf("Debug: active_details[%d].payload_length = %zu, received_payload_len = %zu\n", 
            //        i, active_details[i].payload_length, received_payload_len);

            if (active_details[i].is_active && 
                active_details[i].payload_length == received_payload_len) {
                // Log the details and payload
                fprintf(log_files[i], "%s\n", active_details[i].details_msg);
                fprintf(log_files[i], "Payload (hex): ");
                for (size_t j = 0; j < received_payload_len; j++) {
                    fprintf(log_files[i], "%02x ", (unsigned char)received_payload[j]);
                }
                fprintf(log_files[i], "\n\n");

                // Deactivate the details entry after matching
                active_details[i].is_active = 0;
                break;
            }
        }
    } else {
        fprintf(stderr, "Invalid message received: zero-length payload\n");
    }

    // Clean up the message
    zmq_msg_close(&msg);
    return 0;
}


int main() {

    initialize_log_files();
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
        if(receive_and_log_payload_with_zero_copy(socket) == -1)
        {
            printf("ERROR: unable to recv msg correctly\n");
        }
    }

    // Cleanup
    cleanup_log_files();
    zmq_close(socket);
    zmq_ctx_destroy(context);
    return 0;
}
