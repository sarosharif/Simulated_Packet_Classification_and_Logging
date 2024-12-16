
#include "classifier.h"
#include "pkt_gen.h"

FlowMapEntry *flow_map = NULL; // Hash table
const char *prog_name;

static void *context = NULL;
static void *socket = NULL;

// Function to generate a unique flow key
void generate_flow_key(Packet *pkt, FlowKey *key) {
    strcpy(key->src_ip, pkt->src_ip);
    key->src_port = pkt->src_port;
    strcpy(key->dst_ip, pkt->dst_ip);
    key->dst_port = pkt->dst_port;
    strcpy(key->protocol, pkt->protocol);
}
// Function to generate a unique flow key
void generate_flow_key_rev(Packet *pkt, FlowKey *key) {
    strcpy(key->dst_ip, pkt->src_ip);
    key->dst_port = pkt->src_port;
    strcpy(key->src_ip, pkt->dst_ip);
    key->src_port = pkt->dst_port;
    strcpy(key->protocol, pkt->protocol);
}


void zeroMQ_init()
{
    // Create ZeroMQ context
    context = zmq_ctx_new();
    if (context == NULL) {
        perror("Failed to create ZeroMQ context");
        return;
    }

    // Create ZeroMQ socket
    socket = zmq_socket(context, ZMQ_PUSH);
    if (socket == NULL) {
        perror("Failed to create ZeroMQ socket");
        zmq_ctx_destroy(context); 
        return;
    }

    // Connect to the collector
    if (zmq_connect(socket, "tcp://127.0.0.1:5555") != 0) {
        perror("Failed to connect ZeroMQ socket");
        zmq_close(socket);
        zmq_ctx_destroy(context); 
        return;
    }

    printf("ZeroMQ initialized successfully.\n");
}

void send_payload_with_zero_copy(const char *payload, size_t payload_len)
{
    if (socket == NULL) {
        perror("ZeroMQ socket is not initialized");
        return;
    }

    zmq_msg_t msg;
    // Initialize the ZeroMQ message
    if (zmq_msg_init_data(&msg, (void *)payload, payload_len, NULL, NULL) != 0) {
        perror("Failed to initialize ZeroMQ message");
        return;
    }

    // Send the message to the other process
    int rc = zmq_msg_send(&msg, socket, 0);
    if (rc == -1) {
        perror("Failed to send ZeroMQ message");
    } else {
        printf("Message sent successfully: %zu bytes\n", payload_len);
    }

    // No need to free msg, ZeroMQ will handle it
    zmq_msg_close(&msg);
}

void format_and_send_msg_hdr(Packet *pkt, FlowMapEntry *entry, size_t payload_len) {

    // Calculate the size of the formatted message
    size_t msg_len = snprintf(NULL, 0,
        "Details: %s|%s|%s|%u|%u|%s|%zu", // Using '|' as delimiter
        prog_name, pkt->src_ip, pkt->dst_ip, pkt->src_port, pkt->dst_port,
        entry->app_common_name ? entry->app_common_name : "Unclassified",
        payload_len
    );

    // Allocate memory for the message, including space for the null-terminator
    char *msg = (char *)malloc(msg_len + 1);
    if (msg == NULL) {
        perror("Failed to allocate memory for message");
        return;
    }

    // Format the message into the allocated memory
    snprintf(msg, msg_len + 1,
        "Details: %s|%s|%s|%u|%u|%s|%zu", // Using '|' as delimiter
        prog_name, pkt->src_ip, pkt->dst_ip, pkt->src_port, pkt->dst_port,
        entry->app_common_name ? entry->app_common_name : "Unclassified",
        payload_len
    );

    // Send the message using the zero-copy function
    send_payload_with_zero_copy(msg, msg_len);

    // Free the allocated memory after sending
    free(msg);
}

// Modify the flow lookup and insertion logic
int extract_and_process_packets_from_mmap(const char *filename, FlowKey *flows,
                                            int max_packets, int max_flows) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open pcap file");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("Failed to get file stats");
        close(fd);
        return -1;
    }

    size_t file_size = st.st_size;
    void *file_data = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_data == MAP_FAILED) {
        perror("Failed to mmap file");
        close(fd);
        return -1;
    }

    PcapGlobalHeader *global_header = (PcapGlobalHeader *)file_data;
    if (global_header->magic_number != 0xa1b2c3d4 && global_header->magic_number != 0xd4c3b2a1) {
        fprintf(stderr, "Invalid PCAP file\n");
        munmap(file_data, file_size);
        close(fd);
        return -1;
    }

    uint8_t *current = (uint8_t *)file_data + sizeof(PcapGlobalHeader);
    uint8_t *end = (uint8_t *)file_data + file_size;
    int packet_count = 0;
    int flow_count = 0;

    while (current < end) {
        PcapPacketHeader *packet_header = (PcapPacketHeader *)current;
        current += sizeof(PcapPacketHeader);

        if (current + packet_header->incl_len > end) {
            fprintf(stderr, "Corrupted packet or file\n");
            break;
        }

        const uint8_t *data = current;
        current += packet_header->incl_len;

        if (packet_header->incl_len < 34) continue;

        Packet *pkt = malloc(sizeof(Packet)); // this does not contain actual pkt, it contains metadata
        //copying header but not payload
        sprintf(pkt->src_ip, "%u.%u.%u.%u", data[26], data[27], data[28], data[29]);
        sprintf(pkt->dst_ip, "%u.%u.%u.%u", data[30], data[31], data[32], data[33]);
        pkt->src_port = (data[34] << 8) | data[35];
        pkt->dst_port = (data[36] << 8) | data[37];
        strncpy(pkt->protocol, (data[23] == 6) ? "TCP" : (data[23] == 17) ? "UDP" : "UNK", 3);
        pkt->protocol[3] = '\0';

        size_t payload_len = packet_header->incl_len > 54 ? packet_header->incl_len - 54 : 0;
        pkt->payload = (char *)(data + 54);
        // Create a flow key
        FlowKey key;
        FlowKey rev_key;

        generate_flow_key(pkt, &key);
        generate_flow_key_rev(pkt, &rev_key);

        // Check if the flow exists in the hash map
        FlowMapEntry *entry;

        HASH_FIND(hh, flow_map, &key, sizeof(FlowKey), entry);
        if (entry == NULL)
        {
            // Check if the flow exists in the hash map but rev direction
            HASH_FIND(hh, flow_map, &rev_key, sizeof(FlowKey), entry);
        }
        if (entry == NULL) {
            // Add a new flow if not found
            if (flow_count >= max_flows) {
                fprintf(stderr, "Maximum number of flows reached\n");
                break;
            }

            FlowKey *flow = &flows[flow_count];
            generate_flow_key(pkt,flow);

            // Add to hash map
            entry = (FlowMapEntry *)malloc(sizeof(FlowMapEntry));
            entry->key = key;
            entry->is_classified=0;//unclassified 
            entry->num_pkt_sent_for_classification=0;
            entry->app_common_name=NULL;
            HASH_ADD(hh, flow_map, key, sizeof(FlowKey), entry);

            flow_count++;
        } 
        if (entry->is_classified==0)
        {
            entry->num_pkt_sent_for_classification++;
            entry->app_common_name = find_app_name_in_payload(pkt->payload,payload_len);
            if (entry->app_common_name != NULL)
            {
                entry->is_classified = 1;
            }
            else if (entry->num_pkt_sent_for_classification > 10)
            {
                entry->app_common_name = "Unknown"; // unable to classify in first 10 pkts, no need to check the rest
                entry->is_classified = 1;
            }

        } 
       
        if (pkt->payload)
        {
            format_and_send_msg_hdr(pkt,entry, payload_len);
            send_payload_with_zero_copy(pkt->payload, payload_len);
        }
        packet_count++;
        free(pkt);
    }


    // ideally we should do this however this causes a conflict, the file is unmapped before all the pkts are sent resulting in segfault
    // munmap(file_data, file_size);
    // close(fd); 
    return packet_count;
}




int main(int argc, char *argv[]) {
    // identifier (b1,b2,b3)
    const char *filename = "domain_to_app.ini";

    prog_name = argv[0];

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return EXIT_FAILURE;
    }
    parse_ini_file(filename);

    // Allocate memory for flow data structures
    FlowKey *flows = malloc(NUM_FLOWS * sizeof(FlowKey));
    if (!flows) {
        perror("Failed to allocate memory for flows");
        return EXIT_FAILURE;
    }

    // initialize zero mq
    zeroMQ_init();

    int num_packets = extract_and_process_packets_from_mmap(argv[1], flows,
                                                            NUM_PACKETS, NUM_FLOWS);
    if (num_packets < 0) {
        free(flows);
        return EXIT_FAILURE;
    }

    printf("Extracted %d packets from pcap file.\n", num_packets);

    // Clean up allocated memory
    free(flows);
    // need to free hashmap, haven't done that yet

    return EXIT_SUCCESS;
}
