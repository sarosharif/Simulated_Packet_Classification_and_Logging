#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include "uthash.h"


#define NUM_PACKETS 100000
#define NUM_FLOWS 50000
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0



// PCAP file format structures
typedef struct {
    uint32_t magic_number;    // Magic number
    uint16_t version_major;   // Major version number
    uint16_t version_minor;   // Minor version number
    int32_t  thiszone;        // GMT to local correction
    uint32_t sigfigs;         // Accuracy of timestamps
    uint32_t snaplen;         // Max length of captured packets
    uint32_t network;         // Data link type
} pcap_global_header_t;

typedef struct {
    uint32_t ts_sec;          // Timestamp seconds
    uint32_t ts_usec;         // Timestamp microseconds
    uint32_t incl_len;        // Number of octets of packet saved in file
    uint32_t orig_len;        // Actual length of packet
} pcap_packet_header_t;

// Structure to represent a packet
typedef struct {
    char src_ip[16];
    uint16_t src_port;
    char dst_ip[16];
    uint16_t dst_port;
    char protocol[4];
    char payload[65535];
} Packet;

typedef struct {
    char src_ip[16];
    uint16_t src_port;
    char dst_ip[16];
    uint16_t dst_port;
    char protocol[4];
} FlowKey;

typedef struct {
    FlowKey key;         // Key for the hash table
    uint64_t app_id;
    uint8_t classification_state;
    UT_hash_handle hh;   // Makes this structure hashable
} FlowMapEntry;
FlowMapEntry *flow_map = NULL; // Hash table

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


// Modify the flow lookup and insertion logic
int extract_packets_from_mmap(const char *filename, Packet *packets, FlowKey *flows, int *flow_to_packet_map, int max_packets, int max_flows) {
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

    pcap_global_header_t *global_header = (pcap_global_header_t *)file_data;
    if (global_header->magic_number != 0xa1b2c3d4 && global_header->magic_number != 0xd4c3b2a1) {
        fprintf(stderr, "Invalid PCAP file\n");
        munmap(file_data, file_size);
        close(fd);
        return -1;
    }

    uint8_t *current = (uint8_t *)file_data + sizeof(pcap_global_header_t);
    uint8_t *end = (uint8_t *)file_data + file_size;
    int packet_count = 0;
    int flow_count = 0;

    while (current < end && packet_count < max_packets) {
        pcap_packet_header_t *packet_header = (pcap_packet_header_t *)current;
        current += sizeof(pcap_packet_header_t);

        if (current + packet_header->incl_len > end) {
            fprintf(stderr, "Corrupted packet or file\n");
            break;
        }

        const uint8_t *data = current;
        current += packet_header->incl_len;

        if (packet_header->incl_len < 34) continue;

        Packet *pkt = &packets[packet_count];
        sprintf(pkt->src_ip, "%u.%u.%u.%u", data[26], data[27], data[28], data[29]);
        sprintf(pkt->dst_ip, "%u.%u.%u.%u", data[30], data[31], data[32], data[33]);
        pkt->src_port = (data[34] << 8) | data[35];
        pkt->dst_port = (data[36] << 8) | data[37];
        strncpy(pkt->protocol, (data[23] == 6) ? "TCP" : (data[23] == 17) ? "UDP" : "UNK", 3);
        pkt->protocol[3] = '\0';

        size_t payload_len = packet_header->incl_len > 54 ? packet_header->incl_len - 54 : 0;
        strncpy(pkt->payload, (const char *)(data + 54), payload_len);
        pkt->payload[payload_len] = '\0';

        // Create a flow key
        FlowKey key;
        FlowKey rev_key;

        generate_flow_key(pkt, &key);

        // Check if the flow exists in the hash map
        FlowMapEntry *entry;
        HASH_FIND(hh, flow_map, &key, sizeof(FlowKey), entry);
        if (entry == NULL)
        {
            // Check if the flow exists in the hash map but rev direction
            generate_flow_key_rev(pkt, &rev_key);
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
            HASH_ADD(hh, flow_map, key, sizeof(FlowKey), entry);

            flow_count++;
        } 
        
        packet_count++;
    }



    munmap(file_data, file_size);
    close(fd);
    return packet_count;
}

// Function to process packets
void process_packets(Packet *packets, size_t num_packets, int *flow_to_packet_map) {
    printf("here\n");
    for (size_t i = 0; i < num_packets; i++) {
        // Find the flow entry in the hash map using the flow index
        FlowKey key;
        Packet *pkt = &packets[i];

        generate_flow_key(pkt, &key);
        // Check if the flow exists in the hash map
        FlowMapEntry *entry;
        
        HASH_FIND(hh, flow_map, &key, sizeof(FlowKey), entry);

        if (entry != NULL) {
            // If the flow exists, print the packet details along with the flow information
            printf("  Source: %s:%u\n", packets[i].src_ip, packets[i].src_port);
            printf("  Destination: %s:%u\n", packets[i].dst_ip, packets[i].dst_port);
            printf("  Payload: %s\n", packets[i].payload);
            printf("  Flow Source: %s:%u\n", entry->key.src_ip, entry->key.src_port);
            printf("  Flow Destination: %s:%u\n", entry->key.dst_ip, entry->key.dst_port);
            printf("  Flow Protocol: %s\n\n", entry->key.protocol);
        }
    }
}

// Function to identify binary
void identify_binary(const char *prog_name) {
    if (strstr(prog_name, "b1")) {
        printf("Running binary: b1\n");
    } else if (strstr(prog_name, "b2")) {
        printf("Running binary: b2\n");
    } else if (strstr(prog_name, "b3")) {
        printf("Running binary: b3\n");
    } else {
        printf("Running binary: Unknown\n");
    }
}

int main(int argc, char *argv[]) {
    identify_binary(argv[0]);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Read packets from a memory-mapped pcap file
    Packet *packets = malloc(NUM_PACKETS * sizeof(Packet));
    if (!packets) {
        perror("Failed to allocate memory for packets");
        return EXIT_FAILURE;
    }

    // Allocate memory for flow data structures
    FlowKey *flows = malloc(NUM_FLOWS * sizeof(FlowKey));
    if (!flows) {
        perror("Failed to allocate memory for flows");
        free(packets);
        return EXIT_FAILURE;
    }

    int *flow_to_packet_map = malloc(NUM_PACKETS * sizeof(int));
    if (!flow_to_packet_map) {
        perror("Failed to allocate memory for flow-to-packet map");
        free(packets);
        free(flows);
        return EXIT_FAILURE;
    }

    // Call extract_packets_from_mmap with the correct arguments
    int num_packets = extract_packets_from_mmap(argv[1], packets, flows, flow_to_packet_map, NUM_PACKETS, NUM_FLOWS);
    if (num_packets < 0) {
        free(packets);
        free(flows);
        free(flow_to_packet_map);
        return EXIT_FAILURE;
    }

    printf("Extracted %d packets from pcap file.\n", num_packets);
    process_packets(packets, num_packets,flow_to_packet_map);

    // Clean up allocated memory
    free(packets);
    free(flows);
    free(flow_to_packet_map);

    return EXIT_SUCCESS;
}
