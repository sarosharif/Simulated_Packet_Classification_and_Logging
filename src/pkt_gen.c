
#include "classifier.h"
#include "pkt_gen.h"

FlowMapEntry *flow_map = NULL; // Hash table
const char *prog_name;

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
int extract_and_process_packets_from_mmap(const char *filename, Packet *packets, FlowKey *flows, int *flow_to_packet_map, int max_packets, int max_flows) {
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

    while (current < end && packet_count < max_packets) {
        PcapPacketHeader *packet_header = (PcapPacketHeader *)current;
        current += sizeof(PcapPacketHeader);

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
            entry->is_classified=0;//unclassified 
            entry->num_pkt_sent_for_classification=0;
            entry->app_common_name=NULL;
            HASH_ADD(hh, flow_map, key, sizeof(FlowKey), entry);

            flow_count++;
        } 
        if (entry->is_classified==0)
        {
            entry->num_pkt_sent_for_classification++;
            entry->app_common_name = find_app_name_in_payload(pkt->payload);
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
        packet_count++;
    }



    munmap(file_data, file_size);
    close(fd);
    return packet_count;
}




int main(int argc, char *argv[]) {
    // identifier (b1,b2,b3)
    prog_name = argv[0];

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    const char *filename = "domain_to_app.ini";
    parse_ini_file(filename);


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

    // Call extract_and_process_packets_from_mmap with the correct arguments
    int num_packets = extract_and_process_packets_from_mmap(argv[1], packets, flows, flow_to_packet_map, NUM_PACKETS, NUM_FLOWS);
    if (num_packets < 0) {
        free(packets);
        free(flows);
        free(flow_to_packet_map);
        return EXIT_FAILURE;
    }

    printf("Extracted %d packets from pcap file.\n", num_packets);

    // Clean up allocated memory
    free(packets);
    free(flows);
    free(flow_to_packet_map);

    return EXIT_SUCCESS;
}
