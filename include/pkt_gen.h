#ifndef PKT_GEN_H
#define PKT_GEN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <zmq.h>

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
} PcapGlobalHeader;

typedef struct {
    uint32_t ts_sec;          // Timestamp seconds
    uint32_t ts_usec;         // Timestamp microseconds
    uint32_t incl_len;        // Number of octets of packet saved in file
    uint32_t orig_len;        // Actual length of packet
} PcapPacketHeader;

// Structure to represent a packet
typedef struct {
    char src_ip[16];
    uint16_t src_port;
    char dst_ip[16];
    uint16_t dst_port;
    char protocol[4];
    char *payload;
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
    char *app_common_name;
    uint8_t is_classified;
    uint8_t num_pkt_sent_for_classification;
    UT_hash_handle hh;   // Makes this structure hashable
} FlowMapEntry;


#endif // PKT_GEN_H