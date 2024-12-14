#ifndef CLASSIFIER_H
#define CLASSIFIER_H

#include "uthash.h"  // Include uthash for hash map

#define MAX_LINE_LENGTH 1024

// Structure for storing domain to application name mapping
typedef struct {
    char domain[1024];       // Key: domain name
    char app_name[1024];     // Value: application name
    UT_hash_handle hh;      // Makes this structure hashable
} DomainMapping;

// Function to parse the INI file and load mappings into the hash map
void parse_ini_file(const char *filename);

// Function to search for a domain in the payload and return the corresponding app_name
char *find_app_name_in_payload(const char *payload, size_t payload_len);

// Function to cleanup the hash map
void cleanup_domain_map();

#endif // CLASSIFIER_H
