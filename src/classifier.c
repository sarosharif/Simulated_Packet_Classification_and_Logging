#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "classifier.h"

DomainMapping *domain_map = NULL;  // The hash map

// Insert domain and app_name into the hash table
void insert_domain_mapping(const char *domain, const char *app_name) {
    DomainMapping *entry = (DomainMapping *)malloc(sizeof(DomainMapping));
    strcpy(entry->domain, domain);
    strcpy(entry->app_name, app_name);

    // Add the entry to the hash map
    HASH_ADD_STR(domain_map, domain, entry);
}

// Lookup domain in the hash table and return app_name
const char *lookup_domain(const char *domain) {
    DomainMapping *entry;
    HASH_FIND_STR(domain_map, domain, entry);  // Find domain in the hash table
    if (entry) {
        return entry->app_name;  // Return the corresponding app name
    }
    return NULL;  // Return NULL if domain not found
}

// Parse INI file and load mappings
void parse_ini_file(const char *filename) {
    printf("%s\n",filename);
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        // Skip empty lines and comments
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        // Parse domain and app_name (expecting format: domain=app_name)
        char *domain = strtok(line, "=");
        char *app_name = strtok(NULL, "\n");

        if (domain && app_name) {
            insert_domain_mapping(domain, app_name);
        }
    }

    fclose(file);
}

// Function to search for a domain in the payload and return the app_name
char *find_app_name_in_payload(const char *payload) {
    DomainMapping *entry;
    for (entry = domain_map; entry != NULL; entry = entry->hh.next) {
        printf("%s\n",payload);
        printf("%s\n",entry->domain);
        if (strstr(payload, entry->domain) != NULL) {
            printf("found\n");
            return entry->app_name;
        }
        printf("------\n\n");
    }
    return NULL; 
}

// Cleanup hash map and free memory
void cleanup_domain_map() {
    DomainMapping *current_entry, *tmp;
    HASH_ITER(hh, domain_map, current_entry, tmp) {
        HASH_DEL(domain_map, current_entry);  // Delete the entry from hash map
        free(current_entry);                  // Free the allocated memory
    }
}
