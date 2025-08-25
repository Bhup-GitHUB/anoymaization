#ifndef COMMON_STRUCTS_H
#define COMMON_STRUCTS_H

#include <linux/types.h>
#include <stdbool.h>

// Configuration structure shared between kernel and userspace
typedef struct anonymization_config {
    bool anonymize_multicast_broadcast;
    bool anonymize_srcmac_oui;
    bool anonymize_srcmac_id;
    bool anonymize_dstmac_oui;
    bool anonymize_dstmac_id;
    bool preserve_prefix;
    bool anonymize_mac_in_arphdr;
    bool anonymize_ipv4_in_arphdr;
    __u32 src_ip_mask_lengths;
    __u32 dest_ip_mask_lengths;
    __u32 random_salt;
} anonymization_config;

// IP range structure for configuration
typedef struct ip_range {
    __u32 start_ip;
    __u32 end_ip;
    __u32 mask;
} ip_range;

// Statistics structure for monitoring
typedef struct anonymization_stats {
    __u64 packets_processed;
    __u64 packets_anonymized;
    __u64 mac_addresses_anonymized;
    __u64 ip_addresses_anonymized;
    __u64 arp_packets_anonymized;
    __u64 errors;
} anonymization_stats;

// Packet metadata for processing
typedef struct packet_metadata {
    __u32 original_length;
    __u32 modified_length;
    __u16 protocol;
    bool is_arp;
    bool is_ipv4;
    bool is_multicast;
    bool is_broadcast;
} packet_metadata;

// Hash function result structure
typedef struct hash_result {
    __u32 hash_value;
    __u32 salt;
} hash_result;

// Configuration file parsing result
typedef struct config_parse_result {
    bool success;
    char error_message[256];
    anonymization_config config;
} config_parse_result;

// Constants
#define MAX_IP_RANGES 16
#define MAX_CONFIG_LINE_LENGTH 256
#define DEFAULT_SALT 0x12345678
#define HASH_MAGIC 0xDEADBEEF

// Error codes
#define SUCCESS 0
#define ERROR_INVALID_CONFIG -1
#define ERROR_MEMORY_ALLOCATION -2
#define ERROR_FILE_IO -3
#define ERROR_INVALID_IP_RANGE -4
#define ERROR_BPF_LOAD -5

#endif // COMMON_STRUCTS_H
