#ifndef PARSING_HELPERS_H
#define PARSING_HELPERS_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "common_structs.h"

static inline bool is_valid_ethernet_frame(const void *data, size_t data_len) {
    if (!data || data_len < sizeof(struct ethhdr)) {
        return false;
    }
    
    const struct ethhdr *eth = (const struct ethhdr *)data;
    return ntohs(eth->h_proto) == ETH_P_IP || ntohs(eth->h_proto) == ETH_P_ARP;
}

static inline bool is_valid_ip_packet(const struct iphdr *iph, size_t data_len) {
    if (!iph || data_len < sizeof(struct iphdr)) {
        return false;
    }
    
    if (iph->version != 4) {
        return false;
    }
    
    if (iph->ihl < 5) {
        return false;
    }
    
    size_t header_len = iph->ihl * 4;
    if (header_len > data_len) {
        return false;
    }
    
    return true;
}

static inline bool is_valid_arp_packet(const struct arphdr *arp, size_t data_len) {
    if (!arp || data_len < sizeof(struct arphdr)) {
        return false;
    }
    
    if (ntohs(arp->ar_hrd) != ARPHRD_ETHER) {
        return false;
    }
    
    if (ntohs(arp->ar_pro) != ETH_P_IP) {
        return false;
    }
    
    if (arp->ar_hln != ETH_ALEN) {
        return false;
    }
    
    if (arp->ar_pln != 4) {
        return false;
    }
    
    return true;
}

static inline __u32 parse_ip_address(const char *ip_str) {
    if (!ip_str) {
        return 0;
    }
    
    __u32 ip = 0;
    int octet = 0;
    char *token = strtok((char *)ip_str, ".");
    
    while (token && octet < 4) {
        int value = atoi(token);
        if (value < 0 || value > 255) {
            return 0;
        }
        ip |= (value << (24 - octet * 8));
        octet++;
        token = strtok(NULL, ".");
    }
    
    return octet == 4 ? ip : 0;
}

static inline bool parse_ip_range(const char *range_str, ip_range *range) {
    if (!range_str || !range) {
        return false;
    }
    
    char *dash = strchr((char *)range_str, '-');
    if (!dash) {
        return false;
    }
    
    *dash = '\0';
    __u32 start_ip = parse_ip_address(range_str);
    __u32 end_ip = parse_ip_address(dash + 1);
    *dash = '-';
    
    if (!start_ip || !end_ip || start_ip > end_ip) {
        return false;
    }
    
    range->start_ip = start_ip;
    range->end_ip = end_ip;
    range->mask = 0xFFFFFFFF;
    
    return true;
}

static inline bool parse_cidr_range(const char *cidr_str, ip_range *range) {
    if (!cidr_str || !range) {
        return false;
    }
    
    char *slash = strchr((char *)cidr_str, '/');
    if (!slash) {
        return false;
    }
    
    *slash = '\0';
    __u32 ip = parse_ip_address(cidr_str);
    int prefix_len = atoi(slash + 1);
    *slash = '/';
    
    if (!ip || prefix_len < 0 || prefix_len > 32) {
        return false;
    }
    
    __u32 mask = prefix_len == 0 ? 0 : (0xFFFFFFFF << (32 - prefix_len));
    __u32 network = ip & mask;
    __u32 broadcast = network | (~mask);
    
    range->start_ip = network;
    range->end_ip = broadcast;
    range->mask = mask;
    
    return true;
}

static inline bool is_ip_in_range(__u32 ip, const ip_range *range) {
    if (!range) {
        return false;
    }
    
    return ip >= range->start_ip && ip <= range->end_ip;
}

static inline bool is_valid_mac_address(const char *mac_str) {
    if (!mac_str || strlen(mac_str) != 17) {
        return false;
    }
    
    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (mac_str[i] != ':') {
                return false;
            }
        } else {
            if (!isxdigit(mac_str[i])) {
                return false;
            }
        }
    }
    
    return true;
}

static inline bool parse_mac_address(const char *mac_str, unsigned char *mac) {
    if (!mac_str || !mac || !is_valid_mac_address(mac_str)) {
        return false;
    }
    
    for (int i = 0; i < 6; i++) {
        char hex[3] = {mac_str[i * 3], mac_str[i * 3 + 1], '\0'};
        mac[i] = (unsigned char)strtol(hex, NULL, 16);
    }
    
    return true;
}

static inline bool is_whitespace_only(const char *str) {
    if (!str) {
        return true;
    }
    
    while (*str) {
        if (!isspace(*str)) {
            return false;
        }
        str++;
    }
    
    return true;
}

static inline void remove_trailing_whitespace(char *str) {
    if (!str) {
        return;
    }
    
    int len = strlen(str);
    while (len > 0 && isspace(str[len - 1])) {
        str[len - 1] = '\0';
        len--;
    }
}

static inline char *find_next_non_whitespace(const char *str) {
    if (!str) {
        return NULL;
    }
    
    while (*str && isspace(*str)) {
        str++;
    }
    
    return (char *)str;
}

static inline bool string_starts_with(const char *str, const char *prefix) {
    if (!str || !prefix) {
        return false;
    }
    
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

static inline bool string_equals_ignore_case(const char *str1, const char *str2) {
    if (!str1 || !str2) {
        return false;
    }
    
    return strcasecmp(str1, str2) == 0;
}

static inline int parse_integer(const char *str, int base) {
    if (!str) {
        return 0;
    }
    
    char *endptr;
    long value = strtol(str, &endptr, base);
    
    if (*endptr != '\0') {
        return 0;
    }
    
    return (int)value;
}

static inline bool parse_boolean(const char *str) {
    if (!str) {
        return false;
    }
    
    return string_equals_ignore_case(str, "yes") ||
           string_equals_ignore_case(str, "true") ||
           string_equals_ignore_case(str, "1") ||
           string_equals_ignore_case(str, "on");
}

#endif
