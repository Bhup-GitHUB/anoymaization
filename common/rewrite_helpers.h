#ifndef REWRITE_HELPERS_H
#define REWRITE_HELPERS_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/arp.h>
#include <stdbool.h>
#include <stdint.h>
#include "common_structs.h"

// Hash function for anonymization
static inline __u32 hash_anonymize(__u32 value, __u32 salt) {
    __u32 hash = value ^ salt;
    hash = ((hash << 13) ^ hash) >> 19;
    hash = ((hash << 5) + hash) + 0xe6546b64;
    hash = ((hash << 13) ^ hash) >> 16;
    hash = ((hash << 5) + hash) + 0x85ebca6b;
    return hash;
}

// MAC address anonymization
static inline void anonymize_mac_oui(unsigned char *mac, __u32 salt) {
    __u32 oui = (mac[0] << 16) | (mac[1] << 8) | mac[2];
    __u32 hashed_oui = hash_anonymize(oui, salt);
    
    // Preserve multicast/broadcast bit
    bool is_multicast = (mac[0] & 0x01) != 0;
    hashed_oui &= 0xFEFFFF;  // Clear multicast bit
    if (is_multicast) {
        hashed_oui |= 0x010000;  // Set multicast bit
    }
    
    mac[0] = (hashed_oui >> 16) & 0xFF;
    mac[1] = (hashed_oui >> 8) & 0xFF;
    mac[2] = hashed_oui & 0xFF;
}

static inline void anonymize_mac_id(unsigned char *mac, __u32 salt) {
    __u32 id = (mac[3] << 16) | (mac[4] << 8) | mac[5];
    __u32 hashed_id = hash_anonymize(id, salt);
    
    mac[3] = (hashed_id >> 16) & 0xFF;
    mac[4] = (hashed_id >> 8) & 0xFF;
    mac[5] = hashed_id & 0xFF;
}

// IP address anonymization with prefix preservation
static inline __u32 anonymize_ip_with_prefix(__u32 ip_addr, __u32 salt, __u32 prefix_mask) {
    __u32 network_part = ip_addr & prefix_mask;
    __u32 host_part = ip_addr & ~prefix_mask;
    __u32 hashed_host = hash_anonymize(host_part, salt);
    
    return network_part | (hashed_host & ~prefix_mask);
}

static inline __u32 anonymize_ip_full(__u32 ip_addr, __u32 salt) {
    return hash_anonymize(ip_addr, salt);
}

// IP checksum recalculation
static inline __u16 ip_checksum(const struct iphdr *iph) {
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)iph;
    int len = iph->ihl * 4;
    
    // Clear existing checksum
    sum -= ntohs(iph->check);
    
    // Calculate new checksum
    for (int i = 0; i < len / 2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    // Handle odd length
    if (len % 2) {
        sum += ((unsigned char *)iph)[len - 1] << 8;
    }
    
    // Fold and complement
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return htons(~sum);
}

// ARP packet anonymization
static inline void anonymize_arp_mac(struct arphdr *arp, unsigned char *arp_data, __u32 salt) {
    // Anonymize sender MAC (first 6 bytes after ARP header)
    anonymize_mac_oui(&arp_data[0], salt);
    anonymize_mac_id(&arp_data[0], salt);
    
    // Anonymize target MAC (bytes 6-11 after ARP header)
    anonymize_mac_oui(&arp_data[6], salt);
    anonymize_mac_id(&arp_data[6], salt);
}

static inline void anonymize_arp_ip(struct arphdr *arp, unsigned char *arp_data, __u32 salt) {
    // Anonymize sender IP (bytes 12-15 after ARP header)
    __u32 *sender_ip = (__u32 *)&arp_data[12];
    *sender_ip = anonymize_ip_full(*sender_ip, salt);
    
    // Anonymize target IP (bytes 16-19 after ARP header)
    __u32 *target_ip = (__u32 *)&arp_data[16];
    *target_ip = anonymize_ip_full(*target_ip, salt);
}

// Packet modification tracking
typedef struct packet_modifications {
    bool eth_src_modified;
    bool eth_dst_modified;
    bool ip_src_modified;
    bool ip_dst_modified;
    bool arp_modified;
    bool checksum_updated;
} packet_modifications;

// Main anonymization function
static inline bool anonymize_packet(void *data, __u32 data_len, 
                                   const anonymization_config *config,
                                   packet_modifications *mods) {
    if (!data || !config || !mods) {
        return false;
    }
    
    // Initialize modification tracking
    *mods = (packet_modifications){0};
    
    struct ethhdr *eth = (struct ethhdr *)data;
    
    // Validate packet
    if (!is_valid_ethernet_frame(data, data_len)) {
        return false;
    }
    
    // Anonymize Ethernet addresses
    if (config->anonymize_srcmac_oui) {
        anonymize_mac_oui(eth->h_source, config->random_salt);
        mods->eth_src_modified = true;
    }
    if (config->anonymize_srcmac_id) {
        anonymize_mac_id(eth->h_source, config->random_salt);
        mods->eth_src_modified = true;
    }
    if (config->anonymize_dstmac_oui) {
        anonymize_mac_oui(eth->h_dest, config->random_salt);
        mods->eth_dst_modified = true;
    }
    if (config->anonymize_dstmac_id) {
        anonymize_mac_id(eth->h_dest, config->random_salt);
        mods->eth_dst_modified = true;
    }
    
    // Handle ARP packets
    if (is_arp_packet(eth)) {
        struct arphdr *arp = (struct arphdr *)(eth + 1);
        unsigned char *arp_data = (unsigned char *)(arp + 1);
        
        if (config->anonymize_mac_in_arphdr) {
            anonymize_arp_mac(arp, arp_data, config->random_salt);
            mods->arp_modified = true;
        }
        if (config->anonymize_ipv4_in_arphdr) {
            anonymize_arp_ip(arp, arp_data, config->random_salt);
            mods->arp_modified = true;
        }
    }
    
    // Handle IPv4 packets
    if (is_ipv4_packet(eth)) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        
        if (!is_valid_ip_packet(iph, data_len - sizeof(struct ethhdr))) {
            return false;
        }
        
        // Anonymize source IP
        if (config->anonymize_srcipv4) {
            if (config->preserve_prefix) {
                iph->saddr = anonymize_ip_with_prefix(iph->saddr, config->random_salt, 
                                                    config->src_ip_mask_lengths);
            } else {
                iph->saddr = anonymize_ip_full(iph->saddr, config->random_salt);
            }
            mods->ip_src_modified = true;
        }
        
        // Anonymize destination IP
        if (config->anonymize_dstipv4) {
            if (config->preserve_prefix) {
                iph->daddr = anonymize_ip_with_prefix(iph->daddr, config->random_salt,
                                                    config->dest_ip_mask_lengths);
            } else {
                iph->daddr = anonymize_ip_full(iph->daddr, config->random_salt);
            }
            mods->ip_dst_modified = true;
        }
        
        // Update IP checksum if IP was modified
        if (mods->ip_src_modified || mods->ip_dst_modified) {
            iph->check = ip_checksum(iph);
            mods->checksum_updated = true;
        }
    }
    
    return true;
}

#endif // REWRITE_HELPERS_H
