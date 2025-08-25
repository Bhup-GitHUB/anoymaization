#ifndef REWRITE_HELPERS_H
#define REWRITE_HELPERS_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/arp.h>
#include <stdbool.h>
#include <stdint.h>
#include "common_structs.h"

static inline __u32 compute_hash(__u32 value, __u32 salt) {
    __u32 hash = value ^ salt;
    hash = ((hash << 13) ^ hash) >> 19;
    hash = ((hash << 5) + hash) + 0xe6546b64;
    hash = ((hash << 13) ^ hash) >> 16;
    hash = ((hash << 5) + hash) + 0x85ebca6b;
    return hash;
}

static inline void process_mac_oui(unsigned char *mac, __u32 salt) {
    __u32 oui = (mac[0] << 16) | (mac[1] << 8) | mac[2];
    __u32 hashed_oui = compute_hash(oui, salt);
    
    bool multicast_flag = (mac[0] & 0x01) != 0;
    hashed_oui &= 0xFEFFFF;
    if (multicast_flag) {
        hashed_oui |= 0x010000;
    }
    
    mac[0] = (hashed_oui >> 16) & 0xFF;
    mac[1] = (hashed_oui >> 8) & 0xFF;
    mac[2] = hashed_oui & 0xFF;
}

static inline void process_mac_id(unsigned char *mac, __u32 salt) {
    __u32 id = (mac[3] << 16) | (mac[4] << 8) | mac[5];
    __u32 hashed_id = compute_hash(id, salt);
    
    mac[3] = (hashed_id >> 16) & 0xFF;
    mac[4] = (hashed_id >> 8) & 0xFF;
    mac[5] = hashed_id & 0xFF;
}

static inline __u32 process_ip_with_prefix(__u32 ip_addr, __u32 salt, __u32 prefix_mask) {
    __u32 network_part = ip_addr & prefix_mask;
    __u32 host_part = ip_addr & ~prefix_mask;
    __u32 hashed_host = compute_hash(host_part, salt);
    
    return network_part | (hashed_host & ~prefix_mask);
}

static inline __u32 process_ip_full(__u32 ip_addr, __u32 salt) {
    return compute_hash(ip_addr, salt);
}

static inline __u16 recalculate_ip_checksum(const struct iphdr *iph) {
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)iph;
    int len = iph->ihl * 4;
    
    sum -= ntohs(iph->check);
    
    for (int i = 0; i < len / 2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    if (len % 2) {
        sum += ((unsigned char *)iph)[len - 1] << 8;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return htons(~sum);
}

static inline void process_arp_mac(struct arphdr *arp, unsigned char *arp_data, __u32 salt) {
    process_mac_oui(&arp_data[0], salt);
    process_mac_id(&arp_data[0], salt);
    
    process_mac_oui(&arp_data[6], salt);
    process_mac_id(&arp_data[6], salt);
}

static inline void process_arp_ip(struct arphdr *arp, unsigned char *arp_data, __u32 salt) {
    __u32 *sender_ip = (__u32 *)&arp_data[12];
    __u32 *target_ip = (__u32 *)&arp_data[16];
    
    *sender_ip = process_ip_full(ntohl(*sender_ip), salt);
    *target_ip = process_ip_full(ntohl(*target_ip), salt);
    
    *sender_ip = htonl(*sender_ip);
    *target_ip = htonl(*target_ip);
}

static inline bool is_multicast_mac(const unsigned char *mac) {
    return (mac[0] & 0x01) != 0;
}

static inline bool is_broadcast_mac(const unsigned char *mac) {
    return (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
            mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF);
}

static inline bool is_arp_packet(const struct ethhdr *eth) {
    return ntohs(eth->h_proto) == ETH_P_ARP;
}

static inline bool is_ipv4_packet(const struct ethhdr *eth) {
    return ntohs(eth->h_proto) == ETH_P_IP;
}

static inline bool is_multicast_ip(__u32 ip_addr) {
    return (ip_addr & 0xF0000000) == 0xE0000000;
}

static inline bool is_broadcast_ip(__u32 ip_addr) {
    return ip_addr == 0xFFFFFFFF;
}

static inline bool is_private_ip(__u32 ip_addr) {
    __u32 first_byte = (ip_addr >> 24) & 0xFF;
    return (first_byte == 10) || 
           (first_byte == 172 && ((ip_addr >> 16) & 0xFF) >= 16 && ((ip_addr >> 16) & 0xFF) <= 31) ||
           (first_byte == 192 && ((ip_addr >> 16) & 0xFF) == 168);
}

static inline void anonymize_ethernet_header(struct ethhdr *eth, const anonymization_config *config) {
    if (config->anonymize_srcmac_oui) {
        process_mac_oui(eth->h_source, config->random_salt);
    }
    if (config->anonymize_srcmac_id) {
        process_mac_id(eth->h_source, config->random_salt);
    }
    if (config->anonymize_dstmac_oui) {
        process_mac_oui(eth->h_dest, config->random_salt);
    }
    if (config->anonymize_dstmac_id) {
        process_mac_id(eth->h_dest, config->random_salt);
    }
}

static inline void anonymize_ip_header(struct iphdr *iph, const anonymization_config *config) {
    if (config->anonymize_srcipv4) {
        if (config->preserve_prefix) {
            iph->saddr = process_ip_with_prefix(iph->saddr, config->random_salt, config->src_ip_mask_lengths);
        } else {
            iph->saddr = process_ip_full(iph->saddr, config->random_salt);
        }
    }
    
    if (config->anonymize_dstipv4) {
        if (config->preserve_prefix) {
            iph->daddr = process_ip_with_prefix(iph->daddr, config->random_salt, config->dest_ip_mask_lengths);
        } else {
            iph->daddr = process_ip_full(iph->daddr, config->random_salt);
        }
    }
    
    iph->check = recalculate_ip_checksum(iph);
}

static inline bool anonymize_packet(void *data, size_t data_len, 
                                  const anonymization_config *config,
                                  packet_modifications *mods) {
    if (data_len < sizeof(struct ethhdr)) {
        return false;
    }
    
    struct ethhdr *eth = (struct ethhdr *)data;
    
    if (is_arp_packet(eth)) {
        if (data_len < sizeof(struct ethhdr) + sizeof(struct arphdr)) {
            return false;
        }
        
        struct arphdr *arp = (struct arphdr *)(eth + 1);
        unsigned char *arp_data = (unsigned char *)(arp + 1);
        
        if (config->anonymize_mac_in_arphdr) {
            process_arp_mac(arp, arp_data, config->random_salt);
            mods->arp_modified = true;
        }
        
        if (config->anonymize_ipv4_in_arphdr) {
            process_arp_ip(arp, arp_data, config->random_salt);
            mods->arp_modified = true;
        }
        
        anonymize_ethernet_header(eth, config);
        mods->eth_src_modified = config->anonymize_srcmac_oui || config->anonymize_srcmac_id;
        mods->eth_dst_modified = config->anonymize_dstmac_oui || config->anonymize_dstmac_id;
        
        return true;
    }
    
    if (is_ipv4_packet(eth)) {
        if (data_len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
            return false;
        }
        
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        
        anonymize_ip_header(iph, config);
        mods->ip_src_modified = config->anonymize_srcipv4;
        mods->ip_dst_modified = config->anonymize_dstipv4;
        
        anonymize_ethernet_header(eth, config);
        mods->eth_src_modified = config->anonymize_srcmac_oui || config->anonymize_srcmac_id;
        mods->eth_dst_modified = config->anonymize_dstmac_oui || config->anonymize_dstmac_id;
        
        return true;
    }
    
    anonymize_ethernet_header(eth, config);
    mods->eth_src_modified = config->anonymize_srcmac_oui || config->anonymize_srcmac_id;
    mods->eth_dst_modified = config->anonymize_dstmac_oui || config->anonymize_dstmac_id;
    
    return true;
}

#endif
