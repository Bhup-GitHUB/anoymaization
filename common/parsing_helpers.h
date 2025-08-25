#ifndef PARSING_HELPERS_H
#define PARSING_HELPERS_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/arp.h>
#include <linux/in.h>
#include <stdbool.h>
#include <stdint.h>

// Ethernet header parsing
static inline bool is_arp_packet(const struct ethhdr *eth) {
    return ntohs(eth->h_proto) == ETH_P_ARP;
}

static inline bool is_ipv4_packet(const struct ethhdr *eth) {
    return ntohs(eth->h_proto) == ETH_P_IP;
}

static inline bool is_multicast_mac(const unsigned char *mac) {
    return (mac[0] & 0x01) != 0;
}

static inline bool is_broadcast_mac(const unsigned char *mac) {
    return (mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff &&
            mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff);
}

// IP header parsing
static inline bool is_multicast_ip(__u32 ip_addr) {
    return (ntohl(ip_addr) & 0xF0000000) == 0xE0000000;
}

static inline bool is_broadcast_ip(__u32 ip_addr) {
    return ip_addr == 0xFFFFFFFF;
}

static inline bool is_private_ip(__u32 ip_addr) {
    __u32 addr = ntohl(ip_addr);
    return ((addr & 0xFF000000) == 0x0A000000) ||  // 10.0.0.0/8
           ((addr & 0xFFF00000) == 0xAC100000) ||  // 172.16.0.0/12
           ((addr & 0xFFFF0000) == 0xC0A80000) ||  // 192.168.0.0/16
           (addr == 0x7F000001);                    // 127.0.0.1
}

// ARP header parsing
static inline bool is_arp_request(const struct arphdr *arp) {
    return ntohs(arp->ar_op) == ARPOP_REQUEST;
}

static inline bool is_arp_reply(const struct arphdr *arp) {
    return ntohs(arp->ar_op) == ARPOP_REPLY;
}

// MAC address manipulation
static inline void copy_mac_addr(unsigned char *dst, const unsigned char *src) {
    for (int i = 0; i < ETH_ALEN; i++) {
        dst[i] = src[i];
    }
}

static inline bool mac_addr_equal(const unsigned char *mac1, const unsigned char *mac2) {
    for (int i = 0; i < ETH_ALEN; i++) {
        if (mac1[i] != mac2[i]) return false;
    }
    return true;
}

// IP address manipulation
static inline __u32 ip_to_network(__u32 host_ip) {
    return htonl(host_ip);
}

static inline __u32 ip_to_host(__u32 network_ip) {
    return ntohl(network_ip);
}

// Checksum calculation helpers
static inline __u16 csum_fold(__u32 csum) {
    __u32 sum = csum;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__u16)~sum;
}

static inline __u32 csum_add(__u32 csum, __u32 addend) {
    __u32 res = csum + addend;
    return res + (res < addend);
}

// Packet validation
static inline bool is_valid_ethernet_frame(const void *data, __u32 data_len) {
    return data_len >= sizeof(struct ethhdr);
}

static inline bool is_valid_ip_packet(const struct iphdr *iph, __u32 data_len) {
    return data_len >= sizeof(struct iphdr) &&
           iph->ihl >= 5 &&
           ntohs(iph->tot_len) <= data_len;
}

static inline bool is_valid_arp_packet(const struct arphdr *arp, __u32 data_len) {
    return data_len >= sizeof(struct arphdr) &&
           ntohs(arp->ar_hln) == ETH_ALEN &&
           ntohs(arp->ar_pln) == 4;
}

// Protocol identification
typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_ARP = 1,
    PROTO_IPV4 = 2,
    PROTO_IPV6 = 3
} protocol_type_t;

static inline protocol_type_t identify_protocol(const struct ethhdr *eth) {
    __u16 proto = ntohs(eth->h_proto);
    switch (proto) {
        case ETH_P_ARP:
            return PROTO_ARP;
        case ETH_P_IP:
            return PROTO_IPV4;
        case ETH_P_IPV6:
            return PROTO_IPV6;
        default:
            return PROTO_UNKNOWN;
    }
}

#endif // PARSING_HELPERS_H
