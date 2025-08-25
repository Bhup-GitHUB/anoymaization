#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/arp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/common_structs.h"
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

// BPF maps for configuration and statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, anonymization_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, anonymization_stats);
} stats_map SEC(".maps");

// XDP program entry point
SEC("xdp")
int xdp_anonymize_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Validate packet size
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }
    
    // Get configuration
    __u32 config_key = 0;
    anonymization_config *config = bpf_map_lookup_elem(&config_map, &config_key);
    if (!config) {
        return XDP_PASS;  // No configuration, pass packet
    }
    
    // Get statistics
    __u32 stats_key = 0;
    anonymization_stats *stats = bpf_map_lookup_elem(&stats_map, &stats_key);
    if (!stats) {
        return XDP_PASS;  // No stats map, pass packet
    }
    
    // Update packet count
    stats->packets_processed++;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    
    // Check for multicast/broadcast packets
    bool is_multicast = is_multicast_mac(eth->h_dest);
    bool is_broadcast = is_broadcast_mac(eth->h_dest);
    
    if ((is_multicast || is_broadcast) && !config->anonymize_multicast_broadcast) {
        return XDP_PASS;  // Skip multicast/broadcast if not configured
    }
    
    // Initialize packet modifications tracking
    packet_modifications mods = {0};
    
    // Perform anonymization
    bool anonymized = anonymize_packet(data, data_end - data, config, &mods);
    
    if (anonymized) {
        stats->packets_anonymized++;
        
        // Update specific statistics
        if (mods.eth_src_modified || mods.eth_dst_modified) {
            stats->mac_addresses_anonymized++;
        }
        if (mods.ip_src_modified || mods.ip_dst_modified) {
            stats->ip_addresses_anonymized++;
        }
        if (mods.arp_modified) {
            stats->arp_packets_anonymized++;
        }
    } else {
        stats->errors++;
    }
    
    // Drop the packet after processing (as per design)
    return XDP_DROP;
}

// License required for BPF programs
char _license[] SEC("license") = "GPL";
