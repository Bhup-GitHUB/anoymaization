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

static inline int process_packet_headers(void *data, void *data_end, 
                                       struct ethhdr *eth, 
                                       anonymization_config *config,
                                       anonymization_stats *stats) {
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }
    
    bool multicast_detected = is_multicast_mac(eth->h_dest);
    bool broadcast_detected = is_broadcast_mac(eth->h_dest);
    
    if ((multicast_detected || broadcast_detected) && 
        !config->anonymize_multicast_broadcast) {
        return XDP_PASS;
    }
    
    return 0;
}

static inline void update_anonymization_stats(packet_modifications *mods, 
                                            anonymization_stats *stats) {
    if (mods->eth_src_modified || mods->eth_dst_modified) {
        stats->mac_addresses_anonymized++;
    }
    if (mods->ip_src_modified || mods->ip_dst_modified) {
        stats->ip_addresses_anonymized++;
    }
    if (mods->arp_modified) {
        stats->arp_packets_anonymized++;
    }
}

SEC("xdp")
int xdp_anonymize_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    __u32 config_key = 0;
    anonymization_config *config = bpf_map_lookup_elem(&config_map, &config_key);
    if (!config) {
        return XDP_PASS;
    }
    
    __u32 stats_key = 0;
    anonymization_stats *stats = bpf_map_lookup_elem(&stats_map, &stats_key);
    if (!stats) {
        return XDP_PASS;
    }
    
    stats->packets_processed++;
    
    struct ethhdr *eth = data;
    int header_result = process_packet_headers(data, data_end, eth, config, stats);
    if (header_result != 0) {
        return header_result;
    }
    
    packet_modifications mods = {0};
    bool anonymization_success = anonymize_packet(data, data_end - data, config, &mods);
    
    if (anonymization_success) {
        stats->packets_anonymized++;
        update_anonymization_stats(&mods, stats);
    } else {
        stats->errors++;
    }
    
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
