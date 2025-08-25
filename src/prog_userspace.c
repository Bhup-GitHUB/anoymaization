#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "common_structs.h"

// Global variables for cleanup
static int config_map_fd = -1;
static int stats_map_fd = -1;
static int prog_fd = -1;
static int xdp_link_fd = -1;
static char *interface_name = NULL;
static volatile bool running = true;

// Signal handler for graceful shutdown
static void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    running = false;
}

// Parse configuration file
static config_parse_result parse_config_file(const char *filename) {
    config_parse_result result = {0};
    result.success = false;
    
    FILE *file = fopen(filename, "r");
    if (!file) {
        snprintf(result.error_message, sizeof(result.error_message), 
                "Failed to open config file: %s", strerror(errno));
        return result;
    }
    
    // Initialize with defaults
    result.config = (anonymization_config){
        .anonymize_multicast_broadcast = false,
        .anonymize_srcmac_oui = true,
        .anonymize_srcmac_id = false,
        .anonymize_dstmac_oui = false,
        .anonymize_dstmac_id = true,
        .preserve_prefix = true,
        .anonymize_mac_in_arphdr = true,
        .anonymize_ipv4_in_arphdr = true,
        .src_ip_mask_lengths = 0xFFFFFF00,  // /24
        .dest_ip_mask_lengths = 0xFFFFFF00, // /24
        .random_salt = DEFAULT_SALT
    };
    
    char line[MAX_CONFIG_LINE_LENGTH];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_num++;
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        char *key = strtok(line, ":");
        char *value = strtok(NULL, ":");
        
        if (!key || !value) {
            continue;
        }
        
        // Remove whitespace
        while (*key == ' ') key++;
        while (*value == ' ') value++;
        
        // Remove newline from value
        char *newline = strchr(value, '\n');
        if (newline) *newline = '\0';
        
        // Parse configuration options
        if (strcmp(key, "anonymize_srcmac_oui") == 0) {
            result.config.anonymize_srcmac_oui = (strcmp(value, "yes") == 0);
        } else if (strcmp(key, "anonymize_srcmac_id") == 0) {
            result.config.anonymize_srcmac_id = (strcmp(value, "yes") == 0);
        } else if (strcmp(key, "anonymize_dstmac_oui") == 0) {
            result.config.anonymize_dstmac_oui = (strcmp(value, "yes") == 0);
        } else if (strcmp(key, "anonymize_dstmac_id") == 0) {
            result.config.anonymize_dstmac_id = (strcmp(value, "yes") == 0);
        } else if (strcmp(key, "preserve_prefix") == 0) {
            result.config.preserve_prefix = (strcmp(value, "yes") == 0);
        } else if (strcmp(key, "anonymize_multicast_broadcast") == 0) {
            result.config.anonymize_multicast_broadcast = (strcmp(value, "yes") == 0);
        } else if (strcmp(key, "anonymize_mac_in_arphdr") == 0) {
            result.config.anonymize_mac_in_arphdr = (strcmp(value, "yes") == 0);
        } else if (strcmp(key, "anonymize_ipv4_in_arphdr") == 0) {
            result.config.anonymize_ipv4_in_arphdr = (strcmp(value, "yes") == 0);
        } else if (strcmp(key, "random_salt") == 0) {
            result.config.random_salt = (__u32)strtoul(value, NULL, 0);
        }
    }
    
    fclose(file);
    result.success = true;
    return result;
}

// Load and attach XDP program
static int load_and_attach_xdp(const char *interface) {
    struct bpf_object *obj;
    int err;
    
    // Load BPF object file
    obj = bpf_object__open_file("prog_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return -1;
    }
    
    // Load BPF program
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        return err;
    }
    
    // Get program file descriptor
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_anonymize_prog");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program\n");
        bpf_object__close(obj);
        return -1;
    }
    
    prog_fd = bpf_program__fd(prog);
    
    // Get map file descriptors
    config_map_fd = bpf_object__find_map_fd_by_name(obj, "config_map");
    stats_map_fd = bpf_object__find_map_fd_by_name(obj, "stats_map");
    
    if (config_map_fd < 0 || stats_map_fd < 0) {
        fprintf(stderr, "Failed to get map file descriptors\n");
        bpf_object__close(obj);
        return -1;
    }
    
    // Attach XDP program to interface
    int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", interface);
        bpf_object__close(obj);
        return -1;
    }
    
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-err));
        bpf_object__close(obj);
        return err;
    }
    
    xdp_link_fd = err;
    printf("XDP program attached to interface %s\n", interface);
    
    bpf_object__close(obj);
    return 0;
}

// Update configuration in BPF map
static int update_config(const anonymization_config *config) {
    __u32 key = 0;
    int err = bpf_map_update_elem(config_map_fd, &key, config, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update config map: %s\n", strerror(-err));
        return err;
    }
    printf("Configuration updated successfully\n");
    return 0;
}

// Print statistics
static void print_stats() {
    __u32 key = 0;
    anonymization_stats stats;
    
    int err = bpf_map_lookup_elem(stats_map_fd, &key, &stats);
    if (err) {
        fprintf(stderr, "Failed to get statistics: %s\n", strerror(-err));
        return;
    }
    
    printf("\n=== Packet Anonymization Statistics ===\n");
    printf("Packets processed:     %llu\n", stats.packets_processed);
    printf("Packets anonymized:    %llu\n", stats.packets_anonymized);
    printf("MAC addresses anonymized: %llu\n", stats.mac_addresses_anonymized);
    printf("IP addresses anonymized:  %llu\n", stats.ip_addresses_anonymized);
    printf("ARP packets anonymized:   %llu\n", stats.arp_packets_anonymized);
    printf("Errors:               %llu\n", stats.errors);
    printf("=====================================\n");
}

// Cleanup function
static void cleanup() {
    if (xdp_link_fd >= 0) {
        bpf_xdp_detach(interface_name, XDP_FLAGS_DRV_MODE, NULL);
        printf("XDP program detached from interface %s\n", interface_name);
    }
    
    if (config_map_fd >= 0) {
        close(config_map_fd);
    }
    if (stats_map_fd >= 0) {
        close(stats_map_fd);
    }
    if (prog_fd >= 0) {
        close(prog_fd);
    }
}

// Main function
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <config_file>\n", argv[0]);
        fprintf(stderr, "Example: %s eth0 anonymization_config.txt\n", argv[0]);
        return 1;
    }
    
    interface_name = argv[1];
    const char *config_file = argv[2];
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Set resource limits for BPF
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Failed to set resource limit: %s\n", strerror(errno));
        return 1;
    }
    
    // Parse configuration
    config_parse_result config_result = parse_config_file(config_file);
    if (!config_result.success) {
        fprintf(stderr, "Configuration error: %s\n", config_result.error_message);
        return 1;
    }
    
    printf("Configuration loaded successfully\n");
    
    // Load and attach XDP program
    int err = load_and_attach_xdp(interface_name);
    if (err) {
        fprintf(stderr, "Failed to load and attach XDP program\n");
        return 1;
    }
    
    // Update configuration in BPF map
    err = update_config(&config_result.config);
    if (err) {
        cleanup();
        return 1;
    }
    
    printf("Packet anonymization started on interface %s\n", interface_name);
    printf("Press Ctrl+C to stop\n");
    
    // Main loop - print statistics periodically
    while (running) {
        sleep(5);
        print_stats();
    }
    
    cleanup();
    printf("Packet anonymization stopped\n");
    return 0;
}
