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

typedef struct {
    int config_map_fd;
    int stats_map_fd;
    int prog_fd;
    int xdp_link_fd;
    char *interface_name;
    volatile bool running;
} application_state;

static application_state app_state = {
    .config_map_fd = -1,
    .stats_map_fd = -1,
    .prog_fd = -1,
    .xdp_link_fd = -1,
    .interface_name = NULL,
    .running = true
};

static void handle_signal(int sig) {
    printf("\nSignal %d received, terminating...\n", sig);
    app_state.running = false;
}

static anonymization_config create_default_config(void) {
    return (anonymization_config){
        .anonymize_multicast_broadcast = false,
        .anonymize_srcmac_oui = true,
        .anonymize_srcmac_id = false,
        .anonymize_dstmac_oui = false,
        .anonymize_dstmac_id = true,
        .preserve_prefix = true,
        .anonymize_mac_in_arphdr = true,
        .anonymize_ipv4_in_arphdr = true,
        .src_ip_mask_lengths = 0xFFFFFF00,
        .dest_ip_mask_lengths = 0xFFFFFF00,
        .random_salt = DEFAULT_SALT
    };
}

static void trim_whitespace(char *str) {
    while (*str == ' ') str++;
    char *end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\n' || *end == '\r')) {
        *end = '\0';
        end--;
    }
}

static bool parse_boolean_value(const char *value) {
    return strcmp(value, "yes") == 0 || strcmp(value, "true") == 0 || strcmp(value, "1") == 0;
}

static void apply_config_option(anonymization_config *config, const char *key, const char *value) {
    if (strcmp(key, "anonymize_srcmac_oui") == 0) {
        config->anonymize_srcmac_oui = parse_boolean_value(value);
    } else if (strcmp(key, "anonymize_srcmac_id") == 0) {
        config->anonymize_srcmac_id = parse_boolean_value(value);
    } else if (strcmp(key, "anonymize_dstmac_oui") == 0) {
        config->anonymize_dstmac_oui = parse_boolean_value(value);
    } else if (strcmp(key, "anonymize_dstmac_id") == 0) {
        config->anonymize_dstmac_id = parse_boolean_value(value);
    } else if (strcmp(key, "preserve_prefix") == 0) {
        config->preserve_prefix = parse_boolean_value(value);
    } else if (strcmp(key, "anonymize_multicast_broadcast") == 0) {
        config->anonymize_multicast_broadcast = parse_boolean_value(value);
    } else if (strcmp(key, "anonymize_mac_in_arphdr") == 0) {
        config->anonymize_mac_in_arphdr = parse_boolean_value(value);
    } else if (strcmp(key, "anonymize_ipv4_in_arphdr") == 0) {
        config->anonymize_ipv4_in_arphdr = parse_boolean_value(value);
    } else if (strcmp(key, "random_salt") == 0) {
        config->random_salt = (__u32)strtoul(value, NULL, 0);
    }
}

static config_parse_result parse_config_file(const char *filename) {
    config_parse_result result = {0};
    result.success = false;
    
    FILE *file = fopen(filename, "r");
    if (!file) {
        snprintf(result.error_message, sizeof(result.error_message), 
                "Config file open failed: %s", strerror(errno));
        return result;
    }
    
    result.config = create_default_config();
    
    char line[MAX_CONFIG_LINE_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        char *key = strtok(line, ":");
        char *value = strtok(NULL, ":");
        
        if (!key || !value) {
            continue;
        }
        
        trim_whitespace(key);
        trim_whitespace(value);
        
        apply_config_option(&result.config, key, value);
    }
    
    fclose(file);
    result.success = true;
    return result;
}

static int load_bpf_program(void) {
    struct bpf_object *obj = bpf_object__open_file("prog_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "BPF object file open failed\n");
        return -1;
    }
    
    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "BPF object load failed: %s\n", strerror(-err));
        bpf_object__close(obj);
        return err;
    }
    
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_anonymize_prog");
    if (!prog) {
        fprintf(stderr, "XDP program not found\n");
        bpf_object__close(obj);
        return -1;
    }
    
    app_state.prog_fd = bpf_program__fd(prog);
    app_state.config_map_fd = bpf_object__find_map_fd_by_name(obj, "config_map");
    app_state.stats_map_fd = bpf_object__find_map_fd_by_name(obj, "stats_map");
    
    if (app_state.config_map_fd < 0 || app_state.stats_map_fd < 0) {
        fprintf(stderr, "BPF maps not found\n");
        bpf_object__close(obj);
        return -1;
    }
    
    bpf_object__close(obj);
    return 0;
}

static int attach_xdp_program(const char *interface) {
    int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", interface);
        return -1;
    }
    
    int err = bpf_xdp_attach(ifindex, app_state.prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (err) {
        fprintf(stderr, "XDP program attach failed: %s\n", strerror(-err));
        return err;
    }
    
    app_state.xdp_link_fd = err;
    printf("XDP program attached to %s\n", interface);
    return 0;
}

static int update_bpf_config(const anonymization_config *config) {
    __u32 key = 0;
    int err = bpf_map_update_elem(app_state.config_map_fd, &key, config, BPF_ANY);
    if (err) {
        fprintf(stderr, "Config map update failed: %s\n", strerror(-err));
        return err;
    }
    printf("Configuration updated\n");
    return 0;
}

static void display_statistics(void) {
    __u32 key = 0;
    anonymization_stats stats;
    
    int err = bpf_map_lookup_elem(app_state.stats_map_fd, &key, &stats);
    if (err) {
        fprintf(stderr, "Statistics retrieval failed: %s\n", strerror(-err));
        return;
    }
    
    printf("\n=== Anonymization Statistics ===\n");
    printf("Packets processed:     %llu\n", stats.packets_processed);
    printf("Packets anonymized:    %llu\n", stats.packets_anonymized);
    printf("MAC addresses anonymized: %llu\n", stats.mac_addresses_anonymized);
    printf("IP addresses anonymized:  %llu\n", stats.ip_addresses_anonymized);
    printf("ARP packets anonymized:   %llu\n", stats.arp_packets_anonymized);
    printf("Errors:               %llu\n", stats.errors);
    printf("================================\n");
}

static void cleanup_resources(void) {
    if (app_state.xdp_link_fd >= 0) {
        bpf_xdp_detach(app_state.interface_name, XDP_FLAGS_DRV_MODE, NULL);
        printf("XDP program detached from %s\n", app_state.interface_name);
    }
    
    if (app_state.config_map_fd >= 0) close(app_state.config_map_fd);
    if (app_state.stats_map_fd >= 0) close(app_state.stats_map_fd);
    if (app_state.prog_fd >= 0) close(app_state.prog_fd);
}

static int setup_resource_limits(void) {
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Resource limit setup failed: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <config_file>\n", argv[0]);
        fprintf(stderr, "Example: %s eth0 anonymization_config.txt\n", argv[0]);
        return 1;
    }
    
    app_state.interface_name = argv[1];
    const char *config_file = argv[2];
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    if (setup_resource_limits()) {
        return 1;
    }
    
    config_parse_result config_result = parse_config_file(config_file);
    if (!config_result.success) {
        fprintf(stderr, "Configuration error: %s\n", config_result.error_message);
        return 1;
    }
    
    printf("Configuration loaded\n");
    
    if (load_bpf_program()) {
        fprintf(stderr, "BPF program loading failed\n");
        return 1;
    }
    
    if (attach_xdp_program(app_state.interface_name)) {
        cleanup_resources();
        return 1;
    }
    
    if (update_bpf_config(&config_result.config)) {
        cleanup_resources();
        return 1;
    }
    
    printf("Anonymization started on %s\n", app_state.interface_name);
    printf("Press Ctrl+C to stop\n");
    
    while (app_state.running) {
        sleep(5);
        display_statistics();
    }
    
    cleanup_resources();
    printf("Anonymization stopped\n");
    return 0;
}
