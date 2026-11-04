#ifndef ANTIGRAVITY_PROXY_H
#define ANTIGRAVITY_PROXY_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/time.h>

#define AGY_PROXY_VERSION "2.4-linux"

#define PROXY_TYPE_SOCKS5 1
#define PROXY_TYPE_HTTP   2

#define INJECTION_MODE_FILTERED 1
#define INJECTION_MODE_INHERIT  2

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO  1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_ERROR 3

#define FAKE_IP_MAGIC 0x41475950524F5859ULL /* "AGYPROXY" */

typedef struct {
    char host[256];
    uint16_t port;
    int type; // PROXY_TYPE_SOCKS5 or PROXY_TYPE_HTTP
} proxy_server_t;

typedef struct {
    bool enabled;
    char cidr[64];
    uint32_t net_ip;
    uint32_t net_mask;
} fake_ip_config_t;

typedef struct {
    int connect_ms;
    int send_ms;
    int recv_ms;
} timeout_config_t;

typedef struct {
    int allowed_ports[32];
    int allowed_ports_count;
    char dns_mode[16];   // "direct" or "proxy"
    char ipv6_mode[16];  // "proxy", "direct", "block"
    char udp_mode[16];   // "auto", "block", "direct", "proxy"
    char udp_fallback[16]; // "block", "direct"
    bool routing_enabled;
    bool use_default_private;
    char default_action[16]; // "proxy" or "direct"
} rules_config_t;

typedef struct {
    int log_level;
    bool traffic_logging;
    bool child_injection;
    int child_injection_mode; // FILTERED or INHERIT
    char **child_injection_exclude;
    int child_injection_exclude_count;
    char **target_processes;
    int target_processes_count;

    proxy_server_t proxy;
    fake_ip_config_t fake_ip;
    timeout_config_t timeout;
    rules_config_t rules;

    char log_file_path[512];
    char config_file_path[512];
} app_config_t;

extern app_config_t g_config;
extern bool g_is_targeted_process;
extern char g_process_name[256];

#endif /* ANTIGRAVITY_PROXY_H */
