#include "antigravity_proxy.h"
#include "config.h"
#include "fakeip.h"
#include "socks5.h"
#include "http.h"
#include "logger.h"
#include <libgen.h>

app_config_t g_config;
bool g_is_targeted_process = true;
char g_process_name[256] = "unknown";

static int (*real_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*real_getaddrinfo)(const char *node, const char *service,
                               const struct addrinfo *hints, struct addrinfo **res) = NULL;
static void (*real_freeaddrinfo)(struct addrinfo *res) = NULL;
static struct hostent* (*real_gethostbyname)(const char *name) = NULL;
static int (*real_close)(int fd) = NULL;

static void init_real_functions(void) {
    if (!real_connect) {
        real_connect = dlsym(RTLD_NEXT, "connect");
        real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
        real_freeaddrinfo = dlsym(RTLD_NEXT, "freeaddrinfo");
        real_gethostbyname = dlsym(RTLD_NEXT, "gethostbyname");
        real_close = dlsym(RTLD_NEXT, "close");
    }
}

static void detect_process_name(void) {
    if (program_invocation_short_name && program_invocation_short_name[0] != '\0') {
        strncpy(g_process_name, program_invocation_short_name, sizeof(g_process_name) - 1);
        return;
    }

    char exe_path[512] = {0};
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        char *bname = basename(exe_path);
        strncpy(g_process_name, bname, sizeof(g_process_name) - 1);
    } else {
        FILE *cmd_fp = fopen("/proc/self/cmdline", "r");
        if (cmd_fp) {
            if (fgets(exe_path, sizeof(exe_path), cmd_fp)) {
                char *bname = basename(exe_path);
                strncpy(g_process_name, bname, sizeof(g_process_name) - 1);
            }
            fclose(cmd_fp);
        }
    }
}

static bool match_process_pattern(const char *proc, const char *pattern) {
    if (!proc || !pattern) return false;
    char pat_clean[256];
    strncpy(pat_clean, pattern, sizeof(pat_clean) - 1);
    pat_clean[sizeof(pat_clean) - 1] = '\0';
    // Strip trailing .exe if present in pattern
    size_t plen = strlen(pat_clean);
    if (plen > 4 && strcasecmp(pat_clean + plen - 4, ".exe") == 0) {
        pat_clean[plen - 4] = '\0';
    }
    return strcasestr(proc, pat_clean) != NULL;
}

static bool check_if_targeted(void) {
    if (getenv("ANTIGRAVITY_PROXY_FORCE") != NULL) {
        return true;
    }

    // Check exclusion first
    for (int i = 0; i < g_config.child_injection_exclude_count; i++) {
        if (match_process_pattern(g_process_name, g_config.child_injection_exclude[i])) {
            return false;
        }
    }

    if (g_config.child_injection_mode == INJECTION_MODE_INHERIT) {
        return true;
    }

    if (g_config.target_processes_count == 0) {
        return true;
    }

    for (int i = 0; i < g_config.target_processes_count; i++) {
        if (match_process_pattern(g_process_name, g_config.target_processes[i])) {
            return true;
        }
    }

    // Also check /proc/self/exe directly in case program_invocation_short_name was a wrapper
    char raw_exe[512] = {0};
    ssize_t elen = readlink("/proc/self/exe", raw_exe, sizeof(raw_exe) - 1);
    if (elen > 0) {
        raw_exe[elen] = '\0';
        char *bname = basename(raw_exe);
        for (int i = 0; i < g_config.target_processes_count; i++) {
            if (match_process_pattern(bname, g_config.target_processes[i])) {
                return true;
            }
        }
    }

    return false;
}

__attribute__((constructor))
static void antigravity_proxy_init(void) {
    init_real_functions();
    detect_process_name();
    config_load(&g_config);

    g_is_targeted_process = check_if_targeted();

    if (g_is_targeted_process) {
        logger_init(g_config.log_file_path, g_config.log_level);
        if (g_config.fake_ip.enabled) {
            fakeip_init(g_config.fake_ip.cidr);
        }
        LOG_INFO("==================================================");
        LOG_INFO("Antigravity-Proxy Linux (版本 %s) 已加载", AGY_PROXY_VERSION);
        LOG_INFO("目标进程: %s (PID=%d)", g_process_name, getpid());
        LOG_INFO("代理配置: %s://%s:%u",
                 g_config.proxy.type == PROXY_TYPE_HTTP ? "http" : "socks5",
                 g_config.proxy.host, g_config.proxy.port);
        LOG_INFO("FakeIP 系统: %s (CIDR: %s)",
                 g_config.fake_ip.enabled ? "已启用" : "未启用",
                 g_config.fake_ip.cidr);
        LOG_INFO("==================================================");
    }
}

__attribute__((destructor))
static void antigravity_proxy_fini(void) {
    if (g_is_targeted_process) {
        logger_close();
        config_free(&g_config);
    }
}

// -------------------------------------------------------------
// Intercept getaddrinfo
// -------------------------------------------------------------
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    init_real_functions();

    if (!g_is_targeted_process || !g_config.fake_ip.enabled || !node || node[0] == '\0') {
        return real_getaddrinfo(node, service, hints, res);
    }

    // Check if node is an IP literal or localhost
    struct in_addr in;
    struct in6_addr in6;
    if (inet_pton(AF_INET, node, &in) == 1 ||
        inet_pton(AF_INET6, node, &in6) == 1 ||
        strcasecmp(node, "localhost") == 0 ||
        strcasecmp(node, "localhost.localdomain") == 0) {
        return real_getaddrinfo(node, service, hints, res);
    }

    if (hints && (hints->ai_flags & AI_NUMERICHOST)) {
        return real_getaddrinfo(node, service, hints, res);
    }

    // Allocate / Retrieve FakeIP
    uint32_t fake_ip = fakeip_get_or_create(node);
    if (fake_ip == 0) {
        return real_getaddrinfo(node, service, hints, res);
    }

    uint16_t port = 0;
    if (service) {
        port = atoi(service);
        if (port == 0) {
            if (strcasecmp(service, "https") == 0) port = 443;
            else if (strcasecmp(service, "http") == 0) port = 80;
        }
    }

    *res = fakeip_create_addrinfo(fake_ip, port, hints);
    if (!*res) {
        return real_getaddrinfo(node, service, hints, res);
    }

    return 0;
}

// -------------------------------------------------------------
// Intercept freeaddrinfo
// -------------------------------------------------------------
void freeaddrinfo(struct addrinfo *res) {
    init_real_functions();
    if (fakeip_is_custom_addrinfo(res)) {
        fakeip_free_addrinfo(res);
        return;
    }
    if (real_freeaddrinfo) {
        real_freeaddrinfo(res);
    }
}

// -------------------------------------------------------------
// Intercept gethostbyname
// -------------------------------------------------------------
struct hostent* gethostbyname(const char *name) {
    init_real_functions();

    if (!g_is_targeted_process || !g_config.fake_ip.enabled || !name || name[0] == '\0') {
        return real_gethostbyname(name);
    }

    struct in_addr in;
    if (inet_aton(name, &in) || strcasecmp(name, "localhost") == 0) {
        return real_gethostbyname(name);
    }

    uint32_t fake_ip = fakeip_get_or_create(name);
    if (fake_ip == 0) {
        return real_gethostbyname(name);
    }

    static __thread struct hostent h;
    static __thread char *aliases[1] = {NULL};
    static __thread uint32_t addrs[2] = {0, 0};
    static __thread char *addr_ptrs[2] = {NULL, NULL};
    static __thread char hname[256];

    strncpy(hname, name, sizeof(hname) - 1);
    addrs[0] = htonl(fake_ip);
    addr_ptrs[0] = (char*)&addrs[0];
    addr_ptrs[1] = NULL;

    h.h_name = hname;
    h.h_aliases = aliases;
    h.h_addrtype = AF_INET;
    h.h_length = sizeof(uint32_t);
    h.h_addr_list = addr_ptrs;

    return &h;
}

// -------------------------------------------------------------
// Helper: Check if IP is private
// -------------------------------------------------------------
static bool is_private_ip(uint32_t ip_host_order) {
    // 10.0.0.0/8
    if ((ip_host_order & 0xFF000000) == 0x0A000000) return true;
    // 172.16.0.0/12
    if ((ip_host_order & 0xFFF00000) == 0xAC100000) return true;
    // 192.168.0.0/16
    if ((ip_host_order & 0xFFFF0000) == 0xC0A80000) return true;
    // 169.254.0.0/16 (link local)
    if ((ip_host_order & 0xFFFF0000) == 0xA9FE0000) return true;
    return false;
}

// -------------------------------------------------------------
// Helper: Check if port is allowed
// -------------------------------------------------------------
static bool is_port_allowed(uint16_t port) {
    if (g_config.rules.allowed_ports_count == 0) {
        return true;
    }
    for (int i = 0; i < g_config.rules.allowed_ports_count; i++) {
        if (g_config.rules.allowed_ports[i] == (int)port) {
            return true;
        }
    }
    return false;
}

// -------------------------------------------------------------
// Intercept connect
// -------------------------------------------------------------
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    init_real_functions();

    if (!g_is_targeted_process || !addr) {
        return real_connect(sockfd, addr, addrlen);
    }

    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
        return real_connect(sockfd, addr, addrlen);
    }

    int socktype = 0;
    socklen_t optlen = sizeof(socktype);
    if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socktype, &optlen) == 0) {
        if (socktype != SOCK_STREAM) {
            return real_connect(sockfd, addr, addrlen);
        }
    }

    const char *orig_domain = NULL;
    uint16_t dest_port = 0;
    bool should_proxy = false;

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in*)addr;
        uint32_t ip = ntohl(sin->sin_addr.s_addr);
        dest_port = ntohs(sin->sin_port);

        // Bypass loopback (127.0.0.0/8)
        if ((ip >> 24) == 127) {
            return real_connect(sockfd, addr, addrlen);
        }

        // Check if destination is FakeIP
        if (is_fakeip(ip)) {
            orig_domain = fakeip_get_domain(ip);
            should_proxy = true;
        } else {
            // Check private network
            if (g_config.rules.use_default_private && is_private_ip(ip)) {
                return real_connect(sockfd, addr, addrlen);
            }
            // Normal public IP
            should_proxy = is_port_allowed(dest_port);
        }
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6*)addr;
        dest_port = ntohs(sin6->sin6_port);

        // Bypass loopback (::1)
        static const unsigned char in6_loopback[16] = {
            0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1
        };
        if (memcmp(&sin6->sin6_addr, in6_loopback, 16) == 0) {
            return real_connect(sockfd, addr, addrlen);
        }

        should_proxy = is_port_allowed(dest_port);
    }

    if (!should_proxy) {
        return real_connect(sockfd, addr, addrlen);
    }

    // Avoid proxy loop if target is the proxy server itself
    struct in_addr proxy_in;
    if (inet_aton(g_config.proxy.host, &proxy_in)) {
        if (addr->sa_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in*)addr;
            if (sin->sin_addr.s_addr == proxy_in.s_addr && dest_port == g_config.proxy.port) {
                return real_connect(sockfd, addr, addrlen);
            }
        }
    }

    LOG_DEBUG("[代理/路由] 拦截连接 fd=%d, 目标=%s:%u",
              sockfd, orig_domain ? orig_domain : "(IP目标)", dest_port);

    // Save socket flags & set blocking mode during proxy handshake
    int orig_flags = fcntl(sockfd, F_GETFL, 0);
    if (orig_flags != -1 && (orig_flags & O_NONBLOCK)) {
        fcntl(sockfd, F_SETFL, orig_flags & ~O_NONBLOCK);
    }

    // Set temporary socket timeouts
    struct timeval tv_timeout;
    tv_timeout.tv_sec = g_config.timeout.connect_ms / 1000;
    tv_timeout.tv_usec = (g_config.timeout.connect_ms % 1000) * 1000;
    if (tv_timeout.tv_sec == 0 && tv_timeout.tv_usec == 0) {
        tv_timeout.tv_sec = 5;
    }
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv_timeout, sizeof(tv_timeout));

    // Resolve & Connect to Proxy server
    struct sockaddr_in proxy_sin;
    memset(&proxy_sin, 0, sizeof(proxy_sin));
    proxy_sin.sin_family = AF_INET;
    proxy_sin.sin_port = htons(g_config.proxy.port);

    if (inet_aton(g_config.proxy.host, &proxy_sin.sin_addr) == 0) {
        // Resolve proxy host name directly via system DNS
        struct addrinfo hints, *p_res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (real_getaddrinfo(g_config.proxy.host, NULL, &hints, &p_res) == 0 && p_res) {
            struct sockaddr_in *p_sin = (struct sockaddr_in*)p_res->ai_addr;
            proxy_sin.sin_addr = p_sin->sin_addr;
            real_freeaddrinfo(p_res);
        } else {
            LOG_ERROR("[代理/连接] 无法解析代理服务器域名: %s", g_config.proxy.host);
            if (orig_flags != -1) fcntl(sockfd, F_SETFL, orig_flags);
            errno = ECONNREFUSED;
            return -1;
        }
    }

    int c_res = real_connect(sockfd, (struct sockaddr*)&proxy_sin, sizeof(proxy_sin));
    if (c_res != 0) {
        LOG_WARN("[代理/连接] 连接代理服务器 %s:%u 失败 (errno=%d)",
                 g_config.proxy.host, g_config.proxy.port, errno);
        if (orig_flags != -1) fcntl(sockfd, F_SETFL, orig_flags);
        return -1;
    }

    // Perform Handshake
    int hs_res = -1;
    if (g_config.proxy.type == PROXY_TYPE_HTTP) {
        hs_res = http_handshake(sockfd, orig_domain, dest_port, addr, g_config.timeout.connect_ms);
    } else {
        hs_res = socks5_handshake(sockfd, orig_domain, dest_port, addr, g_config.timeout.connect_ms);
    }

    // Clear temporary timeouts
    struct timeval zero_tv = {0, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &zero_tv, sizeof(zero_tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &zero_tv, sizeof(zero_tv));

    // Restore original socket flags (e.g. O_NONBLOCK)
    if (orig_flags != -1) {
        fcntl(sockfd, F_SETFL, orig_flags);
    }

    if (hs_res == 0) {
        LOG_INFO("[代理/成功] 隧道建立成功: %s:%u (fd=%d)",
                 orig_domain ? orig_domain : "(IP)", dest_port, sockfd);
        return 0;
    } else {
        LOG_WARN("[代理/失败] 代理握手失败: %s:%u",
                 orig_domain ? orig_domain : "(IP)", dest_port);
        errno = ECONNREFUSED;
        return -1;
    }
}
