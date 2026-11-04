#include "fakeip.h"
#include "logger.h"
#include <stddef.h>
#include <ctype.h>

#define HASH_BUCKETS 1024

typedef struct fakeip_node {
    uint32_t ip; // host byte order
    char domain[256];
    struct fakeip_node *next_domain;
    struct fakeip_node *next_ip;
} fakeip_node_t;

static fakeip_node_t *s_domain_table[HASH_BUCKETS];
static fakeip_node_t *s_ip_table[HASH_BUCKETS];
static pthread_mutex_t s_fakeip_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint32_t s_fake_net_ip = 0xC6120000;   // 198.18.0.0
static uint32_t s_fake_net_mask = 0xFFFE0000; // /15 (255.254.0.0)
static uint32_t s_current_alloc_ip = 0xC6120002; // starts at 198.18.0.2

static unsigned int hash_str(const char *str) {
    unsigned int hash = 5381;
    int c;
    while ((c = tolower((unsigned char)*str++))) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % HASH_BUCKETS;
}

static unsigned int hash_ip(uint32_t ip) {
    return (ip ^ (ip >> 16)) % HASH_BUCKETS;
}

void fakeip_init(const char *cidr) {
    pthread_mutex_lock(&s_fakeip_mutex);
    if (cidr && cidr[0] != '\0') {
        char buf[64];
        strncpy(buf, cidr, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *slash = strchr(buf, '/');
        if (slash) {
            *slash = '\0';
            int prefix = atoi(slash + 1);
            struct in_addr in;
            if (inet_aton(buf, &in)) {
                s_fake_net_ip = ntohl(in.s_addr);
                if (prefix > 0 && prefix <= 32) {
                    s_fake_net_mask = (0xFFFFFFFFULL << (32 - prefix)) & 0xFFFFFFFF;
                }
                s_current_alloc_ip = (s_fake_net_ip & s_fake_net_mask) + 2;
            }
        }
    }
    struct in_addr net_addr;
    net_addr.s_addr = htonl(s_fake_net_ip);
    LOG_INFO("[FakeIP] 初始化完成: CIDR=%s, 基础网段=%s", cidr ? cidr : "198.18.0.0/15", inet_ntoa(net_addr));
    pthread_mutex_unlock(&s_fakeip_mutex);
}

bool is_fakeip(uint32_t ip_host_order) {
    return (ip_host_order & s_fake_net_mask) == (s_fake_net_ip & s_fake_net_mask);
}

uint32_t fakeip_get_or_create(const char *domain) {
    if (!domain || domain[0] == '\0') {
        return 0;
    }

    pthread_mutex_lock(&s_fakeip_mutex);

    unsigned int h_domain = hash_str(domain);
    fakeip_node_t *node = s_domain_table[h_domain];
    while (node) {
        if (strcasecmp(node->domain, domain) == 0) {
            uint32_t ip = node->ip;
            pthread_mutex_unlock(&s_fakeip_mutex);
            return ip;
        }
        node = node->next_domain;
    }

    // Allocate next sequential IP in pool
    uint32_t allocated_ip = s_current_alloc_ip++;
    // Avoid network/broadcast addresses
    if ((allocated_ip & ~s_fake_net_mask) == 0 || (allocated_ip & ~s_fake_net_mask) == (~s_fake_net_mask)) {
        allocated_ip = s_current_alloc_ip++;
    }

    // Wrap around if exceeded CIDR pool
    if ((allocated_ip & s_fake_net_mask) != (s_fake_net_ip & s_fake_net_mask)) {
        s_current_alloc_ip = (s_fake_net_ip & s_fake_net_mask) + 2;
        allocated_ip = s_current_alloc_ip++;
    }

    node = (fakeip_node_t*)malloc(sizeof(fakeip_node_t));
    if (!node) {
        pthread_mutex_unlock(&s_fakeip_mutex);
        return 0;
    }

    node->ip = allocated_ip;
    strncpy(node->domain, domain, sizeof(node->domain) - 1);
    node->domain[sizeof(node->domain) - 1] = '\0';

    node->next_domain = s_domain_table[h_domain];
    s_domain_table[h_domain] = node;

    unsigned int h_ip = hash_ip(allocated_ip);
    node->next_ip = s_ip_table[h_ip];
    s_ip_table[h_ip] = node;

    struct in_addr in;
    in.s_addr = htonl(allocated_ip);
    LOG_DEBUG("[FakeIP] 分配虚拟 IP: %s -> %s", domain, inet_ntoa(in));

    pthread_mutex_unlock(&s_fakeip_mutex);
    return allocated_ip;
}

const char* fakeip_get_domain(uint32_t ip_host_order) {
    if (!is_fakeip(ip_host_order)) {
        return NULL;
    }

    pthread_mutex_lock(&s_fakeip_mutex);
    unsigned int h_ip = hash_ip(ip_host_order);
    fakeip_node_t *node = s_ip_table[h_ip];
    while (node) {
        if (node->ip == ip_host_order) {
            pthread_mutex_unlock(&s_fakeip_mutex);
            return node->domain;
        }
        node = node->next_ip;
    }
    pthread_mutex_unlock(&s_fakeip_mutex);
    return NULL;
}

struct addrinfo* fakeip_create_addrinfo(uint32_t fake_ip_host_order, uint16_t port, const struct addrinfo *hints) {
    struct fake_ai_container *cont = (struct fake_ai_container*)calloc(1, sizeof(struct fake_ai_container));
    if (!cont) {
        return NULL;
    }

    cont->magic = FAKE_IP_MAGIC;
    cont->sin.sin_family = AF_INET;
    cont->sin.sin_port = htons(port);
    cont->sin.sin_addr.s_addr = htonl(fake_ip_host_order);

    cont->ai.ai_flags = hints ? hints->ai_flags : 0;
    cont->ai.ai_family = AF_INET;
    cont->ai.ai_socktype = hints && hints->ai_socktype ? hints->ai_socktype : SOCK_STREAM;
    cont->ai.ai_protocol = hints && hints->ai_protocol ? hints->ai_protocol : IPPROTO_TCP;
    cont->ai.ai_addrlen = sizeof(struct sockaddr_in);
    cont->ai.ai_addr = (struct sockaddr*)&cont->sin;
    cont->ai.ai_canonname = NULL;
    cont->ai.ai_next = NULL;

    return &cont->ai;
}

bool fakeip_is_custom_addrinfo(const struct addrinfo *ai) {
    if (!ai) return false;
    struct fake_ai_container *cont = (struct fake_ai_container*)((char*)ai - offsetof(struct fake_ai_container, ai));
    return cont->magic == FAKE_IP_MAGIC;
}

void fakeip_free_addrinfo(struct addrinfo *ai) {
    if (!ai) return;
    struct fake_ai_container *cont = (struct fake_ai_container*)((char*)ai - offsetof(struct fake_ai_container, ai));
    if (cont->magic == FAKE_IP_MAGIC) {
        cont->magic = 0; // Invalidate
        free(cont);
    }
}
