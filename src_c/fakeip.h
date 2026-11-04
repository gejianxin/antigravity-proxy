#ifndef FAKEIP_H
#define FAKEIP_H

#include "antigravity_proxy.h"

struct fake_ai_container {
    uint64_t magic;
    struct addrinfo ai;
    struct sockaddr_in sin;
};

void fakeip_init(const char *cidr);
bool is_fakeip(uint32_t ip_host_order);
uint32_t fakeip_get_or_create(const char *domain);
const char* fakeip_get_domain(uint32_t ip_host_order);

struct addrinfo* fakeip_create_addrinfo(uint32_t fake_ip_host_order, uint16_t port, const struct addrinfo *hints);
bool fakeip_is_custom_addrinfo(const struct addrinfo *ai);
void fakeip_free_addrinfo(struct addrinfo *ai);

#endif /* FAKEIP_H */
