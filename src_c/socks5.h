#ifndef SOCKS5_H
#define SOCKS5_H

#include "antigravity_proxy.h"

int socks5_handshake(int sockfd, const char *dest_host, uint16_t dest_port,
                     const struct sockaddr *orig_addr, int timeout_ms);

#endif /* SOCKS5_H */
