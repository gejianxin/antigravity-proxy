#ifndef HTTP_H
#define HTTP_H

#include "antigravity_proxy.h"

int http_handshake(int sockfd, const char *dest_host, uint16_t dest_port,
                   const struct sockaddr *orig_addr, int timeout_ms);

#endif /* HTTP_H */
