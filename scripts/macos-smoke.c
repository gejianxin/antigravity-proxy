#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

/* Unsigned local binary. SIP does not block DYLD_INSERT_LIBRARIES here. */
int main(void) {
    struct addrinfo *res = NULL;
    int rc = getaddrinfo("oauth2.googleapis.com", "443", NULL, &res);
    if (rc != 0 || res == NULL || res->ai_addr == NULL) {
        fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(rc));
        return 1;
    }
    char ip[INET6_ADDRSTRLEN] = {0};
    if (res->ai_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof ip);
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)res->ai_addr;
        inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof ip);
    }
    printf("resolved %s\n", ip);
    freeaddrinfo(res);
    if (strncmp(ip, "198.18.", 7) != 0 && strstr(ip, "198.18.") == NULL) {
        fprintf(stderr, "expected FakeIP 198.18.0.0/15, got %s\n", ip);
        return 1;
    }
    return 0;
}
