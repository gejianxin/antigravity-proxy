#include "socks5.h"
#include "logger.h"
#include <sys/poll.h>

static int wait_socket_ready(int sockfd, short events, int timeout_ms) {
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = events;
    pfd.revents = 0;
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret > 0 && (pfd.revents & events)) {
        return 0;
    }
    return -1;
}

static int send_all(int sockfd, const void *buf, size_t len, int timeout_ms) {
    const char *p = (const char*)buf;
    size_t total = 0;
    while (total < len) {
        if (wait_socket_ready(sockfd, POLLOUT, timeout_ms) != 0) {
            return -1;
        }
        ssize_t sent = send(sockfd, p + total, len - total, MSG_NOSIGNAL);
        if (sent <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += sent;
    }
    return 0;
}

static int recv_exact(int sockfd, void *buf, size_t len, int timeout_ms) {
    char *p = (char*)buf;
    size_t total = 0;
    while (total < len) {
        if (wait_socket_ready(sockfd, POLLIN, timeout_ms) != 0) {
            return -1;
        }
        ssize_t recvd = recv(sockfd, p + total, len - total, 0);
        if (recvd <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += recvd;
    }
    return 0;
}

int socks5_handshake(int sockfd, const char *dest_host, uint16_t dest_port,
                     const struct sockaddr *orig_addr, int timeout_ms) {
    // 1. Send SOCKS5 Greeting (VER=5, NMETHODS=1, METHOD=0[No Auth])
    unsigned char greeting[3] = {0x05, 0x01, 0x00};
    if (send_all(sockfd, greeting, 3, timeout_ms) != 0) {
        LOG_WARN("[SOCKS5] 发送握手问候失败 (fd=%d)", sockfd);
        return -1;
    }

    // 2. Read Greeting Response
    unsigned char greeting_resp[2];
    if (recv_exact(sockfd, greeting_resp, 2, timeout_ms) != 0) {
        LOG_WARN("[SOCKS5] 接收握手响应失败 (fd=%d)", sockfd);
        return -1;
    }

    if (greeting_resp[0] != 0x05 || greeting_resp[1] != 0x00) {
        LOG_ERROR("[SOCKS5] 代理服务器拒绝或要求身份认证: 0x%02X 0x%02X",
                  greeting_resp[0], greeting_resp[1]);
        return -1;
    }

    // 3. Build SOCKS5 Connect Request
    unsigned char req[300];
    size_t req_len = 0;
    req[0] = 0x05; // VER
    req[1] = 0x01; // CMD: CONNECT
    req[2] = 0x00; // RSV

    if (dest_host && dest_host[0] != '\0') {
        // Domain Name
        size_t dlen = strlen(dest_host);
        if (dlen > 255) dlen = 255;
        req[3] = 0x03; // ATYP: DOMAINNAME
        req[4] = (unsigned char)dlen;
        memcpy(&req[5], dest_host, dlen);
        req_len = 5 + dlen;
        uint16_t n_port = htons(dest_port);
        memcpy(&req[req_len], &n_port, 2);
        req_len += 2;
        LOG_DEBUG("[SOCKS5] 建立连接 -> 目标域名: %s:%u", dest_host, dest_port);
    } else if (orig_addr && orig_addr->sa_family == AF_INET) {
        // IPv4
        const struct sockaddr_in *sin = (const struct sockaddr_in*)orig_addr;
        req[3] = 0x01; // ATYP: IPv4
        memcpy(&req[4], &sin->sin_addr, 4);
        memcpy(&req[8], &sin->sin_port, 2);
        req_len = 10;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
        LOG_DEBUG("[SOCKS5] 建立连接 -> 目标 IPv4: %s:%u", ip_str, ntohs(sin->sin_port));
    } else if (orig_addr && orig_addr->sa_family == AF_INET6) {
        // IPv6
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6*)orig_addr;
        req[3] = 0x04; // ATYP: IPv6
        memcpy(&req[4], &sin6->sin6_addr, 16);
        memcpy(&req[20], &sin6->sin6_port, 2);
        req_len = 22;
        char ip6_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip6_str, sizeof(ip6_str));
        LOG_DEBUG("[SOCKS5] 建立连接 -> 目标 IPv6: [%s]:%u", ip6_str, ntohs(sin6->sin6_port));
    } else {
        LOG_ERROR("[SOCKS5] 无效的目标地址");
        return -1;
    }

    if (send_all(sockfd, req, req_len, timeout_ms) != 0) {
        LOG_WARN("[SOCKS5] 发送 CONNECT 请求失败 (fd=%d)", sockfd);
        return -1;
    }

    // 4. Read SOCKS5 Connect Response
    // Header: VER(1), REP(1), RSV(1), ATYP(1)
    unsigned char resp_hdr[4];
    if (recv_exact(sockfd, resp_hdr, 4, timeout_ms) != 0) {
        LOG_WARN("[SOCKS5] 接收 CONNECT 响应头失败 (fd=%d)", sockfd);
        return -1;
    }

    if (resp_hdr[0] != 0x05) {
        LOG_ERROR("[SOCKS5] 响应版本错误: 0x%02X", resp_hdr[0]);
        return -1;
    }

    if (resp_hdr[1] != 0x00) {
        LOG_ERROR("[SOCKS5] 代理连接失败, 错误码: 0x%02X", resp_hdr[1]);
        return -1;
    }

    // Drain bound address and port
    int atyp = resp_hdr[3];
    size_t to_drain = 0;
    if (atyp == 0x01) {
        // IPv4 (4 bytes) + Port (2 bytes) = 6
        to_drain = 6;
    } else if (atyp == 0x04) {
        // IPv6 (16 bytes) + Port (2 bytes) = 18
        to_drain = 18;
    } else if (atyp == 0x03) {
        // Domain len (1 byte)
        unsigned char dlen = 0;
        if (recv_exact(sockfd, &dlen, 1, timeout_ms) != 0) return -1;
        to_drain = dlen + 2; // Domain + Port (2 bytes)
    } else {
        LOG_ERROR("[SOCKS5] 未知 ATYP: 0x%02X", atyp);
        return -1;
    }

    unsigned char drain_buf[300];
    if (to_drain > sizeof(drain_buf)) to_drain = sizeof(drain_buf);
    if (recv_exact(sockfd, drain_buf, to_drain, timeout_ms) != 0) {
        LOG_WARN("[SOCKS5] 接收绑定地址失败");
        return -1;
    }

    return 0; // Success!
}
