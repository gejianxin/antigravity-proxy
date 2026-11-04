#include "http.h"
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

int http_handshake(int sockfd, const char *dest_host, uint16_t dest_port,
                   const struct sockaddr *orig_addr, int timeout_ms) {
    char target[300];
    if (dest_host && dest_host[0] != '\0') {
        snprintf(target, sizeof(target), "%s:%u", dest_host, dest_port);
    } else if (orig_addr && orig_addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in*)orig_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        snprintf(target, sizeof(target), "%s:%u", ip, ntohs(sin->sin_port));
    } else if (orig_addr && orig_addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6*)orig_addr;
        char ip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip6, sizeof(ip6));
        snprintf(target, sizeof(target), "[%s]:%u", ip6, ntohs(sin6->sin6_port));
    } else {
        LOG_ERROR("[HTTP] 无效的目标地址");
        return -1;
    }

    char req[512];
    int req_len = snprintf(req, sizeof(req),
                           "CONNECT %s HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "User-Agent: Antigravity-Proxy-Linux/2.4\r\n"
                           "Proxy-Connection: Keep-Alive\r\n\r\n",
                           target, target);

    if (wait_socket_ready(sockfd, POLLOUT, timeout_ms) != 0) {
        LOG_WARN("[HTTP] 套接字不可写 (fd=%d)", sockfd);
        return -1;
    }

    ssize_t sent = send(sockfd, req, req_len, MSG_NOSIGNAL);
    if (sent != req_len) {
        LOG_WARN("[HTTP] 发送 CONNECT 请求失败 (fd=%d)", sockfd);
        return -1;
    }

    // Read response line by line until \r\n\r\n
    char resp[1024];
    size_t resp_len = 0;
    while (resp_len < sizeof(resp) - 1) {
        if (wait_socket_ready(sockfd, POLLIN, timeout_ms) != 0) {
            LOG_WARN("[HTTP] 等待响应超时 (fd=%d)", sockfd);
            return -1;
        }
        ssize_t r = recv(sockfd, resp + resp_len, 1, 0);
        if (r <= 0) {
            if (errno == EINTR) continue;
            LOG_WARN("[HTTP] 读取响应失败 (fd=%d)", sockfd);
            return -1;
        }
        resp_len += r;
        resp[resp_len] = '\0';
        if (resp_len >= 4 && memcmp(resp + resp_len - 4, "\r\n\r\n", 4) == 0) {
            break;
        }
    }

    // Check status code: HTTP/1.x 200
    int status = 0;
    if (sscanf(resp, "HTTP/%*d.%*d %d", &status) == 1) {
        if (status >= 200 && status < 300) {
            LOG_DEBUG("[HTTP] 隧道建立成功: %s (状态码 %d)", target, status);
            return 0;
        }
    }

    LOG_ERROR("[HTTP] 代理拒绝或建立失败: %s (响应: %.40s)", target, resp);
    return -1;
}
