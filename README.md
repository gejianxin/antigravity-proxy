# Antigravity-Proxy for Linux (Rust, x64 & ARM64)

[![Language](https://img.shields.io/badge/language-Rust%202021-red.svg)](#)
[![Platform](https://img.shields.io/badge/platform-Linux%20x64%20%7C%20ARM64-blue.svg)](#)
[![Protocol](https://img.shields.io/badge/protocol-SOCKS5%20%7C%20HTTP-green.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](#)

本工具为 Google Antigravity（以及相关 `language_server`、`agy` CLI 等）在 **Linux x64 (x86_64)** 与 **Linux ARM64 (aarch64)** 上提供**免 TUN** 的进程级透明代理。它是一个 `LD_PRELOAD` 的 Rust `cdylib`（`libantigravity_proxy.so`），不替换系统 glibc。

路由、FakeIP 环形地址池、IPv6/UDP 策略和 SOCKS5 UDP Associate 的行为参考了 Windows 项目 [yuaotian/antigravity-proxy](https://github.com/yuaotian/antigravity-proxy)，并按 Linux 拦截模型重新实现。该参考仓库的许可证与本仓库的 MIT 许可证相互独立；本仓库不包含其 MinHook 或 Windows 源码。

## 目录索引
- [使用说明 (完整手册)](./使用说明_Linux.md)
- [项目结构与设计说明 (架构)](./项目结构与设计说明.md)
- [可视化配置工具](./config-web.html)

## 当前能力
1. **glibc 拦截**：`connect`、`getaddrinfo`、`freeaddrinfo`、`gethostbyname`，以及 UDP 路径上的 `send` / `sendto` / `sendmsg` / `sendmmsg` / `recv` / `recvfrom` / `recvmsg` / `recvmmsg` / `close`。
2. **FakeIP**：把域名映射到 `198.18.0.0/15`。地址池回绕时会同时删除旧的域名和 IP 映射。仅请求 IPv6 的解析会得到 `::ffff:` 形式的 IPv4-mapped 地址，`freeaddrinfo` 交给系统 libc。
3. **连接语义**：不修改套接字的 `O_NONBLOCK`，也不清掉应用自己的收发超时。非阻塞 `connect` 会在代理握手完成后返回成功。
4. **SOCKS5 与 HTTP CONNECT**：TCP 走 CONNECT；`udp_mode=auto` 且代理类型为 SOCKS5 时，UDP 走 UDP Associate。不支持代理用户名/密码（与参考实现一样，只协商无认证）。
5. **分流**：`allowed_ports`、`dns_mode`、`ipv6_mode`、`udp_mode` / `udp_fallback`，以及 `routing.rules`（域名通配、IPv4/IPv6 CIDR、端口、协议、`order` / `number` 优先级）。
6. **子进程**：默认继承 `LD_PRELOAD`，每个进程按 `target_processes` / `child_injection_exclude` 自己决定要不要拦截。`child_injection=false` 时，`exec*` / `posix_spawn*` 会从环境里去掉本库。
7. **日志**：写到配置文件同目录的 `proxy.log`（可用 `ANTIGRAVITY_PROXY_LOG` 覆盖），不再依赖进程的当前工作目录。启动时若日志超过 5MB 会轮转到 `proxy.log.1`。

`bin/x64/libantigravity_proxy.so` 是在 x86_64 上重新编译的。`bin/arm64/libantigravity_proxy.so` 需要本机执行 `make arm64`（或在 Windows 上执行 `build.ps1`）后才会带上同样的逻辑。

## 快速使用

```bash
# 1. 运行自检测试（FakeIP、非阻塞 connect、UDP 阻断、子进程环境）
cargo test
cargo build --release
bash scripts/smoke.sh target/release/libantigravity_proxy.so

# 2. 一键安装
bash install.sh

# 3. 启动 Antigravity
./antigravity-proxy.sh
```

详细配置与故障排查请参见 [使用说明_Linux.md](./使用说明_Linux.md)。
