# Antigravity-Proxy for Linux (Rust 重构版, x64 & ARM64)

[![Language](https://img.shields.io/badge/language-Rust%202021-red.svg)](#)
[![Platform](https://img.shields.io/badge/platform-Linux%20x64%20%7C%20ARM64-blue.svg)](#)
[![Protocol](https://img.shields.io/badge/protocol-SOCKS5%20%7C%20HTTP-green.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](#)

本工具为 Google Antigravity（以及相关 `language_server`、`agy` CLI 等）在 **Linux x64 (x86_64)** 与 **Linux ARM64 (aarch64)** 平台提供**免 TUN 模式**的进程级网络透明代理劫持方案。

本项目已完全采用 **Rust** 重构，具备极致的内存安全性、高并发线程安全（`RwLock` / `OnceLock`）与高性能零成本抽象。

## 目录索引
- [使用说明 (完整手册)](./使用说明_Linux.md)
- [项目结构与设计说明 (架构深度剖析)](./项目结构与设计说明.md)
- [可视化配置工具](./config-web.html)

## Rust 重构亮点与技术特性
1. **内存安全与线程安全**：全面使用 Rust 编写，杜绝野指针、内存越界与竞态条件；FakeIP 虚拟 DNS 映射基于 `std::sync::RwLock<FakeIpPool>` 与安全 哈希表管理。
2. **零运行时依赖**：编译为标准的 `cdylib` 动态库，仅依赖系统的 libc。
3. **网络精准拦截**：通过 `LD_PRELOAD` 劫持 glibc 的 `connect`、`getaddrinfo`、`freeaddrinfo`、`gethostbyname`。
4. **FakeIP 虚拟 DNS**：拦截域名解析，本地虚拟映射至 `198.18.0.0/15` 保留网段，在 `connect` 时还原为原始域名并通过 SOCKS5 远端解析，避免本地 DNS 污染与解析失败。
5. **子进程继承**：Linux 进程派生自动保留环境变量，天然支持 `language_server`、`node` 子进程代理。
6. **双架构二进制就绪**：预编译提供 `bin/x64/libantigravity_proxy.so` 与 `bin/arm64/libantigravity_proxy.so`。

## 快速使用

```bash
# 1. 运行自检测试
./antigravity-proxy.sh --test

# 2. 一键安装
bash install.sh

# 3. 启动 Antigravity
./antigravity-proxy.sh
```

详细配置与故障排查请参见 [使用说明_Linux.md](./使用说明_Linux.md)。
