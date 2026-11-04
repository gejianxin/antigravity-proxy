# Antigravity-Proxy (Rust, Linux / Windows / macOS)

[![Language](https://img.shields.io/badge/language-Rust%202021-red.svg)](#)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20x64%20%7C%20macOS-blue.svg)](#)
[![Protocol](https://img.shields.io/badge/protocol-SOCKS5%20%7C%20HTTP-green.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](#)

本工具为 Google Antigravity（以及相关 `language_server`、`agy` CLI 等）提供**免 TUN** 的进程级透明代理。

| 平台 | 产物 | 加载方式 |
| --- | --- | --- |
| Linux x64 | `bin/x64/libantigravity_proxy.so` + `config.json` | `LD_PRELOAD` |
| Linux arm64 | `bin/arm64/libantigravity_proxy.so` + `config.json` | `LD_PRELOAD` |
| Windows x64 | `bin/windows-x64/version.dll` + `config.json` | 放在 `Antigravity.exe` 同目录，由 DLL 搜索顺序加载 |
| macOS arm64 / x64 | `bin/macos-arm64` 或 `bin/macos-x64` 的 `libantigravity_proxy.dylib` + `config.json` | `DYLD_INSERT_LIBRARIES`，直接执行 .app 内的 Mach-O |

Linux 侧是 Rust `cdylib`。Windows 日常部署只放 `version.dll` 和 `config.json`。macOS 用 dyld 插入 dylib，不用 `open -a`，也不是把库塞进 App 包里冒充系统库。dylib 在 GitHub Actions 的 macOS runner 上编译。协议与路由决策在 `crates/agy-core`。参考仓库 [yuaotian/antigravity-proxy](https://github.com/yuaotian/antigravity-proxy) 的许可证与本仓库的 MIT 许可证相互独立；本仓库不包含其 MinHook 或 Windows C/C++ 源码。

English: Linux uses `LD_PRELOAD` with `libantigravity_proxy.so` and `config.json` in the same directory. Windows copies `version.dll` and `config.json` next to `Antigravity.exe`. macOS inserts `libantigravity_proxy.dylib` with `DYLD_INSERT_LIBRARIES` by executing the Mach-O inside the `.app`, and keeps `config.json` beside the dylib. See [使用说明_macOS.md](./使用说明_macOS.md). SIP and Hardened Runtime can ignore that variable; injection into the real Antigravity app was not verified here. Build and install copy a default `config.json` only when that file is absent.

## 目录索引
- [Linux 使用说明](./使用说明_Linux.md)
- [Windows 使用说明](./使用说明_Windows.md)
- [macOS 使用说明](./使用说明_macOS.md)
- [项目结构与设计说明](./项目结构与设计说明.md)
- [可视化配置工具](./config-web.html)

## 当前能力
1. **glibc 拦截**：`connect`、`getaddrinfo`、`freeaddrinfo`、`gethostbyname`，以及 UDP 路径上的 `send` / `sendto` / `sendmsg` / `sendmmsg` / `recv` / `recvfrom` / `recvmsg` / `recvmmsg` / `close`。
2. **FakeIP**：把域名映射到 `198.18.0.0/15`。地址池回绕时会同时删除旧的域名和 IP 映射。仅请求 IPv6 的解析会得到 `::ffff:` 形式的 IPv4-mapped 地址，`freeaddrinfo` 交给系统 libc。
3. **连接语义**：不修改套接字的 `O_NONBLOCK`，也不清掉应用自己的收发超时。非阻塞 `connect` 会在代理握手完成后返回成功。
4. **SOCKS5 与 HTTP CONNECT**：TCP 走 CONNECT；`udp_mode=auto` 且代理类型为 SOCKS5 时，UDP 走 UDP Associate。不支持代理用户名/密码（与参考实现一样，只协商无认证）。
5. **分流**：`allowed_ports`、`dns_mode`、`ipv6_mode`、`udp_mode` / `udp_fallback`，以及 `routing.rules`（域名通配、IPv4/IPv6 CIDR、端口、协议、`order` / `number` 优先级）。
6. **子进程**：Linux 默认继承 `LD_PRELOAD`。`child_injection=false` 时从 `exec*` / `posix_spawn*` 去掉本库。Windows 由 `CreateProcess` 钩子注入。macOS 上未受 SIP 保护的子进程继承 `DYLD_INSERT_LIBRARIES`；`child_injection=false` 时从 `execve` / `posix_spawn` 去掉本 dylib。
7. **日志**：Linux 写到配置文件同目录的 `proxy.log`（可用 `ANTIGRAVITY_PROXY_LOG` 覆盖）。启动时若日志超过 5MB 会轮转到 `proxy.log.1`。Windows 写到 DLL 旁的 `logs\proxy-YYYYMMDD.log`。macOS 写到 dylib 旁的 `logs/`，失败则写到 `~/Library/Logs/antigravity-proxy/`。

`bin/x64` 与 `bin/arm64` 里是重新编译的 `.so`，旁边有一份 `config.json`。Windows 桌面版用 `bin/windows-x64/` 里的 `version.dll` 和 `config.json`。macOS 的 dylib 由 Actions 的 macOS runner 产出，工件里同时带上该目录的 `config.json`，不进 Linux 交叉编译。构建脚本只在目录里还没有 `config.json` 时从仓库根目录复制，不会盖掉已经改过的文件。

## 快速使用

### macOS

在 Mac 上 `cargo build --release -p macos-proxy`，或把 Actions 工件里的 dylib 和 `config.json` 放到 `bin/macos-arm64/`（Intel 为 `bin/macos-x64/`），然后：

```bash
./antigravity-proxy-macos.sh "/Applications/Antigravity.app/Contents/MacOS/Antigravity"
```

不要用 `open -a`。若签名拒绝插入，见 [使用说明_macOS.md](./使用说明_macOS.md)。`--test` 只检查 FakeIP，不启动 Antigravity。

### Windows

把 `bin/windows-x64/version.dll` 和 `bin/windows-x64/config.json` 复制到 `Antigravity.exe` 所在目录，然后照常启动 Antigravity。不需要运行 `antigravity-proxy.exe`。端口和规则在旁边的 `config.json` 里改。细节见 [使用说明_Windows.md](./使用说明_Windows.md)。

### Linux

```bash
# 1. 运行自检测试（FakeIP、非阻塞 connect、UDP 阻断、子进程环境）
cargo test
cargo build --release
bash scripts/smoke.sh target/release/libantigravity_proxy.so

# 2. 一键安装
bash install.sh

# 3. 启动 Antigravity（后台运行，脚本立刻返回，关闭终端不会结束进程）
./antigravity-proxy.sh
```

详细配置与故障排查请参见 [使用说明_Linux.md](./使用说明_Linux.md)。
