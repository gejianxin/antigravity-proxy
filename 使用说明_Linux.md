# Antigravity-Proxy Linux 使用说明 (x64 & ARM64)

## 概述
Antigravity-Proxy Linux 版本是专为 Linux 平台（支持 **x86_64 / x64** 与 **AArch64 / ARM64**）打造的进程级透明代理劫持工具。

Windows 版本通过劫持 `version.dll` 拦截 Winsock API，而在 Linux 环境下，本工具通过标准的 **`LD_PRELOAD`** 动态链接库拦截机制（`libantigravity_proxy.so`），无侵入式地挂钩 glibc 的 `connect`、`getaddrinfo`、`freeaddrinfo`、`gethostbyname` 等网络系统调用。

### 核心特性
- **全架构支持**：原生支持 Linux x64（Intel/AMD）与 Linux ARM64（如 树莓派、飞腾、鲲鹏、RK3588、Apple Silicon Linux 虚拟机、UOS/统信、Kylin/麒麟等）。
- **免 TUN 模式**：无需 root 全局虚拟网卡权限，无需开启代理软件的 TUN 模式，仅对目标进程生效。
- **内置 FakeIP 系统**：默认将目标域名在本地分配虚拟保留 IP（`198.18.0.0/15`），彻底规避本地 DNS 污染、DNS 泄露和超时问题。
- **全协议兼容**：支持 SOCKS5（标准域名握手）与 HTTP CONNECT 隧道代理。
- **智能子进程跟随与过滤**：`LD_PRELOAD` 天然被 Linux `fork` / `execve` 子进程继承，Antigravity 主程序与后台语言服务（`language_server`、`node`）均能透明走代理，同时支持 `target_processes` 白名单过滤，防止干扰 `git`、`bash` 等系统命令。

---

## ⚠️ 先看这个：对话报错先排查出口 IP

> **如果 Antigravity 对话时报 `Agent execution terminated due to error`，请先排查代理出口 IP，不要先怀疑代理库未生效。**

常见场景：
- `libantigravity_proxy.so` 已加载成功
- `language_server` 与 `antigravity` 已成功拦截并走 SOCKS5 代理
- 但在 `~/.config/Antigravity/logs/<最新目录>/ls-main.log` 中报出：
  ```text
  FAILED_PRECONDITION (code 400): User location is not supported for the API use.
  ```

**原因分析**：
- 当前代理节点的出口 IP（国家、机房/ASN 属性）被 Google API 服务端拦截。
- 解决办法：更换为优质的**非机房/非数据中心托管/普通 ISP/住宅**代理节点后重试。

---

## 文件结构说明

```text
antigravity-proxy/
├── bin/
│   ├── x64/
│   │   └── libantigravity_proxy.so    # Linux x86_64 专用劫持库
│   └── arm64/
│       └── libantigravity_proxy.so    # Linux AArch64 (ARM64) 专用劫持库
├── config.json                        # 代理与路由配置文件
├── config-web.html                    # 可视化配置网页工具
├── antigravity-proxy.sh               # 智能启动器 (自动识别 CPU 架构)
├── install.sh                         # Linux 一键安装/桌面集成脚本
├── uninstall.sh                       # 一键卸载脚本
├── build.sh / build.ps1               # 本地/交叉编译脚本
├── Makefile                           # 标准构建文件
├── README.md                          # 项目概览与快速参考
├── 使用说明_Linux.md                   # 详细使用手册与排障指南 (本文档)
└── 项目结构与设计说明.md               # 完整目录结构、Rust 内部架构与部署脚本机制剖析
```

---

## 快速开始

### 方式一：一键安装集成（推荐）

1. 打开终端，进入解压后的 `antigravity-proxy` 目录。
2. 运行安装脚本：
   ```bash
   bash install.sh
   ```
   脚本会自动：
   - 识别系统是 `x64` 还是 `arm64`，并部署对应的 `libantigravity_proxy.so`
   - 将配置文件安装到 `~/.config/antigravity-proxy/config.json`
   - 安装快捷命令 `antigravity-proxy` 到 `~/.local/bin/`
   - 自动检测并修补桌面应用菜单中的 `antigravity.desktop`，让点击图标启动也能直接生效！

3. 修改代理端口配置：
   ```bash
   nano ~/.config/antigravity-proxy/config.json
   ```
   将 `proxy.port` 修改为你本地代理软件的端口（如 Clash/Mihomo 默认 `7890` 或 `7898`）。

---

### 方式二：绿色便携模式（针对解压版 Antigravity）

若你有独立的 Antigravity 文件夹（例如 `Antigravity_Linux_x64`）：

1. 运行安装脚本并指定 Antigravity 所在目录：
   ```bash
   bash install.sh /path/to/Antigravity_Linux_x64
   ```
2. 脚本会在该目录下生成 `start-with-proxy.sh` 与配置文件。
3. 启动 Antigravity：
   ```bash
   cd /path/to/Antigravity_Linux_x64
   ./start-with-proxy.sh
   ```

---

### 方式三：使用通用启动器命令运行

无论任何位置，可直接通过 `antigravity-proxy.sh` 包装启动：

```bash
# 自动检测 Antigravity 并启动
./antigravity-proxy.sh

# 或显式指定二进制路径启动
./antigravity-proxy.sh /opt/Antigravity/antigravity

# 代理模式启动 Antigravity 命令行工具 (agy)
./antigravity-proxy.sh agy
```

---

## 验证与自检

运行自带的环境诊断命令：
```bash
./antigravity-proxy.sh --test
```
如果输出类似以下内容，说明动态库加载与 FakeIP 拦截完全正常：
```text
=== Antigravity-Proxy Linux 运行环境诊断 ===
操作系统架构: x86_64 (x64)
代理劫持库:   /.../bin/x64/libantigravity_proxy.so
配置文件路径: /.../config.json

正在测试 FakeIP 与网络重定向拦截...
[Python 测试] 正在请求解析 oauth2.googleapis.com...
[Python 测试] 解析结果 (FakeIP 拦截): [(<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('198.18.0.2', 443))]
=== 诊断完成 ===
```

运行日志会默认记录在当前运行目录的 `proxy.log` 中。

---

## 配置文件说明 (`config.json`)

```jsonc
{
  "log_level": "info",              // 日志等级: debug / info / warn / error
  "traffic_logging": false,         // 是否记录详细流量日志
  "child_injection": true,          // 是否自动代理子进程 (通过 LD_PRELOAD 继承)
  "child_injection_mode": "filtered", // 过滤模式: filtered(按目标进程过滤) / inherit(全部继承)
  "child_injection_exclude": [       // 排除进程列表 (例如编译工具或系统命令)
    "git",
    "bash",
    "sh",
    "which"
  ],
  "target_processes": [             // 目标拦截进程列表 (支持子串匹配)
    "antigravity",
    "language_server",
    "language_server_linux_x64",
    "language_server_linux_arm64",
    "agy",
    "node"
  ],
  "proxy": {
    "host": "127.0.0.1",            // 代理服务器地址
    "port": 7898,                   // 代理服务器端口 (已配置 7898)
    "type": "socks5"                // 协议类型: socks5 或 http
  },
  "fake_ip": {
    "enabled": true,                // 开启 FakeIP (彻底杜绝 DNS 污染)
    "cidr": "198.18.0.0/15"         // 虚拟 IP 网段 (RFC 2544 基准测试保留网段)
  },
  "timeout": {
    "connect": 5000,                // 连接超时 (毫秒)
    "send": 5000,                   // 发送超时 (毫秒)
    "recv": 5000                    // 接收超时 (毫秒)
  },
  "proxy_rules": {
    "allowed_ports": [80, 443],     // 仅代理 80 和 443 端口，空数组表示代理所有端口
    "routing": {
      "use_default_private": true   // 局域网/回环地址 (127.0.0.1, 192.168.x.x, 10.x.x.x 等) 自动直连
    }
  }
}
```

### 常用代理软件端口对照表

| 代理软件 | SOCKS5 端口 | HTTP 端口 | 说明 |
| :--- | :--- | :--- | :--- |
| **Clash / Clash Verge / Mihomo** | `7891` | `7890` (或混合 `7890`/`7898`) | 混合端口同时支持 SOCKS5 / HTTP |
| **V2RayA / V2Ray** | `20170` / `10808` | `20171` / `10809` | 设置页可查看具体端口 |
| **Xray / sing-box** | `2080` / `1080` | `2081` | 自定义配置入站端口 |
| **Shadowsocks** | `1080` | - | 纯 SOCKS5 |

> **提示**：推荐使用 **SOCKS5** 协议，支持直接传输域名，由代理服务器在远端解析，稳定性最佳。

---

## 卸载方法

如需卸载全局注入：
```bash
bash uninstall.sh
```
该命令会自动复原 `.desktop` 桌面快捷方式，并清理相关动态库文件。

---

## 源码重新编译（可选）

本项目已采用 **Rust** 重构，代码位于 `src/`，可通过标准 Cargo 构建：

- **本机编译（使用 Cargo）**：
  ```bash
  cargo build --release
  # 或
  bash build.sh
  ```
- **Windows 下交叉编译 x64 + ARM64 双架构（使用 PowerShell）**：
  ```powershell
  .\build.ps1
  ```
- **Linux 下多架构交叉编译（需安装对应 target）**：
  ```bash
  make x64
  make arm64
  ```
