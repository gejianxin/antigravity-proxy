# Antigravity-Proxy Windows 使用说明 (x64)

## 概述

Windows 运行时是一枚可注入的 `version.dll`，外加启动器 `antigravity-proxy.exe`。它和 Linux 的 `libantigravity_proxy.so` 共用同一套 Rust 核心（FakeIP 环、路由、SOCKS5 / HTTP CONNECT 组包），在 Windows 上改走 Winsock。

桌面版 Antigravity 会按 DLL 搜索顺序加载同目录的 `version.dll`。DLL 把 `version.dll` 的公开导出转发给 `System32\version.dll`，同时改写已加载模块的导入表，并挂钩 `GetProcAddress` / `LoadLibrary*`，从而拦截：

- `connect` / `WSAConnect` / `ConnectEx`（完成端口取出时再做代理握手）
- `getaddrinfo` / `GetAddrInfoW` / `gethostbyname`
- `send` / `recv` / `sendto` / `recvfrom` 以及同步的 `WSASendTo` / `WSARecvFrom`
- `CreateProcessA` / `CreateProcessW`（挂起子进程、注入同一枚 DLL、再恢复）

没有把 MinHook 或参考仓库的 C++ 源码整份拷进来。挂钩是本仓库自己的导入表补丁。

## 文件

```text
bin/windows-x64/
├── version.dll                 # 注入用代理 DLL，放在 Antigravity.exe 旁边
├── antigravity-proxy.exe       # 挂起启动并注入，适合 agy.exe 这类不加载 version.dll 的程序
└── config.json                 # 与 Linux 相同的字段，目标进程是 Windows 名称
```

日志写到 DLL 旁边的 `logs\proxy-YYYYMMDD.log`。该目录不可写时，退到 `%TEMP%\antigravity-proxy-logs\`。

## 桌面版

1. 本地代理监听 SOCKS5（默认按本仓库配置为 `127.0.0.1:7898`，Clash 混合端口请改 `proxy.port` / `proxy.type`）。
2. 把 `version.dll` 和 `config.json` 复制到 `Antigravity.exe` 所在目录。
3. 正常启动 Antigravity。日志里应出现 `Antigravity-Proxy Windows DLL 已加载` 和 `IAT Hook 安装完成`。
4. 子进程（`language_server*.exe`、`node.exe`）由 `CreateProcess` 钩子在挂起状态下注入。

`Antigravity.exe` 更新后可能会清掉安装目录里的 DLL，需要重新复制。

## 命令行 / 任意程序

`agy.exe` 不一定会加载 `version.dll`。用启动器代替搜索顺序劫持：

```bat
bin\windows-x64\antigravity-proxy.exe C:\path\to\agy.exe
bin\windows-x64\antigravity-proxy.exe --dll C:\path\to\version.dll C:\path\to\agy.exe
```

启动器以 `CREATE_SUSPENDED` 创建进程，远程 `LoadLibraryW` 注入 DLL，再恢复主线程。这只应用于你自己启动的 Antigravity 相关程序。

自检（不需要真实代理，只检查 FakeIP）：

```bat
set ANTIGRAVITY_PROXY_FORCE=1
bin\windows-x64\antigravity-proxy.exe --self-test
```

成功时打印 `fakeip 198.18.0.2` 和 `self-test ok`。Wine 下需要 `WINEDLLOVERRIDES=version=n`，否则会加载内置的 `version.dll`。

## 和 Linux 配置的对应关系

两边读同一份 JSON 字段：`proxy`、`fake_ip`、`timeout`、`proxy_rules`（含 `ipv6_mode`、`udp_mode`、`udp_fallback`、`routing`）、`child_injection*`、`target_processes`。

有意保留的平台差异：

| 行为 | Linux | Windows |
| --- | --- | --- |
| `udp_mode=auto` | SOCKS5 时走 `src/udp.rs` 的 UDP Associate | SOCKS5 时代理同步 UDP；HTTP 代理按 `udp_fallback` |
| 端口白名单 | 由 `src/route.rs` 统一判定 | 不在 `allowed_ports` 里的连接直连 |
| 子进程 | 继承 `LD_PRELOAD`，再按进程名过滤 | `CreateProcess` 挂起注入 |
| 重叠 I/O 的 UDP | 未改写 | 默认同 `udp_fallback=block`：重叠 UDP 失败，便于 QUIC 退回已代理的 TCP。设为 `direct` 则原样放行 |

`diagnostics.agent_ip_probe` 会被读入并写进启动日志，本构建不会额外向外探测出口 IP。

## 已知缺口

- 导入表挂钩覆盖进程入口之前就加载好的模块，以及之后的 `GetProcAddress`。如果某个 DLL 在我们安装钩子之前就把函数指针抄进了自己的表，那些调用不会被重定向。支持的加载方式（同目录 `version.dll`，或挂起注入）发生在入口点之前。
- `ConnectEx` 在 `GetQueuedCompletionStatus` / `GetQueuedCompletionStatusEx` 取出完成包时做握手。完成例程（APC）没有单独包一层。
- 每个进程有自己的 FakeIP 环，没有参考实现里的跨进程共享内存。域名解析和 `connect` 通常发生在同一进程。
- 用 MinGW 交叉编译的 DLL 依赖系统自带的 `msvcrt.dll`，不依赖 VC++ 2015-2022 运行库。在 Windows 上用 `build.ps1` 打 MSVC 目标会改用 MSVC 运行库。
- 本仓库的 CI 在 Linux 上编译这枚 DLL，不能在 CI 里对真正的 Antigravity 做注入。Wine 自检只覆盖 FakeIP。

## English

Copy `version.dll` and `config.json` next to `Antigravity.exe`, or launch a process with `antigravity-proxy.exe <program>`. The DLL forwards real `version.dll` exports and redirects Winsock through the shared FakeIP / SOCKS5 / HTTP CONNECT core. See the table above for the Linux/Windows policy differences and the gaps that are not covered by an inline-hook clone of the reference project.
