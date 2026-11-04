# Antigravity-Proxy Windows 使用说明 (x64)

## 概述

桌面版的用法和参考项目一样：把 `version.dll` 和 `config.json` 放在 `Antigravity.exe` 旁边。Antigravity 按 DLL 搜索顺序加载这份 `version.dll`。它把 `version.dll` 的公开导出转发给 `System32\version.dll`，同时改写导入表并挂钩 `GetProcAddress` / `LoadLibrary*`，从而拦截：

- `connect` / `WSAConnect` / `ConnectEx`（完成端口取出时再做代理握手）
- `getaddrinfo` / `GetAddrInfoW` / `gethostbyname`
- `send` / `recv` / `sendto` / `recvfrom` 以及同步的 `WSASendTo` / `WSARecvFrom`
- `CreateProcessA` / `CreateProcessW`（挂起子进程、注入同一枚 DLL、再恢复）

没有把 MinHook 或参考仓库的 C++ 源码整份拷进来。挂钩是本仓库自己的导入表补丁。

日常使用不需要 `antigravity-proxy.exe`。那个启动器是可选项，只在目标程序不会自己加载 `version.dll`、或者你要对任意 exe 做挂起注入时才用。见文末「可选：启动器」。

## 部署（推荐）

1. 本地代理监听 SOCKS5（默认按本仓库配置为 `127.0.0.1:7898`。Clash 混合端口请改 `config.json` 里的 `proxy.port` / `proxy.type`）。
2. 从 `bin/windows-x64/` 只复制这两个文件到 `Antigravity.exe` 所在目录：
   - `version.dll`
   - `config.json`
3. 像平时一样启动 Antigravity。不要经过别的启动器。
4. 日志里应出现 `Antigravity-Proxy Windows DLL 已加载` 和 `IAT Hook 安装完成`。子进程（`language_server*.exe`、`node.exe`）由 DLL 里的 `CreateProcess` 钩子在挂起状态下注入。

```text
Antigravity 安装目录/
├── Antigravity.exe
├── version.dll      ← 放这里
└── config.json      ← 放这里
```

日志写到 DLL 旁边的 `logs\proxy-YYYYMMDD.log`。该目录不可写时，退到 `%TEMP%\antigravity-proxy-logs\`。

`Antigravity.exe` 更新后可能会清掉安装目录里的 DLL，需要重新复制这两个文件。

## 和 Linux 配置的对应关系

两边读同一份 JSON 字段：`proxy`、`fake_ip`、`timeout`、`proxy_rules`（含 `ipv6_mode`、`udp_mode`、`udp_fallback`、`routing`）、`child_injection*`、`target_processes`。

有意保留的平台差异：

| 行为 | Linux | Windows |
| --- | --- | --- |
| `udp_mode=auto` | SOCKS5 时走 `src/udp.rs` 的 UDP Associate | SOCKS5 时代理同步 UDP；HTTP 代理按 `udp_fallback` |
| 端口白名单 | 由 `src/route.rs` 统一判定 | 不在 `allowed_ports` 里的连接直连 |
| 子进程 | 继承 `LD_PRELOAD`，再按进程名过滤 | `version.dll` 里的 `CreateProcess` 钩子挂起注入 |
| 重叠 I/O 的 UDP | 未改写 | 默认同 `udp_fallback=block`：重叠 UDP 失败，便于 QUIC 退回已代理的 TCP。设为 `direct` 则原样放行 |

`diagnostics.agent_ip_probe` 会被读入并写进启动日志，本构建不会额外向外探测出口 IP。

## 已知缺口

- 导入表挂钩覆盖进程入口之前就加载好的模块，以及之后的 `GetProcAddress`。如果某个 DLL 在我们安装钩子之前就把函数指针抄进了自己的表，那些调用不会被重定向。同目录 `version.dll` 会在进程入口之前装上钩子。
- `ConnectEx` 在 `GetQueuedCompletionStatus` / `GetQueuedCompletionStatusEx` 取出完成包时做握手。完成例程（APC）没有单独包一层。
- 每个进程有自己的 FakeIP 环，没有参考实现里的跨进程共享内存。域名解析和 `connect` 通常发生在同一进程。
- 用 MinGW 交叉编译的 DLL 依赖系统自带的 `msvcrt.dll`，不依赖 VC++ 2015-2022 运行库。在 Windows 上用 `build.ps1` 打 MSVC 目标会改用 MSVC 运行库。
- 本仓库的 CI 在 Linux 上编译这枚 DLL，不能在 CI 里对真正的 Antigravity 做注入。

## 可选：启动器

`bin/windows-x64/antigravity-proxy.exe` 不是桌面版的安装步骤。只有下面两种情况才用它：

- 目标程序（例如某些 `agy.exe`）不会按搜索顺序加载旁边的 `version.dll`
- 你要自己对一个任意 exe 做挂起创建，再把 DLL 注入进去

```bat
bin\windows-x64\antigravity-proxy.exe C:\path\to\agy.exe
bin\windows-x64\antigravity-proxy.exe --dll C:\path\to\version.dll C:\path\to\agy.exe
```

启动器以 `CREATE_SUSPENDED` 创建进程，远程 `LoadLibraryW` 注入 DLL，再恢复主线程。这只应用于你自己启动的程序。

开发自检（不需要真实代理，只检查 FakeIP；日常使用不用跑）：

```bat
set ANTIGRAVITY_PROXY_FORCE=1
bin\windows-x64\antigravity-proxy.exe --self-test
```

成功时打印 `fakeip 198.18.0.2` 和 `self-test ok`。Wine 下需要 `WINEDLLOVERRIDES=version=n`，否则会加载内置的 `version.dll`。

## English

Normal install: copy `version.dll` and `config.json` into the folder that contains `Antigravity.exe`, then start Antigravity the way you usually do. Do not run a launcher. The DLL forwards real `version.dll` exports and redirects Winsock. Child processes are injected by the `CreateProcess` hook inside that DLL.

`antigravity-proxy.exe` is optional. Use it only when the target does not load `version.dll` by itself, or when you want suspended-process injection into some other executable. `--self-test` is a developer check, not part of setup.
