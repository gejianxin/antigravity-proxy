# Antigravity-Proxy macOS 使用说明 (Apple Silicon 优先，另有 x86_64)

## 部署

macOS 没有 Linux 的 `LD_PRELOAD`，也没有 Windows 那种把 `version.dll` 放在 exe 旁边的搜索顺序劫持。加载方式是 dyld 的 `DYLD_INSERT_LIBRARIES`：启动 **.app 里面的 Mach-O**，而不是用 `open -a`。`open` 会丢掉 `DYLD_*` 环境变量。

1. 在 Mac 上编译，或从 GitHub Actions 的 `macos` 工件下载 dylib 和同目录的 `config.json`：
   - Apple Silicon：`bin/macos-arm64/libantigravity_proxy.dylib` 与 `config.json`
   - Intel：`bin/macos-x64/libantigravity_proxy.dylib` 与 `config.json`
2. 按本机代理改旁边 `config.json` 的 `proxy.port` / `proxy.type`（默认 `127.0.0.1:7898`）。构建和安装只在这个文件不存在时写入默认配置，不会覆盖你改过的内容。
3. 启动：

```bash
./antigravity-proxy-macos.sh
# 或显式给出可执行文件（不要传 .app 包本身）
./antigravity-proxy-macos.sh "/Applications/Antigravity.app/Contents/MacOS/Antigravity"
```

脚本会设置 `DYLD_INSERT_LIBRARIES` 和 `ANTIGRAVITY_PROXY_CONFIG`，把进程放到后台后立刻返回。关闭终端不会结束它。输出追加到 `~/.local/state/antigravity-proxy/launch.log`。库自己的日志在 dylib 旁边的 `logs/proxy-YYYYMMDD.log`，写不了就到 `~/Library/Logs/antigravity-proxy/`。

需要留在终端里看输出时：

```bash
./antigravity-proxy-macos.sh --foreground
```

只检查 dylib 能不能拦住 `getaddrinfo`（不启动 Antigravity）：

```bash
./antigravity-proxy-macos.sh --test
```

这会编译一个无签名的小程序，再用 `DYLD_INSERT_LIBRARIES` 跑它。成功时打印 `198.18.` 网段的 FakeIP。

在 Mac 上自己编译：

```bash
cargo build --release -p macos-proxy
# Intel 切片（Apple Silicon 上若 SDK 允许）
rustup target add x86_64-apple-darwin
cargo build --release --target x86_64-apple-darwin -p macos-proxy
```

Linux 云主机没有 Apple SDK，不要从 Linux 交叉编译这个 dylib。CI 使用 `macos-latest`。

## 库在做什么

dylib 用 dyld 的 `__interpose` 挂钩 `connect`、`getaddrinfo`、`gethostbyname`、`sendto`、`posix_spawn`、`execve`。FakeIP、路由和 SOCKS5/HTTP 组包来自 `crates/agy-core`，配置字段与 Linux/Windows 的 `config.json` 相同。

- 域名解析分配 `198.18.0.0/15`，第一个地址是 `198.18.0.2`。
- TCP `connect` 在套接字上完成 SOCKS5 或 HTTP CONNECT，不永久改掉 `O_NONBLOCK`。
- `udp_mode=auto` 且代理是 SOCKS5 时，策略上希望走 UDP。macOS 这版还没有 SOCKS5 UDP Associate，于是按 `udp_fallback`（默认 `block`）阻断 `sendto`，避免 QUIC 悄悄直连。需要 UDP 直连时把 `udp_fallback` 设为 `direct`。
- `child_injection=true` 时不改子进程环境，未受系统保护的子进程会继承 `DYLD_INSERT_LIBRARIES`。`false` 时从 `execve` / `posix_spawn` 的环境里去掉本 dylib。

## SIP 与 Hardened Runtime

下面这些情况 **插不进去**。这不是库编译失败，而是系统拒绝插入：

- `/usr`、`/bin`、`/System` 里的系统程序受 SIP 保护，忽略 `DYLD_INSERT_LIBRARIES`。
- 带 Hardened Runtime 且开启 library validation 的已签名 App（Antigravity 发行版通常如此）也会忽略插入。dyld 的提示类似 ignoring `DYLD_INSERT_LIBRARIES`。

如果启动后日志里没有「dylib 已加载」，说明签名拦住了。可以对 **你自己机器上的这份 App** 重新做 ad-hoc 签名，并加上关闭 library validation 的 entitlement（仓库里的 `scripts/macos-disable-library-validation.plist`）：

```bash
codesign --force --deep --sign - \
  --entitlements scripts/macos-disable-library-validation.plist \
  /Applications/Antigravity.app
```

这会替换该 App 的签名，系统更新后要再签一次。不要对系统自带程序这样做。本仓库没有在真实的 Antigravity 进程里验证过插入；CI 只对无签名的测试程序做了 FakeIP 自检。

受 SIP 保护的子进程仍会自己丢掉 `DYLD_*`，库无法强制它们加载。

## English

Copy or build `libantigravity_proxy.dylib` and launch the Mach-O inside `Antigravity.app` with `./antigravity-proxy-macos.sh`. Do not use `open -a`; Launch Services drops `DYLD_*`. The script returns immediately and leaves the process running after the terminal closes.

`--test` only inserts the library into a tiny unsigned program and checks that `getaddrinfo` returns a `198.18.0.0/15` address. It does not start Antigravity.

SIP-protected binaries and Hardened Runtime apps with library validation ignore `DYLD_INSERT_LIBRARIES`. If the log never says the dylib loaded, re-sign your local app ad-hoc with `scripts/macos-disable-library-validation.plist`. UDP associate is not implemented; proxied UDP follows `udp_fallback` (default `block`).
