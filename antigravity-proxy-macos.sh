#!/bin/bash
# Launch Antigravity with DYLD_INSERT_LIBRARIES. This is not a DLL hijack.
# `open -a` drops DYLD_* variables, so the Mach-O inside the .app is executed directly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCH="$(uname -m)"

if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    ARCH_DIR="macos-arm64"
elif [ "$ARCH" = "x86_64" ]; then
    ARCH_DIR="macos-x64"
else
    echo "[错误] 不支持的架构: $ARCH" >&2
    exit 1
fi

DYLIB=""
for candidate in \
    "$SCRIPT_DIR/bin/$ARCH_DIR/libantigravity_proxy.dylib" \
    "$SCRIPT_DIR/libantigravity_proxy.dylib"
do
    if [ -f "$candidate" ]; then
        DYLIB="$candidate"
        break
    fi
done

if [ -z "$DYLIB" ]; then
    echo "[错误] 未找到 $ARCH_DIR 的 libantigravity_proxy.dylib" >&2
    echo "在 Mac 上执行: cargo build --release -p macos-proxy" >&2
    echo "或从 GitHub Actions 的 macos 工件下载到 bin/$ARCH_DIR/" >&2
    exit 1
fi

if [ -z "${ANTIGRAVITY_PROXY_CONFIG:-}" ]; then
    if [ -f "$SCRIPT_DIR/bin/$ARCH_DIR/config.json" ]; then
        export ANTIGRAVITY_PROXY_CONFIG="$SCRIPT_DIR/bin/$ARCH_DIR/config.json"
    elif [ -f "$SCRIPT_DIR/config.json" ]; then
        export ANTIGRAVITY_PROXY_CONFIG="$SCRIPT_DIR/config.json"
    elif [ -f "$HOME/Library/Application Support/antigravity-proxy/config.json" ]; then
        export ANTIGRAVITY_PROXY_CONFIG="$HOME/Library/Application Support/antigravity-proxy/config.json"
    fi
fi

export DYLD_INSERT_LIBRARIES="$DYLIB${DYLD_INSERT_LIBRARIES:+:$DYLD_INSERT_LIBRARIES}"

if [ "${1:-}" = "--test" ]; then
    echo "=== Antigravity-Proxy macOS dylib 自检 ==="
    echo "架构: $ARCH"
    echo "dylib: $DYLIB"
    echo "配置: ${ANTIGRAVITY_PROXY_CONFIG:-未设置}"
    echo "这一步只把库插进临时编译的无签名程序，不启动 Antigravity。"
    bash "$SCRIPT_DIR/scripts/smoke-macos.sh" "$DYLIB"
    exit 0
fi

FOREGROUND=0
if [ "${1:-}" = "--foreground" ]; then
    FOREGROUND=1
    shift
fi

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    echo "用法: $0 [--test | --foreground] [Antigravity 可执行文件]"
    echo "默认脱离终端并立刻返回。不要用 open -a，那会丢掉 DYLD_INSERT_LIBRARIES。"
    exit 0
fi

if [ $# -gt 0 ]; then
    TARGET="$1"
    shift
else
    TARGET=""
    for candidate in \
        "/Applications/Antigravity.app/Contents/MacOS/Antigravity" \
        "$HOME/Applications/Antigravity.app/Contents/MacOS/Antigravity" \
        "/Applications/Antigravity IDE.app/Contents/MacOS/Antigravity IDE"
    do
        if [ -x "$candidate" ]; then
            TARGET="$candidate"
            break
        fi
    done
fi

if [ -z "$TARGET" ] || [ ! -x "$TARGET" ]; then
    echo "[错误] 找不到 Antigravity 可执行文件。请传入 .app 内的 Mach-O 路径，例如:" >&2
    echo "  $0 /Applications/Antigravity.app/Contents/MacOS/Antigravity" >&2
    exit 1
fi

if [ "$FOREGROUND" -eq 1 ]; then
    echo "[启动] 前台运行: $TARGET"
    exec "$TARGET" "$@"
fi

LOG_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/antigravity-proxy"
mkdir -p "$LOG_DIR"
if command -v setsid >/dev/null 2>&1; then
    setsid nohup "$TARGET" "$@" >>"$LOG_DIR/launch.log" 2>&1 < /dev/null &
else
    nohup "$TARGET" "$@" >>"$LOG_DIR/launch.log" 2>&1 < /dev/null &
fi
echo "[启动] 已在后台运行: $TARGET (PID $!)"
echo "[启动] 若日志没有 “dylib 已加载”，多半是签名的 Hardened Runtime 拒绝了插入。"
echo "[启动] 说明见 使用说明_macOS.md。输出追加到 $LOG_DIR/launch.log"
