#!/bin/bash
# ==============================================================================
# Antigravity-Proxy Linux 启动器 (支持 x64 / ARM64 自动识别)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCH="$(uname -m)"

# 架构判断与匹配 SO 文件
SO_FILE=""
if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then
    ARCH_NAME="x64"
    if [ -f "$SCRIPT_DIR/bin/x64/libantigravity_proxy.so" ]; then
        SO_FILE="$SCRIPT_DIR/bin/x64/libantigravity_proxy.so"
    elif [ -f "$SCRIPT_DIR/libantigravity_proxy.so" ]; then
        SO_FILE="$SCRIPT_DIR/libantigravity_proxy.so"
    fi
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH_NAME="arm64"
    if [ -f "$SCRIPT_DIR/bin/arm64/libantigravity_proxy.so" ]; then
        SO_FILE="$SCRIPT_DIR/bin/arm64/libantigravity_proxy.so"
    elif [ -f "$SCRIPT_DIR/libantigravity_proxy.so" ]; then
        SO_FILE="$SCRIPT_DIR/libantigravity_proxy.so"
    fi
else
    echo "[错误] 不支持的架构: $ARCH (仅支持 x86_64 和 aarch64/arm64)"
    exit 1
fi

if [ -z "$SO_FILE" ] || [ ! -f "$SO_FILE" ]; then
    echo "[错误] 未找到适用于 $ARCH_NAME 架构的 libantigravity_proxy.so！"
    echo "请先在项目目录运行 ./build.sh 或 bash build.sh 进行编译。"
    exit 1
fi

# 配置文件定位
if [ -z "$ANTIGRAVITY_PROXY_CONFIG" ]; then
    if [ -f "$SCRIPT_DIR/config.json" ]; then
        export ANTIGRAVITY_PROXY_CONFIG="$SCRIPT_DIR/config.json"
    elif [ -f "$HOME/.config/antigravity-proxy/config.json" ]; then
        export ANTIGRAVITY_PROXY_CONFIG="$HOME/.config/antigravity-proxy/config.json"
    elif [ -f "/etc/antigravity-proxy/config.json" ]; then
        export ANTIGRAVITY_PROXY_CONFIG="/etc/antigravity-proxy/config.json"
    fi
fi

# 诊断测试模式
if [ "$1" = "--test" ]; then
    echo "=== Antigravity-Proxy Linux 运行环境诊断 ==="
    echo "操作系统架构: $ARCH ($ARCH_NAME)"
    echo "代理劫持库:   $SO_FILE"
    echo "配置文件路径: ${ANTIGRAVITY_PROXY_CONFIG:-未找到 (将使用默认设置)}"
    echo ""
    echo "正在测试 FakeIP 与网络重定向拦截..."
    ANTIGRAVITY_PROXY_FORCE=1 ANTIGRAVITY_PROXY_DEBUG=1 LD_PRELOAD="$SO_FILE" python3 -c '
import socket
print("[Python 测试] 正在请求解析 oauth2.googleapis.com...")
try:
    info = socket.getaddrinfo("oauth2.googleapis.com", 443)
    print("[Python 测试] 解析结果 (FakeIP 拦截):", info)
except Exception as e:
    print("[Python 测试] 解析异常:", e)
' 2>&1
    echo "=== 诊断完成 ==="
    exit 0
fi

# 帮助信息
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "用法: $0 [选项] [可执行程序路径 [参数...]]"
    echo ""
    echo "选项:"
    echo "  --test        运行代理环境注入与 FakeIP 诊断测试"
    echo "  --help, -h    显示本帮助信息"
    echo ""
    echo "示例:"
    echo "  $0                           # 自动搜寻并启动系统中的 Antigravity"
    echo "  $0 /opt/Antigravity/antigravity  # 启动指定路径的 Antigravity"
    echo "  $0 agy                       # 代理模式启动 Antigravity CLI"
    echo "  $0 --test                    # 运行自检"
    exit 0
fi

# 如果指定了目标程序命令，则直接启动
if [ $# -gt 0 ]; then
    TARGET_CMD="$1"
    shift
    echo "[启动] 正在以代理注入模式启动: $TARGET_CMD $@"
    export LD_PRELOAD="$SO_FILE${LD_PRELOAD:+:$LD_PRELOAD}"
    exec "$TARGET_CMD" "$@"
fi

# 未指定程序，自动搜寻常见的 Antigravity 安装位置
CANDIDATES=(
    "$SCRIPT_DIR/antigravity"
    "/opt/Antigravity/antigravity"
    "/usr/lib/antigravity/antigravity"
    "/usr/share/antigravity/antigravity"
    "$HOME/.local/share/antigravity/antigravity"
)

FOUND_BIN=""
for path in "${CANDIDATES[@]}"; do
    if [ -x "$path" ]; then
        FOUND_BIN="$path"
        break
    fi
done

if [ -z "$FOUND_BIN" ]; then
    FOUND_BIN=$(command -v antigravity 2>/dev/null || true)
fi

if [ -n "$FOUND_BIN" ] && [ -x "$FOUND_BIN" ]; then
    echo "[启动] 找到 Antigravity 可执行文件: $FOUND_BIN"
    export LD_PRELOAD="$SO_FILE${LD_PRELOAD:+:$LD_PRELOAD}"
    exec "$FOUND_BIN" "$@"
else
    echo "[提示] 未在常见目录中找到 antigravity 可执行文件。"
    echo "请直接将 antigravity 路径作为参数传递，例如:"
    echo "  $0 /path/to/antigravity"
    echo "或使用 $0 --test 查看当前代理库注入状态。"
    exit 1
fi
