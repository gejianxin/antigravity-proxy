#!/bin/bash
# ==============================================================================
# Antigravity-Proxy Linux 一键安装/配置脚本 (支持 x64 与 ARM64)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCH="$(uname -m)"

echo "=========================================================="
echo "         Antigravity-Proxy Linux 一键安装助手             "
echo "=========================================================="

# 1. 架构识别与选择 SO
SO_SRC=""
if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then
    ARCH_NAME="x64"
    SO_SRC="$SCRIPT_DIR/bin/x64/libantigravity_proxy.so"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH_NAME="arm64"
    SO_SRC="$SCRIPT_DIR/bin/arm64/libantigravity_proxy.so"
else
    echo "[错误] 不支持的架构: $ARCH"
    exit 1
fi

if [ ! -f "$SO_SRC" ]; then
    echo "[警告] 未找到编译好的 $SO_SRC，尝试现地编译..."
    if [ -x "$SCRIPT_DIR/build.sh" ]; then
        bash "$SCRIPT_DIR/build.sh"
    fi
fi

if [ ! -f "$SO_SRC" ]; then
    echo "[错误] 缺少 $ARCH_NAME 架构的 libantigravity_proxy.so，请先运行 build.sh。"
    exit 1
fi

echo "[信息] 检测到当前系统架构: $ARCH ($ARCH_NAME)"
echo "[信息] 使用代理动态库: $SO_SRC"

# 2. 判断安装模式: 目录安装 (参数1为路径) 或 用户全局/桌面安装
TARGET_DIR="$1"

if [ -n "$TARGET_DIR" ] && [ -d "$TARGET_DIR" ]; then
    echo ""
    echo "[模式] 目录集成安装 -> $TARGET_DIR"
    cp "$SO_SRC" "$TARGET_DIR/libantigravity_proxy.so"
    if [ ! -f "$TARGET_DIR/config.json" ]; then
        cp "$SCRIPT_DIR/config.json" "$TARGET_DIR/config.json"
        echo "[完成] 已复制 config.json 到目标目录"
    else
        echo "[提示] 目标目录下已存在 config.json，跳过覆盖"
    fi

    cp "$SCRIPT_DIR/antigravity-proxy.sh" "$TARGET_DIR/antigravity-proxy.sh"
    chmod +x "$TARGET_DIR/antigravity-proxy.sh"

    # 创建快捷启动脚本
    cat << 'EOF' > "$TARGET_DIR/start-with-proxy.sh"
#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$DIR/antigravity-proxy.sh" "$DIR/antigravity" "$@"
EOF
    chmod +x "$TARGET_DIR/start-with-proxy.sh"

    echo "[完成] 目录集成安装完毕！"
    echo "使用方式:"
    echo "  1. 编辑 $TARGET_DIR/config.json 设置您的代理端口 (当前已配置 7898)"
    echo "  2. 运行 $TARGET_DIR/start-with-proxy.sh 即可带代理启动 Antigravity"
    exit 0
fi

# 用户全局安装模式 (~/.local)
INSTALL_DIR="$HOME/.local/lib/antigravity-proxy"
CONFIG_DIR="$HOME/.config/antigravity-proxy"
BIN_DIR="$HOME/.local/bin"

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$BIN_DIR"

cp "$SO_SRC" "$INSTALL_DIR/libantigravity_proxy.so"

if [ ! -f "$CONFIG_DIR/config.json" ]; then
    cp "$SCRIPT_DIR/config.json" "$CONFIG_DIR/config.json"
    echo "[完成] 已生成初始配置文件: $CONFIG_DIR/config.json"
else
    echo "[提示] 已存在用户配置文件: $CONFIG_DIR/config.json，保留现有配置"
fi

# 写入命令行全局调用包装器
WRAPPER_BIN="$BIN_DIR/antigravity-proxy"
cat << EOF > "$WRAPPER_BIN"
#!/bin/bash
export ANTIGRAVITY_PROXY_CONFIG="$CONFIG_DIR/config.json"
export LD_PRELOAD="$INSTALL_DIR/libantigravity_proxy.so\${LD_PRELOAD:+:\$LD_PRELOAD}"
exec "\$@"
EOF
chmod +x "$WRAPPER_BIN"

echo "[完成] 代理环境库已部署至: $INSTALL_DIR/libantigravity_proxy.so"
echo "[完成] 快捷启动命令已安装至: $WRAPPER_BIN"

# 3. 检测并修补桌面快捷方式 (.desktop)
DESKTOP_DIRS=(
    "$HOME/.local/share/applications"
    "/usr/share/applications"
)

PATCHED=0
for ddir in "${DESKTOP_DIRS[@]}"; do
    DESKTOP_FILE="$ddir/antigravity.desktop"
    if [ -f "$DESKTOP_FILE" ]; then
        LOCAL_DESKTOP="$HOME/.local/share/applications/antigravity.desktop"
        if [ "$ddir" != "$HOME/.local/share/applications" ] && [ ! -f "$LOCAL_DESKTOP" ]; then
            cp "$DESKTOP_FILE" "$LOCAL_DESKTOP"
            DESKTOP_FILE="$LOCAL_DESKTOP"
        fi

        if [ -w "$DESKTOP_FILE" ]; then
            # 备份原文件
            if [ ! -f "${DESKTOP_FILE}.bak" ]; then
                cp "$DESKTOP_FILE" "${DESKTOP_FILE}.bak"
            fi
            # 替换 Exec
            sed -i "s|^Exec=.*|Exec=$WRAPPER_BIN antigravity %F|g" "$DESKTOP_FILE"
            echo "[完成] 已为桌面快捷方式注入代理: $DESKTOP_FILE"
            PATCHED=1
            break
        fi
    fi
done

if [ $PATCHED -eq 0 ]; then
    echo "[提示] 未自动检测到桌面快捷方式 antigravity.desktop。"
    echo "您可以随时通过以下方式运行:"
    echo "  $WRAPPER_BIN /path/to/antigravity"
    echo "或者将 $SCRIPT_DIR/antigravity-proxy.sh 作为启动器。"
fi

echo ""
echo "=========================================================="
echo "                   安装成功！                             "
echo "=========================================================="
echo "下一步说明:"
echo "1. 检查并根据您的本地代理软件修改配置文件:"
echo "   nano $CONFIG_DIR/config.json"
echo "2. 验证代理环境是否正常:"
echo "   $SCRIPT_DIR/antigravity-proxy.sh --test"
echo "3. 启动 Antigravity 体验透明代理加速！"
echo "=========================================================="
