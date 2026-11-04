#!/bin/bash
# ==============================================================================
# Antigravity-Proxy Linux 卸载脚本
# ==============================================================================

echo "=========================================================="
echo "         Antigravity-Proxy Linux 卸载程序                 "
echo "=========================================================="

INSTALL_DIR="$HOME/.local/lib/antigravity-proxy"
CONFIG_DIR="$HOME/.config/antigravity-proxy"
WRAPPER_BIN="$HOME/.local/bin/antigravity-proxy"
DESKTOP_FILE="$HOME/.local/share/applications/antigravity.desktop"

# 恢复桌面快捷方式
if [ -f "${DESKTOP_FILE}.bak" ]; then
    mv "${DESKTOP_FILE}.bak" "$DESKTOP_FILE"
    echo "[完成] 已恢复原始桌面快捷方式"
fi

if [ -f "$WRAPPER_BIN" ]; then
    rm -f "$WRAPPER_BIN"
    echo "[完成] 已删除快捷命令: $WRAPPER_BIN"
fi

if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    echo "[完成] 已删除代理动态库目录: $INSTALL_DIR"
fi

read -p "是否同时删除配置文件目录 ($CONFIG_DIR)? [y/N]: " confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
    rm -rf "$CONFIG_DIR"
    echo "[完成] 已删除配置目录: $CONFIG_DIR"
else
    echo "[保留] 保留配置目录: $CONFIG_DIR"
fi

echo "=========================================================="
echo "卸载完成！"
echo "=========================================================="
