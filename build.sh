#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ARCH=$(uname -m)
echo "=== Antigravity-Proxy Linux (Rust 重构版) 构建脚本 ==="
echo "当前平台架构: $ARCH"

mkdir -p bin/x64 bin/arm64

if command -v cargo >/dev/null 2>&1; then
    echo "使用 Cargo 编译本地架构 ($ARCH)..."
    cargo build --release
    TARGET_DIR="target/release"
    if [ "$ARCH" = "x86_64" ]; then
        cp "$TARGET_DIR/libantigravity_proxy.so" bin/x64/
        echo " -> [成功] bin/x64/libantigravity_proxy.so"
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
        cp "$TARGET_DIR/libantigravity_proxy.so" bin/arm64/
        echo " -> [成功] bin/arm64/libantigravity_proxy.so"
    fi
else
    echo "错误: 未找到 cargo 编译器！请先安装 Rust (https://rustup.rs)。"
    exit 1
fi

echo "=== 构建完成 ==="
