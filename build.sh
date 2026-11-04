#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGET="${1:-native}"
ARCH=$(uname -m)

echo "=== Antigravity-Proxy 构建脚本 ==="
echo "当前平台架构: $ARCH"
echo "目标: $TARGET"

mkdir -p bin/x64 bin/arm64 bin/windows-x64

build_native() {
    if ! command -v cargo >/dev/null 2>&1; then
        echo "错误: 未找到 cargo。请先安装 Rust (https://rustup.rs)。"
        exit 1
    fi
    echo "使用 Cargo 编译本地架构 ($ARCH)..."
    cargo build --release -p antigravity-proxy
    if [ "$ARCH" = "x86_64" ]; then
        cp target/release/libantigravity_proxy.so bin/x64/
        echo " -> [成功] bin/x64/libantigravity_proxy.so"
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
        cp target/release/libantigravity_proxy.so bin/arm64/
        echo " -> [成功] bin/arm64/libantigravity_proxy.so"
    else
        echo "已生成 target/release/libantigravity_proxy.so（未识别的架构，未复制到 bin/）"
    fi
}

build_arm64() {
    if ! command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
        echo "跳过 Linux arm64: 未安装 aarch64-linux-gnu-gcc"
        return
    fi
    rustup target add aarch64-unknown-linux-gnu >/dev/null
    echo "交叉编译 Linux arm64..."
    cargo build --release --target aarch64-unknown-linux-gnu -p antigravity-proxy
    cp target/aarch64-unknown-linux-gnu/release/libantigravity_proxy.so bin/arm64/
    echo " -> [成功] bin/arm64/libantigravity_proxy.so"
}

build_windows() {
    if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
        echo "跳过 Windows x64: 未安装 x86_64-w64-mingw32-gcc"
        echo "在 Windows 上请改用 build.ps1（MSVC 或 GNU 目标）。"
        return
    fi
    rustup target add x86_64-pc-windows-gnu >/dev/null
    echo "交叉编译 Windows x64 (version.dll + injector)..."
    cargo build --release --target x86_64-pc-windows-gnu -p windows-proxy -p windows-injector
    cp target/x86_64-pc-windows-gnu/release/version.dll bin/windows-x64/
    cp target/x86_64-pc-windows-gnu/release/antigravity-proxy.exe bin/windows-x64/
    if [ ! -f bin/windows-x64/config.json ]; then
        cp config.json bin/windows-x64/config.json
    fi
    echo " -> [成功] bin/windows-x64/version.dll"
    echo " -> [成功] bin/windows-x64/antigravity-proxy.exe"
}

case "$TARGET" in
    native|"")
        build_native
        ;;
    x64)
        build_native
        ;;
    arm64)
        build_arm64
        ;;
    windows)
        build_windows
        ;;
    all)
        build_native
        build_arm64
        build_windows
        ;;
    *)
        echo "用法: $0 [native|x64|arm64|windows|all]"
        exit 1
        ;;
esac

echo "=== 构建完成 ==="
