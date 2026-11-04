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

stage_config() {
    bash "$SCRIPT_DIR/scripts/stage-config.sh" "$@"
}

build_native() {
    if ! command -v cargo >/dev/null 2>&1; then
        echo "错误: 未找到 cargo。请先安装 Rust (https://rustup.rs)。"
        exit 1
    fi
    echo "使用 Cargo 编译本地架构 ($ARCH)..."
    cargo build --release -p antigravity-proxy
    if [ "$ARCH" = "x86_64" ]; then
        cp target/release/libantigravity_proxy.so bin/x64/
        stage_config bin/x64
        echo " -> [成功] bin/x64/libantigravity_proxy.so 与 config.json"
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
        cp target/release/libantigravity_proxy.so bin/arm64/
        stage_config bin/arm64
        echo " -> [成功] bin/arm64/libantigravity_proxy.so 与 config.json"
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
    stage_config bin/arm64
    echo " -> [成功] bin/arm64/libantigravity_proxy.so 与 config.json"
}

build_macos() {
    if [ "$(uname -s)" != "Darwin" ]; then
        echo "macOS dylib 需要在 Mac 或 GitHub Actions macos-latest 上编译。"
        echo "Linux 上没有可用的 Apple SDK，本脚本不从 Linux 交叉编译 darwin 目标。"
        echo "在 Mac 上: cargo build --release -p macos-proxy"
        echo "          cargo build --release --target x86_64-apple-darwin -p macos-proxy"
        return
    fi
    echo "编译 macOS 原生 dylib..."
    cargo build --release -p macos-proxy
    local arch dest
    arch="$(uname -m)"
    if [ "$arch" = "arm64" ]; then
        dest="bin/macos-arm64"
    else
        dest="bin/macos-x64"
    fi
    mkdir -p "$dest"
    cp target/release/libantigravity_proxy.dylib "$dest/"
    stage_config "$dest"
    echo " -> [成功] $dest/libantigravity_proxy.dylib 与 config.json"
    if rustup target list --installed | grep -q 'x86_64-apple-darwin'; then
        cargo build --release --target x86_64-apple-darwin -p macos-proxy
        mkdir -p bin/macos-x64
        cp target/x86_64-apple-darwin/release/libantigravity_proxy.dylib bin/macos-x64/
        stage_config bin/macos-x64
        echo " -> [成功] bin/macos-x64/libantigravity_proxy.dylib 与 config.json"
    fi
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
    stage_config bin/windows-x64
    echo " -> [成功] bin/windows-x64/version.dll 与 config.json"
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
    macos)
        build_macos
        ;;
    all)
        build_native
        build_arm64
        build_windows
        build_macos
        ;;
    *)
        echo "用法: $0 [native|x64|arm64|windows|macos|all]"
        exit 1
        ;;
esac

echo "=== 构建完成 ==="
