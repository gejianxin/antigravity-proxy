param (
    [string]$Target = "all"
)

$rootDir = $PSScriptRoot
$zigLdX64 = Join-Path $rootDir "scripts\zig-ld-x64.cmd"
$zigLdArm64 = Join-Path $rootDir "scripts\zig-ld-arm64.cmd"

New-Item -ItemType Directory -Force -Path "bin\x64", "bin\arm64" | Out-Null

if ($Target -eq "all" -or $Target -eq "x64") {
    Write-Host "Compiling Rust for Linux x64 (x86_64-unknown-linux-gnu)..." -ForegroundColor Cyan
    $env:RUSTFLAGS = "-C linker=$zigLdX64"
    cargo build --release --target x86_64-unknown-linux-gnu
    if ($LASTEXITCODE -eq 0) {
        Copy-Item -Force "target\x86_64-unknown-linux-gnu\release\libantigravity_proxy.so" "bin\x64\libantigravity_proxy.so"
        Write-Host "x64 build succeeded -> bin/x64/libantigravity_proxy.so" -ForegroundColor Green
    } else {
        Write-Error "x64 build failed!"
        exit 1
    }
}

if ($Target -eq "all" -or $Target -eq "arm64") {
    Write-Host "Compiling Rust for Linux ARM64 (aarch64-unknown-linux-gnu)..." -ForegroundColor Cyan
    $env:RUSTFLAGS = "-C linker=$zigLdArm64"
    cargo build --release --target aarch64-unknown-linux-gnu
    if ($LASTEXITCODE -eq 0) {
        Copy-Item -Force "target\aarch64-unknown-linux-gnu\release\libantigravity_proxy.so" "bin\arm64\libantigravity_proxy.so"
        Write-Host "arm64 build succeeded -> bin/arm64/libantigravity_proxy.so" -ForegroundColor Green
    } else {
        Write-Error "arm64 build failed!"
        exit 1
    }
}

Write-Host "=== All Rust builds finished successfully ===" -ForegroundColor Green
