param (
    [string]$Target = "all"
)

$rootDir = $PSScriptRoot
$zigLdX64 = Join-Path $rootDir "scripts\zig-ld-x64.cmd"
$zigLdArm64 = Join-Path $rootDir "scripts\zig-ld-arm64.cmd"

New-Item -ItemType Directory -Force -Path "bin\x64", "bin\arm64", "bin\windows-x64" | Out-Null

function Build-LinuxTarget([string]$label, [string]$triple, [string]$linker, [string]$outDir) {
    Write-Host "Compiling Rust for $label ($triple)..." -ForegroundColor Cyan
    $env:RUSTFLAGS = "-C linker=$linker"
    cargo build --release --target $triple -p antigravity-proxy
    if ($LASTEXITCODE -ne 0) {
        Write-Error "$label build failed!"
        exit 1
    }
    Copy-Item -Force "target\$triple\release\libantigravity_proxy.so" "$outDir\libantigravity_proxy.so"
    Write-Host "$label build succeeded -> $outDir/libantigravity_proxy.so" -ForegroundColor Green
}

if ($Target -eq "all" -or $Target -eq "x64") {
    Build-LinuxTarget "Linux x64" "x86_64-unknown-linux-gnu" $zigLdX64 "bin\x64"
}

if ($Target -eq "all" -or $Target -eq "arm64") {
    Build-LinuxTarget "Linux ARM64" "aarch64-unknown-linux-gnu" $zigLdArm64 "bin\arm64"
}

if ($Target -eq "all" -or $Target -eq "windows") {
    Write-Host "Compiling Windows x64 runtime (version.dll + injector)..." -ForegroundColor Cyan
    Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
    $installed = (rustup target list --installed | Out-String)
    if ($installed -match "x86_64-pc-windows-msvc") {
        $winTriple = "x86_64-pc-windows-msvc"
    } elseif ($installed -match "x86_64-pc-windows-gnu") {
        $winTriple = "x86_64-pc-windows-gnu"
    } else {
        Write-Host "Adding x86_64-pc-windows-msvc (needs the Visual C++ build tools)..." -ForegroundColor Yellow
        rustup target add x86_64-pc-windows-msvc
        if ($LASTEXITCODE -eq 0) {
            $winTriple = "x86_64-pc-windows-msvc"
        } else {
            $winTriple = "x86_64-pc-windows-gnu"
            rustup target add x86_64-pc-windows-gnu
        }
    }
    cargo build --release --target $winTriple -p windows-proxy -p windows-injector
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Windows build failed. On Windows, the MSVC target needs the Visual C++ build tools. The GNU target needs mingw-w64."
        exit 1
    }
    Copy-Item -Force "target\$winTriple\release\version.dll" "bin\windows-x64\version.dll"
    Copy-Item -Force "target\$winTriple\release\antigravity-proxy.exe" "bin\windows-x64\antigravity-proxy.exe"
    if (-not (Test-Path "bin\windows-x64\config.json")) {
        Copy-Item -Force "config.json" "bin\windows-x64\config.json"
    }
    Write-Host "Windows build succeeded -> bin/windows-x64/version.dll" -ForegroundColor Green
}

Write-Host "=== Builds finished ===" -ForegroundColor Green
