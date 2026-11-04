#!/bin/bash
# Place the repo default config.json next to staged binaries.
# An existing config.json is left as-is.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/config.json"

if [ ! -f "$SRC" ]; then
    echo "stage-config: 找不到 $SRC" >&2
    exit 1
fi

if [ "$#" -eq 0 ]; then
    echo "usage: $0 dest-dir..." >&2
    exit 1
fi

for dir in "$@"; do
    mkdir -p "$dir"
    if [ -f "$dir/config.json" ]; then
        continue
    fi
    cp "$SRC" "$dir/config.json"
    echo " -> [配置] 已写入 $dir/config.json（目录里原来没有）"
done
