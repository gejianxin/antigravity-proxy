#!/bin/bash
# Load the dylib into an unsigned local binary. This does not launch Antigravity.
set -euo pipefail

DYLIB="${1:-}"
if [ -z "$DYLIB" ] || [ ! -f "$DYLIB" ]; then
    echo "usage: $0 path/to/libantigravity_proxy.dylib" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cc -O2 -o "$WORK/agy-macos-smoke" "$ROOT/scripts/macos-smoke.c"
echo "smoke binary: $WORK/agy-macos-smoke"
echo "dylib: $DYLIB"
ANTIGRAVITY_PROXY_FORCE=1 DYLD_INSERT_LIBRARIES="$DYLIB" "$WORK/agy-macos-smoke"
echo "macOS dylib smoke passed (FakeIP via getaddrinfo; Antigravity itself was not launched)"
