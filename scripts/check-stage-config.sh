#!/bin/bash
# The default config is copied only when a staged directory has none.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="$ROOT/scripts/stage-config.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/fresh" "$WORK/keep"
printf 'custom-config\n' > "$WORK/keep/config.json"

bash "$STAGE" "$WORK/fresh" "$WORK/keep"
cmp "$ROOT/config.json" "$WORK/fresh/config.json"
test "$(cat "$WORK/keep/config.json")" = "custom-config"

# A second run must not replace either file.
before="$(cksum "$WORK/fresh/config.json" "$WORK/keep/config.json")"
bash "$STAGE" "$WORK/fresh" "$WORK/keep"
after="$(cksum "$WORK/fresh/config.json" "$WORK/keep/config.json")"
test "$before" = "$after"
test "$(cat "$WORK/keep/config.json")" = "custom-config"

for dir in bin/x64 bin/arm64 bin/windows-x64 bin/macos-arm64 bin/macos-x64; do
    if [ ! -f "$ROOT/$dir/config.json" ]; then
        echo "缺少 $dir/config.json" >&2
        exit 1
    fi
done

echo "stage-config check passed"
