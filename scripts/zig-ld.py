import sys
import subprocess

target = sys.argv[1]
args = sys.argv[2:]

# Filter out flags that zig's clang-based driver rejects for aarch64
filtered = [a for a in args if "fix-cortex-a53" not in a]
cmd = ["zig", "cc", "-target", target] + filtered
sys.exit(subprocess.run(cmd).returncode)
