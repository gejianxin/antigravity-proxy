#!/bin/bash
# Load the built interceptor and check FakeIP, non-blocking connect, UDP block,
# routing bypass, and child_injection=false. Requires python3.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SO="${1:-$ROOT/target/release/libantigravity_proxy.so}"
if [[ ! -f "$SO" ]]; then
  SO="$ROOT/target/debug/libantigravity_proxy.so"
fi
if [[ ! -f "$SO" ]]; then
  echo "missing libantigravity_proxy.so (build it first)" >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

python3 - <<'PY' "$WORKDIR" &
import socket, sys, threading
port_file = sys.argv[1] + "/socks.port"
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(8)
open(port_file, "w").write(str(srv.getsockname()[1]))

def handle(conn):
    try:
        greet = conn.recv(3)
        if len(greet) < 3:
            return
        conn.sendall(b"\x05\x00")
        hdr = conn.recv(4)
        if len(hdr) < 4:
            return
        atyp = hdr[3]
        if atyp == 1:
            conn.recv(6)
        elif atyp == 4:
            conn.recv(18)
        elif atyp == 3:
            n = conn.recv(1)
            if n:
                conn.recv(n[0] + 2)
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    finally:
        conn.close()

while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
MOCK_PID=$!
for _ in $(seq 1 50); do
  [[ -f "$WORKDIR/socks.port" ]] && break
  sleep 0.05
done
PORT="$(cat "$WORKDIR/socks.port")"

cat >"$WORKDIR/config.json" <<EOF
{
  "log_level": "debug",
  "child_injection": false,
  "child_injection_mode": "filtered",
  "proxy": {"host": "127.0.0.1", "port": $PORT, "type": "socks5"},
  "fake_ip": {"enabled": true, "cidr": "198.18.0.0/15"},
  "timeout": {"connect": 2000, "send": 2000, "recv": 2000},
  "proxy_rules": {
    "allowed_ports": [80, 443],
    "dns_mode": "direct",
    "ipv6_mode": "proxy",
    "udp_mode": "block",
    "udp_fallback": "block",
    "routing": {
      "enabled": true,
      "priority_mode": "order",
      "default_action": "proxy",
      "use_default_private": true,
      "rules": [
        {"name": "direct-name", "action": "direct", "domains": ["direct.example.invalid"], "protocols": ["tcp"]}
      ]
    }
  }
}
EOF

set +e
ANTIGRAVITY_PROXY_CONFIG="$WORKDIR/config.json" \
ANTIGRAVITY_PROXY_FORCE=1 \
ANTIGRAVITY_PROXY_LOG="$WORKDIR/proxy.log" \
LD_PRELOAD="$SO" \
python3 - <<'PY' "$WORKDIR" "$SO"
import os, socket, fcntl, subprocess, sys
workdir, so = sys.argv[1], sys.argv[2]
errors = []

def check(cond, msg):
    if not cond:
        errors.append(msg)
        print("FAIL", msg)
    else:
        print("ok", msg)

infos = socket.getaddrinfo("oauth2.googleapis.com", 443, socket.AF_INET, socket.SOCK_STREAM)
ip = infos[0][4][0]
check(ip.startswith("198.18.") or ip.startswith("198.19."), f"fake ipv4 {ip}")

try:
    v6 = socket.getaddrinfo("oauth2.googleapis.com", 443, socket.AF_INET6, socket.SOCK_STREAM)
    v6ip = v6[0][4][0].lower()
    check(v6ip.startswith("::ffff:198.18.") or v6ip.startswith("::ffff:198.19."), f"fake ipv6 {v6ip}")
except socket.gaierror as exc:
    print("skip ipv6", exc)

try:
    direct = socket.getaddrinfo("direct.example.invalid", 80)
    for item in direct:
        check(not str(item[4][0]).startswith("198.18."), f"direct rule leaked fakeip {item[4]}")
except socket.gaierror:
    print("ok direct rule used the system resolver")

s = socket.socket()
s.setblocking(False)
flags_before = fcntl.fcntl(s.fileno(), fcntl.F_GETFL)
try:
    s.connect((ip, 443))
    check(True, "nonblocking connect completed inside the hook")
except BlockingIOError:
    errors.append("connect returned EINPROGRESS; hook cleared the handshake contract")
    print("FAIL einprogress")
flags_after = fcntl.fcntl(s.fileno(), fcntl.F_GETFL)
check(flags_after & os.O_NONBLOCK, "O_NONBLOCK preserved")
check(flags_before & os.O_NONBLOCK, "socket started nonblocking")
s.close()

u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    u.sendto(b"x", ("1.1.1.1", 443))
    errors.append("udp block did not stop sendto")
    print("FAIL udp sendto succeeded")
except OSError as exc:
    check(exc.errno in (13, 1), f"udp blocked errno={exc.errno}")
u.close()

env = os.environ.copy()
child = subprocess.check_output(
    [sys.executable, "-c", "import os; print(os.environ.get('LD_PRELOAD',''))"],
    env=env,
    text=True,
).strip()
check(so not in child and "libantigravity_proxy.so" not in child, f"child LD_PRELOAD={child!r}")

if errors:
    print("SMOKE FAILED")
    for err in errors:
        print(" -", err)
    sys.exit(1)
print("SMOKE OK")
PY
STATUS=$?
set -e
kill "$MOCK_PID" 2>/dev/null || true
wait "$MOCK_PID" 2>/dev/null || true
if [[ $STATUS -ne 0 ]]; then
  echo "----- proxy.log -----"
  cat "$WORKDIR/proxy.log" 2>/dev/null || true
  exit "$STATUS"
fi
echo "smoke passed; log at $WORKDIR/proxy.log"
