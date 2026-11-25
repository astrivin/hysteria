#!/bin/sh
set -eu
printf '=== read-only preflight; no service/firewall/configuration changes ===\n'
date -u '+%Y-%m-%dT%H:%M:%SZ'
printf '\n=== identity ===\n'
id
uname -srmo
cat /etc/os-release
printf '\n=== capabilities ===\n'
awk '/^(CapEff|CapBnd|NoNewPrivs):/' /proc/self/status
printf '\n=== resources ===\n'
getconf _NPROCESSORS_ONLN
uptime
free -m
df -h /root
printf '\n=== CPU usage snapshot ===\n'
ps -eo pid,comm,pcpu,pmem,rss --sort=-pcpu | head -n 15
printf '\n=== test-port occupancy ===\n'
if command -v ss >/dev/null; then
    ss -H -lntu | awk '{n=split($5,a,":"); if (a[n]+0 >= 6666 && a[n]+0 <= 7777) print}'
fi
printf '\n=== tools ===\n'
for program in ip tc iptables ip6tables iptables-save ethtool timeout python3 sysctl conntrack unshare nsenter mount readlink mktemp setsid curl wget nice ionice openssl tar sha256sum gcc go; do
    command -v "$program" || printf 'MISSING %s\n' "$program"
done
printf '\n=== routes and interface names ===\n'
if command -v ip >/dev/null; then
    ip -br addr
    ip route
fi
printf '\n=== control groups ===\n'
stat -fc %T /sys/fs/cgroup
cat /proc/self/cgroup
printf '\n=== existing test directory metadata ===\n'
if [ -e /root/tmp/hy2 ]; then
    ls -ld /root/tmp/hy2
    find /root/tmp/hy2 -maxdepth 1 -mindepth 1 -printf '%f\n' | head -n 30
else
    printf 'not present\n'
fi
printf '\n=== resource snapshot and raw socket permission (no packets sent) ===\n'
if command -v python3 >/dev/null; then
    python3 - <<'PY'
import json
from pathlib import Path
import socket
import time

def cpu():
    values = list(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
    return sum(values), values[3] + values[4]

before = cpu()
time.sleep(1)
after = cpu()
total = after[0] - before[0]
print(json.dumps({'host_cpu_busy_percent': round(100 * (1 - (after[1] - before[1]) / total), 1) if total else None}))
for family, name in ((socket.AF_INET, 'IPv4'), (socket.AF_INET6, 'IPv6')):
    try:
        with socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_TCP):
            print(json.dumps({'raw_socket': name, 'creation': 'allowed', 'packets_sent': 0}))
    except OSError as error:
        print(json.dumps({'raw_socket': name, 'creation': 'failed', 'errno': error.errno, 'error': error.strerror}))
PY
fi
