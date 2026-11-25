#!/usr/bin/env bash
# Reproducible Linux network tests. An outer mount/network/PID namespace
# contains all test processes, links and runtime files, including /run/netns.
set -euo pipefail
umask 077
ulimit -c 0
export PYTHONDONTWRITEBYTECODE=1

if [[ ${EUID} -ne 0 ]]; then
    echo 'This test requires root with CAP_NET_RAW, CAP_NET_ADMIN, CAP_SYS_ADMIN and namespace support.' >&2
    exit 1
fi
for program in ip tc iptables ip6tables ethtool timeout python3 sysctl conntrack unshare mount mktemp readlink; do
    command -v "$program" >/dev/null || { echo "Missing test dependency: $program" >&2; exit 1; }
done

script=$(readlink -f -- "${BASH_SOURCE[0]}")
repo=$(cd -- "$(dirname -- "$script")/.." && pwd -P)
if [[ ! -f $repo/go.work ]]; then repo=$(dirname -- "$script"); fi
seconds=${FAKETCP_CASE_SECONDS:-15}
soak=${FAKETCP_SOAK_SECONDS:-0}
clients=${FAKETCP_CLIENTS:-2}
port=${FAKETCP_PORT:-6666}
parallel=${FAKETCP_PARALLEL:-2}
bandwidth=${FAKETCP_BANDWIDTH:-12500000}
udp_pps=${FAKETCP_UDP_PPS:-8000}
for value in "$seconds" "$clients" "$parallel" "$bandwidth" "$udp_pps" "$port"; do
    [[ $value =~ ^[1-9][0-9]*$ ]] || { echo 'Case seconds, clients, parallel, bandwidth, UDP PPS and port must be positive integers.' >&2; exit 1; }
done
[[ $soak =~ ^(0|[1-9][0-9]*)$ ]] || { echo 'Soak seconds must be a nonnegative integer.' >&2; exit 1; }
((port >= 6666 && port <= 7777)) || { echo 'FAKETCP_PORT must be in 6666..7777.' >&2; exit 1; }
((parallel <= 128)) || { echo 'FAKETCP_PARALLEL must be in 1..128.' >&2; exit 1; }
# Keep the service, ephemeral client ports and translated SNAT ports in
# separate blocks, all within the explicitly reserved test port range.
if ((port < 7000)); then
    client_min=7000 client_max=7399 snat_min=7400 snat_max=7777
elif ((port < 7400)); then
    client_min=6666 client_max=6999 snat_min=7400 snat_max=7777
else
    client_min=6666 client_max=6999 snat_min=7000 snat_max=7399
fi
((clients <= client_max - client_min + 1 && clients <= snat_max - snat_min + 1)) || {
    echo 'FAKETCP_CLIENTS exceeds the isolated client/SNAT port budget.' >&2; exit 1;
}
output=${FAKETCP_RESULTS_DIR:-"$repo/build/faketcp-results"}
mkdir -p "$output"
output=$(cd -- "$output" && pwd -P)
binary=${FAKETCP_INTEGRATION_BIN:-"$repo/build/faketcp-integration"}
if [[ ! -x $binary ]]; then
    echo 'Build the integration executable first: go build -o build/faketcp-integration ./extras/transport/faketcp/internal/integration' >&2
    exit 1
fi
binary=$(readlink -f -- "$binary")

if (($# == 0)); then
    # No veth or named namespace is ever created in the caller's network or
    # mount namespace. All mount changes below are private to this child.
    for path in "$repo" "$output" "$binary"; do
        case "$path" in
            /run/*|/var/run/*|/tmp/*|/var/tmp/*)
                echo 'Test files must live outside /run, /tmp and /var/tmp, which are replaced inside the private mount namespace.' >&2
                exit 1
                ;;
        esac
    done
    if [[ -e $output/environment.txt || -e $output/results.json ]]; then
        echo 'Choose a fresh FAKETCP_RESULTS_DIR; existing test results will not be overwritten or mixed into this run.' >&2
        exit 1
    fi
    runtime=$(mktemp -d "$output/runtime.XXXXXXXX")
    mkdir -p "$runtime/run" "$runtime/tmp"
    export FAKETCP_RESULTS_DIR="$output" FAKETCP_INTEGRATION_BIN="$binary"
    FAKETCP_PARENT_NETNS=$(readlink /proc/self/ns/net)
    FAKETCP_PARENT_MNTNS=$(readlink /proc/self/ns/mnt)
    export FAKETCP_PARENT_NETNS FAKETCP_PARENT_MNTNS
    exec unshare --mount --net --pid --fork --kill-child=KILL --mount-proc --propagation private \
        bash "$script" --isolated "$runtime"
fi
if [[ $# != 2 || $1 != --isolated || $$ != 1 ||
      $(readlink /proc/self/ns/net) == "${FAKETCP_PARENT_NETNS:-}" ||
      $(readlink /proc/self/ns/mnt) == "${FAKETCP_PARENT_MNTNS:-}" ]]; then
    echo 'Failed to enter the private test namespaces.' >&2
    exit 1
fi
runtime=$2
[[ $runtime == "$output"/runtime.* && -d $runtime/run && -d $runtime/tmp ]] || {
    echo 'Invalid private runtime directory.' >&2; exit 1;
}
mount --no-mtab --bind "$runtime/run" /run
if [[ $(readlink -f /var/run) != /run ]]; then
    mount --no-mtab --bind "$runtime/run" /var/run
fi
export TMPDIR="$runtime/tmp"
mount --no-mtab --bind "$TMPDIR" /tmp
mount --no-mtab --bind "$TMPDIR" /var/tmp
cd -- "$output"

server_ns="hy2-ft-s-$$"
client_ns="hy2-ft-c-$$"
router1_ns="hy2-ft-r1-$$"
router2_ns="hy2-ft-r2-$$"
server_dev="hys$$"
client_dev="hyc$$"
server_pid=
client_pids=()
created_namespaces=()
created_links=()
cleanup() {
    for pid in "${client_pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
    if [[ -n $server_pid ]]; then kill -TERM "$server_pid" 2>/dev/null || true; fi
    for ns in "${created_namespaces[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
    for dev in "${created_links[@]}"; do
        ip link del "$dev" 2>/dev/null || true
    done
}
add_namespace() {
    ip netns add "$1"
    created_namespaces+=("$1")
}
add_veth() {
    ip link add "$1" type veth peer name "$2"
    created_links+=("$1" "$2")
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

add_namespace "$server_ns"
add_namespace "$client_ns"
add_veth "$server_dev" "$client_dev"
ip link set "$server_dev" netns "$server_ns"
ip link set "$client_dev" netns "$client_ns"
ip -n "$server_ns" addr add 10.203.0.1/24 dev "$server_dev"
ip -n "$client_ns" addr add 10.203.0.2/24 dev "$client_dev"
ip -n "$client_ns" addr add 10.203.0.3/24 dev "$client_dev"
ip -n "$server_ns" -6 addr add fd73:203::1/64 dev "$server_dev" nodad
ip -n "$client_ns" -6 addr add fd73:203::2/64 dev "$client_dev" nodad
for ns in "$server_ns" "$client_ns"; do ip -n "$ns" link set lo up; done
ip netns exec "$client_ns" sysctl -qw "net.ipv4.ip_local_port_range=$client_min $client_max"
ip -n "$server_ns" link set "$server_dev" up
ip -n "$client_ns" link set "$client_dev" up
# Drop locally generated resets before conntrack sees them. A filter/OUTPUT
# DROP is too late: conntrack can already have moved the flow to CLOSE and
# shortened its NAT lifetime. Raw priority -300 precedes conntrack at -200.
# These rules match only the test service; the host firewall is untouched.
for firewall in iptables ip6tables; do
    ip netns exec "$server_ns" "$firewall" -t raw -I OUTPUT 1 -p tcp --sport "$port" --tcp-flags RST RST -j DROP
    ip netns exec "$client_ns" "$firewall" -t raw -I OUTPUT 1 -p tcp --dport "$port" --tcp-flags RST RST -j DROP
done
{
    uname -a
    printf 'port=%s client_ports=%s-%s snat_ports=%s-%s\n' "$port" "$client_min" "$client_max" "$snat_min" "$snat_max"
    printf 'clients=%s parallel=%s bandwidth_bytes_per_second=%s udp_packets_per_second=%s\n' "$clients" "$parallel" "$bandwidth" "$udp_pps"
    printf 'case_seconds=%s soak_seconds=%s runtime=%s\n' "$seconds" "$soak" "$runtime"
} > "$output/environment.txt"
"$binary" -h >> "$output/environment.txt" 2>&1

link_settings() {
    local mtu=$1 gro=$2
    ip -n "$server_ns" link set "$server_dev" mtu "$mtu"
    ip -n "$client_ns" link set "$client_dev" mtu "$mtu"
    ip netns exec "$server_ns" ethtool -K "$server_dev" gro "$gro" gso off tso off
    ip netns exec "$client_ns" ethtool -K "$client_dev" gro "$gro" gso off tso off
    for pair in "$server_ns:$server_dev" "$client_ns:$client_dev"; do
        local ns=${pair%%:*} dev=${pair#*:}
        local actual
        actual=$(ip netns exec "$ns" ethtool -k "$dev" | awk -F ': ' '/^generic-receive-offload:/{print $2}')
        [[ $actual == "$gro" ]] || { echo "Failed to set GRO=$gro on $dev (observed $actual)" >&2; exit 1; }
    done
}

run_case() {
    local name=$1 address=$2 mtu=$3 gro=$4 traffic=$5 host=$6 reconnect=$7 duration=$8 transport=$9
    local prefix="$output/$name-$transport"
    link_settings "$mtu" "$gro"
    ip netns exec "$server_ns" "$binary" -role server -transport "$transport" -address "$address" -mtu "$mtu" \
        -bandwidth "$bandwidth" > "$prefix-server.log" 2>&1 &
    server_pid=$!
    local ready=0
    for ((attempt = 0; attempt < 100; attempt++)); do
        if grep -q '^READY ' "$prefix-server.log"; then ready=1; break; fi
        if ! kill -0 "$server_pid" 2>/dev/null; then cat "$prefix-server.log" >&2; wait "$server_pid"; exit 1; fi
        sleep 0.1
    done
    if [[ $ready != 1 ]]; then echo "Server readiness timed out: $name/$transport" >&2; cat "$prefix-server.log" >&2; exit 1; fi
    client_pids=()
    for ((i = 0; i < clients; i++)); do
        ip netns exec "$client_ns" timeout --signal=TERM --kill-after=5 "$((duration + 45))s" \
            "$binary" -role client -transport "$transport" -address "$address" -mtu "$mtu" \
            -traffic "$traffic" -host "$host" -reconnect "$reconnect" -duration "${duration}s" \
            -bandwidth "$bandwidth" -parallel "$parallel" -udp-pps "$udp_pps" \
            > "$prefix-client-$i.json" 2> "$prefix-client-$i.log" &
        client_pids+=("$!")
    done
    if [[ $name == nat && $transport == faketcp ]]; then
        # Observe conntrack only after every client has verified real payload,
        # while connections are still active. Throughput alone can hide a
        # poisoned CLOSE state whose short timeout is repeatedly refreshed.
        local verified=0
        for ((attempt = 0; attempt < duration * 10; attempt++)); do
            verified=1
            for ((i = 0; i < clients; i++)); do
                if ! grep -q '"event":"verified_data"' "$prefix-client-$i.log"; then verified=0; break; fi
            done
            if [[ $verified == 1 ]]; then break; fi
            sleep 0.1
        done
        if [[ $verified != 1 ]]; then
            cat "$prefix"-client-*.log >&2
            echo 'NAT case did not verify payload before the conntrack check.' >&2
            exit 1
        fi
        for pid in "${client_pids[@]}"; do
            if ! kill -0 "$pid" 2>/dev/null; then
                echo 'NAT client stopped before the conntrack check.' >&2
                exit 1
            fi
        done
        ip netns exec "$client_ns" conntrack -L -f ipv4 -p tcp \
            --orig-src 10.203.0.2 --orig-dst 10.203.0.1 --dport "$port" --src-nat -o extended \
            > "$prefix-conntrack.txt" 2> "$prefix-conntrack.log"
        python3 - "$prefix-conntrack.txt" "$clients" "$port" "$snat_min" "$snat_max" <<'CTPY'
import pathlib
import re
import sys
path = pathlib.Path(sys.argv[1])
entries = [line for line in path.read_text().splitlines() if line.strip()]
expected = int(sys.argv[2])
service_port, snat_min, snat_max = map(int, sys.argv[3:6])
if len(entries) != expected:
    raise SystemExit(f'Expected {expected} TCP SNAT flows, found {len(entries)}: {path.read_text()}')
for line in entries:
    if 'ESTABLISHED' not in line.split():
        raise SystemExit(f'SNAT flow is not ESTABLISHED after payload verification: {line}')
    destinations = re.findall(r'\bdst=(\S+)', line)
    ports = re.findall(r'\bdport=(\d+)', line)
    if destinations != ['10.203.0.1', '10.203.0.3'] or len(ports) != 2 or int(ports[0]) != service_port or not snat_min <= int(ports[1]) <= snat_max:
        raise SystemExit(f'SNAT address/port translation missing or unexpected: {line}')
print(f'Verified {len(entries)} active ESTABLISHED TCP SNAT flows.')
CTPY
    fi
    local status=0
    for pid in "${client_pids[@]}"; do wait "$pid" || status=1; done
    client_pids=()
    if [[ $status != 0 ]]; then
        cat "$prefix"-client-*.log >&2
        echo "Failed: $name/$transport" >&2
        exit 1
    fi
    kill -TERM "$server_pid"
    wait "$server_pid"
    server_pid=
    ip netns exec "$server_ns" ip -s link show dev "$server_dev" > "$prefix-link.txt"
    ip netns exec "$server_ns" tc -s qdisc show dev "$server_dev" > "$prefix-qdisc.txt"
    echo "Passed: $name/$transport"
}

# Compare with ordinary UDP using the same QUIC settings, Brutal target,
# payload verifier and link conditions. This is not a mimic comparison.
for transport in udp faketcp; do
    run_case ipv4 "10.203.0.1:$port" 1500 on tcp '' 0 "$seconds" "$transport"
    run_case ipv6-min-mtu "[fd73:203::1]:$port" 1280 on tcp '' 0 "$seconds" "$transport"
    run_case gro-off "10.203.0.1:$port" 1500 off tcp '' 0 "$seconds" "$transport"
    run_case datagrams "10.203.0.1:$port" 1500 on udp '' 0 "$seconds" "$transport"
    run_case reconnect "10.203.0.1:$port" 1500 on tcp '' 2 "$seconds" "$transport"
done
run_case host "10.203.0.1:$port" 1500 on tcp camouflage.example 0 "$seconds" faketcp

# Exercise real conntrack address and port translation in the client namespace.
for protocol in tcp udp; do
    ip netns exec "$client_ns" iptables -t nat -A POSTROUTING -p "$protocol" \
        -s 10.203.0.2 -d 10.203.0.1 --dport "$port" -j SNAT --to-source "10.203.0.3:$snat_min-$snat_max"
done
for transport in udp faketcp; do
    run_case nat "10.203.0.1:$port" 1500 on tcp '' 0 "$seconds" "$transport"
done
for protocol in tcp udp; do
    ip netns exec "$client_ns" iptables -t nat -D POSTROUTING -p "$protocol" \
        -s 10.203.0.2 -d 10.203.0.1 --dport "$port" -j SNAT --to-source "10.203.0.3:$snat_min-$snat_max"
done

ip netns exec "$server_ns" tc qdisc replace dev "$server_dev" root netem delay 5ms 2ms loss 1% duplicate 0.1% reorder 25% 50%
ip netns exec "$client_ns" tc qdisc replace dev "$client_dev" root netem delay 5ms 2ms loss 1% duplicate 0.1% reorder 25% 50%
for transport in udp faketcp; do
    run_case impaired "10.203.0.1:$port" 1280 on tcp '' 0 "$seconds" "$transport"
done
if ((soak > 0)); then
    for transport in udp faketcp; do
        run_case soak "10.203.0.1:$port" 1280 on tcp camouflage.example 20 "$soak" "$transport"
    done
fi
# A smaller *remote* link must work even when both local endpoint MTUs are
# 1500 and ICMP Packet Too Big / fragmentation-needed replies are blackholed.
# Two routers keep the 1280-byte bottleneck separate from both endpoint links.
add_namespace "$router1_ns"
add_namespace "$router2_ns"
ip -n "$server_ns" link del "$server_dev"
r1c="hyr1c$$"
r1b="hyr1b$$"
r2b="hyr2b$$"
r2s="hyr2s$$"
add_veth "$client_dev" "$r1c"
ip link set "$client_dev" netns "$client_ns"
ip link set "$r1c" netns "$router1_ns"
add_veth "$r1b" "$r2b"
ip link set "$r1b" netns "$router1_ns"
ip link set "$r2b" netns "$router2_ns"
add_veth "$r2s" "$server_dev"
ip link set "$r2s" netns "$router2_ns"
ip link set "$server_dev" netns "$server_ns"
ip -n "$client_ns" addr add 10.203.0.2/24 dev "$client_dev"
ip -n "$router1_ns" addr add 10.203.0.1/24 dev "$r1c"
ip -n "$router1_ns" addr add 10.204.0.1/24 dev "$r1b"
ip -n "$router2_ns" addr add 10.204.0.2/24 dev "$r2b"
ip -n "$router2_ns" addr add 10.205.0.2/24 dev "$r2s"
ip -n "$server_ns" addr add 10.205.0.1/24 dev "$server_dev"
ip -n "$client_ns" -6 addr add fd73:203::2/64 dev "$client_dev" nodad
ip -n "$router1_ns" -6 addr add fd73:203::1/64 dev "$r1c" nodad
ip -n "$router1_ns" -6 addr add fd73:204::1/64 dev "$r1b" nodad
ip -n "$router2_ns" -6 addr add fd73:204::2/64 dev "$r2b" nodad
ip -n "$router2_ns" -6 addr add fd73:205::2/64 dev "$r2s" nodad
ip -n "$server_ns" -6 addr add fd73:205::1/64 dev "$server_dev" nodad
ip -n "$router1_ns" link set "$r1b" mtu 1280
ip -n "$router2_ns" link set "$r2b" mtu 1280
for pair in "$client_ns:$client_dev" "$router1_ns:$r1c" "$router1_ns:$r1b" "$router2_ns:$r2b" "$router2_ns:$r2s" "$server_ns:$server_dev"; do
    ip -n "${pair%%:*}" link set "${pair#*:}" up
done
for ns in "$router1_ns" "$router2_ns"; do
    ip -n "$ns" link set lo up
    ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
    ip netns exec "$ns" iptables -A OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP
    ip netns exec "$ns" ip6tables -A OUTPUT -p ipv6-icmp --icmpv6-type packet-too-big -j DROP
done
ip -n "$client_ns" route add 10.205.0.0/24 via 10.203.0.1
ip -n "$router1_ns" route add 10.205.0.0/24 via 10.204.0.2
ip -n "$router2_ns" route add 10.203.0.0/24 via 10.204.0.1
ip -n "$server_ns" route add 10.203.0.0/24 via 10.205.0.2
ip -n "$client_ns" -6 route add fd73:205::/64 via fd73:203::1
ip -n "$router1_ns" -6 route add fd73:205::/64 via fd73:204::2
ip -n "$router2_ns" -6 route add fd73:203::/64 via fd73:204::1
ip -n "$server_ns" -6 route add fd73:203::/64 via fd73:205::2
for transport in udp faketcp; do
    run_case remote-mtu-v4 "10.205.0.1:$port" 1500 on tcp '' 0 "$seconds" "$transport"
    run_case remote-mtu-v6 "[fd73:205::1]:$port" 1500 on tcp '' 0 "$seconds" "$transport"
done
python3 - "$output" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
results = []
for path in sorted(root.glob('*-client-*.json')):
    result = json.loads(path.read_text())
    if result['verified_payload_bytes'] <= 0:
        raise SystemExit(f'No payload verified: {path.name}')
    result['case'] = path.name
    results.append(result)
(root / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
print(f'Verified {len(results)} client runs. Results: {root / "results.json"}')
PY
