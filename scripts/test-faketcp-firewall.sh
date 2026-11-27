#!/usr/bin/env bash
# Production CLI static-rule/migration tests in private mount/network/PID namespaces.
set -euo pipefail
umask 077
ulimit -c 0

if [[ $EUID -ne 0 ]]; then
    echo 'This test requires root and network/mount/PID namespace support.' >&2
    exit 1
fi
for program in ip iptables ip6tables nft sysctl unshare mount readlink mktemp; do
    command -v "$program" >/dev/null || { echo "Missing test dependency: $program" >&2; exit 1; }
done
script=$(readlink -f -- "${BASH_SOURCE[0]}")
repo=$(cd -- "$(dirname -- "$script")/.." && pwd -P)
output=${HYSTERIA_FAKETCP_FIREWALL_RESULTS:-"$repo/build/faketcp-firewall-results"}
binary=${HYSTERIA_FAKETCP_FIREWALL_TEST_BIN:-"$repo/build/faketcp-firewall.test"}
[[ -x $binary ]] || { echo 'Build first: go test -c -o build/faketcp-firewall.test ./app/cmd' >&2; exit 1; }
binary=$(readlink -f -- "$binary")
mkdir -p "$output"
output=$(cd -- "$output" && pwd -P)

if (($# == 0)); then
    for path in "$repo" "$output" "$binary"; do
        case "$path" in
            /run/*|/var/run/*|/tmp/*|/var/tmp/*)
                echo 'Test paths must be outside directories replaced by the private mounts.' >&2
                exit 1
                ;;
        esac
    done
    [[ ! -e $output/environment.txt ]] || { echo 'Choose a fresh results directory.' >&2; exit 1; }
    runtime=$(mktemp -d "$output/runtime.XXXXXXXX")
    mkdir -p "$runtime/run" "$runtime/tmp"
    export HYSTERIA_FAKETCP_FIREWALL_RESULTS="$output" HYSTERIA_FAKETCP_FIREWALL_TEST_BIN="$binary"
    HYSTERIA_FAKETCP_PARENT_NETNS=$(readlink /proc/self/ns/net)
    HYSTERIA_FAKETCP_PARENT_MNTNS=$(readlink /proc/self/ns/mnt)
    export HYSTERIA_FAKETCP_PARENT_NETNS HYSTERIA_FAKETCP_PARENT_MNTNS
    exec unshare --mount --net --pid --fork --kill-child=KILL --mount-proc --propagation private \
        bash "$script" --isolated "$runtime"
fi
if [[ $# != 2 || $1 != --isolated || $$ != 1 ||
      $(readlink /proc/self/ns/net) == "${HYSTERIA_FAKETCP_PARENT_NETNS:-}" ||
      $(readlink /proc/self/ns/mnt) == "${HYSTERIA_FAKETCP_PARENT_MNTNS:-}" ]]; then
    echo 'Failed to enter private test namespaces.' >&2
    exit 1
fi
runtime=$2
[[ $runtime == "$output"/runtime.* && -d $runtime/run && -d $runtime/tmp ]] || exit 1
mount --no-mtab --bind "$runtime/run" /run
if [[ $(readlink -f /var/run) != /run ]]; then
    mount --no-mtab --bind "$runtime/run" /var/run
fi
export TMPDIR="$runtime/tmp"
mount --no-mtab --bind "$TMPDIR" /tmp
mount --no-mtab --bind "$TMPDIR" /var/tmp
uname -a > "$output/environment.txt"
export HYSTERIA_FAKETCP_FIREWALL_INTEGRATION=1
"$binary" -test.run='^TestFakeTCPAutoFirewallIntegration$' -test.timeout=6m -test.v \
    2>&1 | tee "$output/integration.log"
