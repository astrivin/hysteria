# Native FakeTCP validation — experimental candidate

Both directions completed the recorded low-load minute tests and 61-minute stability runs, and final production/cleanup comparisons passed. This remains an experimental candidate: high-load capacity, parity with mimic, hardware-offload acceptance and WSL2/Android runtime acceptance are incomplete. The scope, observed socket drops and retained failures are recorded below.

## Source and artifacts

The tested source is `81b1fb4618d5fca60aa4a181714bb6b080ec0d5b`, based on the initial feature commit `e076fcde8395be574d8a4092438a3d45c48322ea`. The comparison baseline is `7040c16752192e1ba72ee251005809a6bd9c9fd6`. Changes since the feature commit affect the integration harness, monitoring tests, CI and workspace checksums; production FakeTCP transport code is unchanged.

The UDP harness previously updated its verified byte counter only after the transfer returned. A diagnostic restoring that behavior reproduced missing progress after two seconds. The fix updates the shared atomic counter after each validated datagram. Valid/corrupt payload regressions passed ten race repetitions and the complete four-test harness race suite on ARM64. This makes the long UDP checkpoints usable without changing the transport.

Server builds used Go 1.26.0, clean standalone Git checkouts, `-trimpath -buildvcs=true`, and stripped application/harness binaries. Both Linux architectures report the full tested revision and `vcs.modified=false`. Application metadata includes the candidate commit, build time, toolchain and target architecture. Both deployed bundles passed their SHA256 manifests before running tests.

| Server-tested file | SHA256 |
| --- | --- |
| Linux amd64 application | `0db101eb25d4855ee5d5841a744e3a6772c520d5b677403af6a6965477d2a004` |
| Linux amd64 integration harness | `2b2661063ac7c3c2867e8828dc1c47a6d30002076aef2ef2230e65ba92ba9b8d` |
| Linux arm64 application | `7625c778ea12c7846e4e6ee43b4a7d4234b7384984390f10b2b32c4ea6aeb85d` |
| Linux arm64 integration harness | `5afb1071a1b060238a8d74991d9e74a44487ac87afbe2bbb7328d5414ec7a400` |

[Actions run 45645156812](https://github.com/astrivin/hysteria/actions/runs/45645156812) built four candidate programs with Go 1.26.11. The program ZIP's GitHub API digest is `e9524590598102718b5744abc141005e896c32e3f124e71af135c5451b61e678`; the downloaded archive and every extracted program matched it and the included manifest. ELF architecture/loader checks passed; the Linux ARM64 program's version command also ran on ARM64. Android builds target API 29 and remain untested on devices.

| CI program | SHA256 |
| --- | --- |
| hysteria-linux-amd64 | `6d48d909f0b4a68ab9c08802ca9243929c9f7d6d477cedaaad32a61d31e257c8` |
| hysteria-linux-arm64 | `70ff179654f534fe6434adc8b4dd28d750753368359400a99606c9c0c0f20c6a` |
| hysteria-android-arm64 | `919a426aea2a96c211a12d53a4b32e3eb5c8f71377eea8bb8fdf1826252748f4` |
| hysteria-android-armv7 | `1b82162f1067e5587db0e159e48b977e0f74c53ac73c7952f4570515e89ce819` |

CI and server manifests are separate because their toolchains/build flags differ. The commit containing this report changes only documentation relative to the tested81b source. Final clean builds embed that report revision and use separate manifests under `/root/tmp/hy2/20261125T150108Z-final`; the build compares the app/core/extras/scripts trees with81b before compiling. Final program hashes and checks are retained with those programs and in the private continuation record. This remains a candidate branch.

## Environment and production protection

| Role | System/kernel | Resources and verified runtime envelope |
| --- | --- | --- |
| GCP | Debian 13, amd64, `6.12.94+deb13-cloud-amd64` | 2 online logical CPUs reported by getconf/nproc/sysfs, approximately 964 MiB RAM; CPU 0.2 logical core, MemoryHigh/Max 160/192 MiB |
| Oracle | Ubuntu 24.04.4 LTS, arm64, `6.17.0-1011-oracle` | 4 CPUs, 24 GiB RAM; CPU 0.5 core, MemoryHigh/Max 320/384 MiB |

Runtime groups used `GOMAXPROCS=1`, `GOMEMLIMIT=64MiB`, swap 0, TasksMax 128, NOFILE 512 and a 64 MiB file limit. Oracle builds used a separate 0.5-core/1.5-GiB envelope. Only the two instrumented fuzz cases used a 128 MiB file limit for Go's 100 MiB worker shared file; their CPU/memory limits were unchanged. Every group waited until effective cgroup limits were verified. Only one load group ran on each host.

Test ports were 6666–7777. Existing applications and their protected 20000–50000 listeners were not reconfigured or used as load endpoints. No global installs, module loading, host sysctl/route/physical-interface changes, firewall flushes, broad conntrack deletion or process-name killing were used. Private namespace topology, transient units and exact owned RST tables were explicitly registered. Both hosts passed 60-second resource baselines.

The host UTC clocks differed by approximately 17–18 minutes. No clocks were changed. Per-host timestamps and monotonic harness/resource durations are retained separately.

The supplied GCP instance description was 1 core/1 GiB; final read-only checks report two online logical CPUs. The test quota remained 20000/100000 microseconds, or 0.2 of one logical core. Host CPU/IRQ/softirq percentages use aggregate tick deltas, while process CPU seconds use the measured CLK_TCK=100 on both hosts.

## Regression and real-kernel results

| Test | Status | Evidence scope |
| --- | --- | --- |
| Baseline/candidate full CI regression | PASS | 261/300 top-level tests passed, zero failed, 1/2 skipped; both exit 0 |
| Affected server unit/config/replay/Brutal regressions | PASS | Both architectures; MTU1280 matrix repeated ten times and explicit dual-stack one-minute simulated soak |
| Native ARM64 race and CI amd64 race | PASS | Real race binaries, no race diagnostics; harness progress race checks included |
| Guided parser fuzz | PASS | GCP 9804 executions (20 seconds configured, 21 observed), Oracle 41326 (20 seconds), two workers each; coverage-guided binaries |
| CI monitor regression and codec microbenchmarks | PASS | Three monitor behavior checks and nine benchmark cases; benchmarks are local codec costs, not network throughput |
| GCP kernel loopback | PASS for 18 cases | IPv4/IPv6, UDP/native, MTU, Host, DATAGRAM, reconnect and wildcard |
| Oracle kernel veth | PASS for 28 cases | Above plus actual GRO on/off and IPv6 link-local |
| Strict app/YAML/forwarding | PASS | GCP 11 and Oracle 19 positive cases, six explicit CA/SNI/auth failures and recovery per host |
| Oracle private SNAT | PASS for 8 client runs | Two simultaneous clients, address/port translation, MTU1280, UDP/native/Host/reconnect, active ESTABLISHED/ASSURED after verified data |
| Two-client matrices | PASS | Fourteen configurations and 28 client runs on each host |
| Oracle remote MTU blackhole | PASS for four cases | IPv4/IPv6 × UDP/native, endpoints/config 1500, middle link1280; each 15 seconds/1,835,008 verified bytes and 12 actual dropped PMTU replies |
| CI isolated network | PASS | 21 configurations, 42 client runs, 14,140,544,976 verified payload bytes; real NAT/netem/MTU blackhole and 600-second UDP/native fault/reconnect cases |

The full regression skip was `TestUDPPortRedirectIntegration` in both sources because the test lacked its required privileges. The candidate also skipped the opt-in `TestQUICBrutalShortSoak`; it then passed explicitly. The four historical environment failures all passed in current CI and were not exempted automatically.

App checks validated 1 MiB TCP and 64 unique UDP sequences per positive case, including a 15-second application idle interval. The totals were 11,534,336/19,922,944 TCP bytes and 704/1216 unique UDP sequences on GCP/Oracle. UDP retries/duplicates are retained in the raw checker results. This idle interval is not proof of pure line silence or NAT expiry; QUIC control traffic may continue. App outbound/TLS verification ran in private namespaces, while WAN harness tests used a fixed memory echo and self-signed certificates with verification disabled.

Oracle SNAT used the inspected, already-loaded xt compatibility targets through iptables-nft with `--modprobe /bin/false`; post-install module-set comparison found no additions. Private namespaces and their exact tuples were cleaned by the driver. GCP loopback does not replace unavailable private veth or hardware GRO testing.

CI network results are separate: amd64, kernel `7.0.0-1020-azure`, Go1.26.11, two clients × two streams, 12,500,000 bytes/s per direction/connection and 8000 UDPpps. Fault/reconnect soaks were 600 seconds per transport, approximately 26 Mbps per client and 47 connections. These are validated goodput at configured targets, not measured peak capacity.

CI codec benchmarks used an AMD EPYC 7763: marshaling 1200/1400-byte segments took 308.2/353.4 ns for IPv4 and 320.7/366.3 ns for IPv6. All nine marshal/GRO frame benchmark cases reported zero allocations. These measurements include neither Raw Socket nor QUIC/network costs and provide no mimic comparison.

## Public low-load matrix

Both directions used one client/stream, 125000 bytes/s per direction, 65536-byte TCP transfers and 50 requested UDPpps; default MTU1500, fixed client source7001/server6666. Independent probes established both TCP and UDP NAT-visible tuples. Exact RST-only rules ran before conntrack at priority -300. Active native tuples were checked for ESTABLISHED after load began. Bounded full captures confirmed configured Host prefaces and zero checksum errors in inspected packets.

| Case | GCP client → Oracle server | Oracle client → GCP server |
| --- | --- | --- |
| UDP baseline, 15s | 1,835,008 verified bytes, 0.951Mbps | 1,835,008 bytes, 0.954Mbps |
| Native, 15s | 1,835,008 bytes, 0.950Mbps | 1,835,008 bytes, 0.944Mbps |
| Native Host, 15s | 1,835,008 bytes, 0.954Mbps | 1,769,472 bytes, 0.943Mbps |
| Native DATAGRAM, 45s | 2242 sent/2238 validated returns, 3,133,200 bytes | 2242 sent/2240 returns, 3,136,000 bytes |
| MTU1280, 15s | 1,835,008 bytes, 0.947Mbps | 1,835,008 bytes, 0.948Mbps |
| Host + reconnect2, 30s | 24 connections, 3,145,728 bytes, 0.824Mbps | 24 connections, 3,080,192 bytes, 0.815Mbps |

All successful formal cases had client/server exit and supervisor status0. The original reverse DATAGRAM attempt was aborted by the controller; its successful repeat has a separate case directory. Each direction's exact short-test RST table was removed after ownership/content review. Residual owned conntrack entries were allowed to expire normally; no host-wide clearing was used.

Goodput counts a verified request/echo payload once, not both wire directions. Harness DATAGRAM returns are not deduplicated; sent/validated counters do not establish an exact unique-packet loss percentage. The app checker does provide unique/duplicate/retry counts for its separate workload.

## Minute and hour stability

The authorized workload runs native continuous TCP+Host, native DATAGRAM+Host, native Host/reconnect2 and UDP-transport continuous TCP simultaneously inside one group per host. Each flow has one client/stream. Native sourceports7001–7003 and UDP7004/server6666 were independently observed in bounded probes before installing exact three-tuple RST rules. This is a stability workload; simultaneous flows do not form an independent peak-performance comparison.

The steps are 300 seconds at125000B/s per TCP flow, 600 seconds at500000B/s, then3660 seconds at the same target to provide hour duration margin. All keep the existing CPU/memory envelope. The configured targets are 1/4Mbps per TCP flow and 50 requested DATAGRAMpps; achieved rates are lower under the hard quota.

| Direction / step | Status | Native TCP bytes / Mbps | UDP-transport TCP bytes / Mbps | Host reconnect connections / bytes | DATAGRAM sent / validated / bytes |
| --- | --- | --- | --- | --- | --- |
| GCP → Oracle, 300s | PASS within recorded load | 30,408,704 / 0.810 | 30,408,704 / 0.810 | 197 / 25,821,184 | 11991 / 11980 / 16,772,000 |
| GCP → Oracle, 600s repeat | PASS within recorded load | 104,202,240 / 1.389 | 104,267,776 / 1.390 | 532 / 69,664,768 | 15521 / 15507 / 21,709,800 |
| GCP → Oracle, 3660s repeat | PASS within recorded load | 442,695,680 / 0.967 | 439,615,488 / 0.961 | 2275 / 298,057,728 | 65988 / 65949 / 92,328,600 |
| Oracle → GCP, 300s | PASS within recorded load | 19,791,872 / 0.527 | 20,643,840 / 0.549 | 122 / 15,925,248 | 12484 / 12446 / 17,424,400 |
| Oracle → GCP, 600s | PASS within recorded load | 66,060,288 / 0.880 | 69,861,376 / 0.931 | 343 / 44,892,160 | 27488 / 27144 / 38,001,600 |
| Oracle → GCP, 3660s | PASS within recorded load | 447,217,664 / 0.978 | 462,225,408 / 1.010 | 2312 / 303,038,464 | 172282 / 171863 / 240,608,200 |

Each completed row has four positive content results, at least the configured effective duration, client/server gated exit0, supervisor0 and every registered child cleanup exit0. DATAGRAM counts are not deduplicated. UTC intervals below are the respective clients' recorded clocks, not a shared cross-host clock.

| Client / step | Client UTC start–finish on 2026-11-25 | Effective client duration range |
| --- | --- | --- |
| GCP / 300s | 17:30:26–17:35:27 | 300.001–300.498s |
| GCP / 600s repeat | 17:55:56–18:05:57 | 600.003–600.195s |
| GCP / 3660s repeat | 19:21:13–20:22:15 | 3660.799–3660.979s |
| Oracle / 300s | 20:40:09–20:45:10 | 300.007–300.728s |
| Oracle / 600s | 20:45:20–20:55:21 | 600.007–600.370s |
| Oracle / 3660s | 20:55:30–21:56:31 | 3660.007–3660.308s |

The first forward600-second run's four Go content results passed, but its supervisor failed opening a cgroup PID file during automatic collection. The first forward3660-second run's four Go content results also passed, but the client supervisor reported1 because its terminal is-active check preceded reading the completed exit file. Both attempts remain formal FAIL (supervision tooling) with separate evidence. PID snapshot correction passed four rapid-GC runs per host; a deterministic terminal-race shim then reproduced old supervisor1/fixed supervisor0 on both hosts, with gated exit0. Atomic exit publication and terminal adjudication were fixed before the distinct successful600/3660-second repeats. Transport source81b was unchanged.

In the successful forward10-minute run the GCP group used0.175core average, peak aggregate RSS92.7MiB, cgroup memory53.6MiB, OOM0 and at most8fd/7threads per Go process. Approximately82.1% of CPU periods were throttled. Native/UDP TCP goodput was1.389/1.390Mbps despite the4Mbps target; native reconnect established532connections and DATAGRAM sent15521/validated15507. Thus the configured4Mbps/50pps target is not an achieved capability claim.

Every30seconds the harness logs verified bytes, heap and goroutines. Approximately one-second samples record process RSS/CPU/fd/threads, cgroup accounting, host CPU/softirq/steal/memory, owned conntrack/socket state, queue/drop counters and interface diagnostics. Protected production PIDs and disk headroom are checked throughout. Final analysis compares successive10-minute windows after10minutes warmup, alongside GC/heap and session cleanup; a final RSS value alone is not a leak verdict. Interface counters include production traffic and do not establish per-flow wire bytes.

Forward3660-second formal repeat resource evidence:

| Host | Samples / monotonic span | Mean group logical cores | Throttled periods | Peak group RSS / cgroup memory | Peak host CPU / minimum available memory | OOM / oom_kill |
| --- | --- | --- | --- | --- | --- | --- |
| GCP client | 2744 / 3664.51s | 0.165 | 78.31% | 93.07 / 66.82MiB | 25% / 577.97MiB | 0 / 0 |
| Oracle server | 3526 / 3668.35s | 0.056 | 0.0034% | 44.94 / 33.87MiB | 22% / 22638.23MiB | 0 / 0 |

After warmup, successive10–20/20–30/30–40/40–50/50–60 minute RSS medians in MiB were:

| Process | Five RSS medians | fd median |
| --- | --- | --- |
| GCP native TCP+Host | 17.945 / 17.891 / 17.949 / 17.953 / 17.957 | 8 throughout |
| GCP native DATAGRAM+Host | 17.965 / 17.969 / 17.969 / 19.973 / 19.973 | 8 throughout |
| GCP native Host/reconnect | 16.844 / 16.727 / 16.852 / 16.605 / 16.727 | 8 throughout |
| Oracle native server | 14.324 / 14.375 / 14.398 / 14.445 / 14.465 | 8 throughout |

Each client produced122 checkpoints. Native TCP/DATAGRAM/reconnect window goroutine medians were13/12/12–13; heap medians were approximately1.49–2.34MiB. Native server post-GC heap readings used integer-MB gctrace output and were below1MiB, rather than proof of zero memory. No RSS investigation threshold or sustained fd growth appeared in these windows. The observed owned raw/UDP socket drop sum was0. Native TCP and DATAGRAM tuples remained ESTABLISHED; reconnect tuples temporarily changed handshake state, with at most2/7 consecutive bad-state observations on GCP/Oracle, below the driver's10-observation failure gate. This covers the recorded sampling interval and achieved workload.

Forward-hour host accounting recorded GCP softirq50.77s/0.843% and steal20.32s/0.337%, and Oracle softirq12.77s/0.087% and steal23.15s/0.158%; IRQ counters did not advance. Those totals include production activity and must not be charged entirely to the transport or added to process CPU again. Per-process user/system samples and spacing are retained in the private resource summaries.

Reverse3660-second formal resource evidence:

| Host | Samples / monotonic span | Mean group logical cores | Throttled periods | Peak group RSS / cgroup memory | Peak host CPU / minimum available memory | OOM / oom_kill |
| --- | --- | --- | --- | --- | --- | --- |
| GCP server | 2904 / 3665.69s | 0.167 | 76.89% | 58.21 / 43.31MiB | 40% / 596.88MiB | 0 / 0 |
| Oracle client | 3479 / 3660.03s | 0.076 | 0.0029% | 74.31 / 53.71MiB | 23% / 22627.38MiB | 0 / 0 |

| Process | Five post-warmup RSS medians in MiB | fd median |
| --- | --- | --- |
| GCP native server | 18.852 / 18.848 / 18.844 / 18.813 / 18.906 | 8 throughout |
| Oracle native TCP+Host | 14.172 / 14.238 / 14.320 / 14.324 / 14.324 | 8 throughout |
| Oracle native DATAGRAM+Host | 14.191 / 14.195 / 14.211 / 14.211 / 14.211 | 8 throughout |
| Oracle native Host/reconnect | 14.512 / 14.551 / 14.590 / 14.613 / 14.598 | 8 throughout |

All four clients produced122 checkpoints; post-warmup goroutine medians stayed12–12.5 and heap medians approximately1.49–2.82MiB. Native server gctrace post-GC heap medians were1 integer MiB. No RSS investigation threshold, sustained fd/goroutine growth, content failure or permanent progress stall was observed in the recorded windows. Reconnect bad-state counters reached at most3 consecutive samples per host; one GCP UDP-tuple observation was temporarily missing. Host IRQ did not advance; GCP softirq61.93s/1.020% and steal13.12s/0.216%, Oracle softirq16.99s/0.117% and steal30.87s/0.212% include production activity.

The GCP native server's shared Raw receive socket recorded428 kernel drop-counter increments in35 observations, beginning around80.8s and continuing through3640.8s. Its UDP-baseline socket recorded0; Oracle observed owned raw/UDP socket drops were0. The Raw counter covers all three native flows, so it cannot be assigned entirely to the DATAGRAM workload. Reliable TCP still completed content checks. DATAGRAM172282 sent/171863 validated returns are not deduplicated and cannot establish an exact unique-packet loss percentage. The drop cause was not isolated by this quota-limited run; it is recorded rather than treated as zero loss. Server stderr contained no panic/fatal/corruption/timeout diagnostics. Both formal hour conclusions are stability at their achieved workloads, with high-load capacity still BLOCKED.

## Retained limitations

| Scope | Status | Reason |
| --- | --- | --- |
| GCP private veth/GRO/router | BLOCKED | veth is a module and was not loaded; loading it was forbidden |
| Server netem loss/reorder/duplicate injection | BLOCKED | Required sch_netem/ingress modules not already loaded; CI isolation has separate evidence |
| Fair mimic, unrestricted peak or hardware-offload comparison | BLOCKED | Missing TC/BPF dependencies and no authorized independent physical interface; no production attach or removal of hard quotas |
| Sustained high-load / 4Mbps-per-flow and 50pps capacity acceptance | BLOCKED at this envelope | Actual rates did not reach the configured targets; successful hour records establish stability at their achieved workloads |
| Real WSL2 | NOT_RUN | No authorized device; Linux cloud results are not WSL/NAT/suspend/network-switch acceptance |
| Root Android | NOT_RUN | No authorized device; cross-build/ELF checks are not SELinux/radio/power/thermal acceptance |
| Full app public outbound and pure silent NAT expiry | NOT_RUN | App verification remained private; application idle may contain keepalive |
| Public IPv6 path | NOT_RUN | No verified public IPv6 tuple/path between the hosts; private kernel/app IPv6 coverage is separate |

There is no claim that native reaches or exceeds mimic. Rate-limited target attainment, simulated tests, CI soaks and cross compilation do not substitute for the corresponding unavailable acceptance scope.

## Evidence, cleanup and release state

Raw logs, addresses, credentials, key paths, captures, namespace ownership records and per-case metrics are retained privately under the authorized per-round server directory. Only this sanitized report is intended for Git. Early failures and their distinct repeats are retained, including VCS-less linked-worktree builds, fuzz shared-file initialization, missing private drivers, SNI rejection-path correction, SSH control interruption and supervision auto-GC races.

Final current-round cleanup/production comparison: PASS on both hosts, gated/supervisor exit0. No owned process or registered load unit remained; all four current-round short/long RST tables were absent on both hosts after exact ownership checks and deletion. Initial and fresh protected listener/PID sets matched (GCP1/Oracle5 listeners). All12/29 initially running persistent service states matched. Interfaces/addresses/MTU, main IPv4 and IPv6 routes, physical-interface offload and normalized nft firewall structure matched saved baselines; modules had no additions or removals. IPv6/offload comparison used the existing earlier private preflight records. Raw evidence includes registered-unit states, process/namespace scans, original/after snapshots, ownership/deletion records and per-case timestamps under `/root/tmp/hy2/20261125T150108Z`.

The private outer-job index retained37GCP jobs (33PASS/4FAIL) and42Oracle jobs (39PASS/2FAIL/1incomplete startup). These are job outcomes, including deliberate old-supervisor diagnostics and distinct failed setup attempts; they are not protocol acceptance totals. Successful repeats remain separate. Residual conntrack entries were allowed to expire normally. No global state snapshot was restored, production application replaced or stable release created. Programs, private CA/auth and raw evidence remain in the authorized test directories for review and continuation.
