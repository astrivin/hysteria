# 原生 FakeTCP 实机验收手册：交给本地 Codex

本手册用于在用户授权的两台生产服务器上继续验收 `faketcp` 分支。用户已允许先提交、推送候选实现，再由能连接服务器的本地 Codex 执行测试；**提交和构建成功不等于验收通过**。执行者应完成能安全完成的阶段、修正发现的问题，并保留不能完成的项目及原因，不把 `BLOCKED`、`SKIP` 或监控强制终止记成 `PASS`。

此前云端开发环境无法建立两台机器的 SSH 连接，也没有 Raw Socket/namespace 权限；没有在这两台机器上完成真实测试。本文件是执行计划，不是测试结果。即使下述验收全部完成，结论也只能覆盖记录的提交、设备、内核、网络和负载范围，不能证明所有环境永不失败。

先阅读 [实现与配置说明](FAKETCP.md)、[变更说明](FAKETCP_CHANGES.md)、[隔离网络矩阵脚本](scripts/test-faketcp-netns.sh)、[监控工具说明](scripts/faketcp/README.md) 和 [mimic 隔离对照计划](scripts/faketcp/MIMIC-PLAN.txt)。

## 1. 授权范围与生产保护

| 项目 | GCP | Oracle |
| --- | --- | --- |
| 主机变量 | `GCP_HOST` | `ORACLE_HOST` |
| 已知系统 | Debian，x86-64 | Ubuntu，ARM64 |
| 已知规格 | 1 核 / 1 GB | 4 核 / 24 GB |
| SSH | `root`，端口 `22` | `root`，端口 `22` |
| 服务器上的测试文件根目录 | `/root/tmp/hy2` | `/root/tmp/hy2` |
| 允许使用的测试端口 | `6666–7777` | `6666–7777` |
| 必须保护的现有服务端口 | `20000–50000` | `20000–50000` |

以上规格须由只读预检重新确认。真实地址由用户通过私有渠道提供，只在本地设置 `GCP_HOST`、`ORACLE_HOST`。SSH 私钥使用本地变量 `SSH_KEY` 指向已有文件，**不复制到服务器，不写入仓库、补丁、日志或提交说明**；本机私钥路径、真实主机地址、测试口令及未脱敏的生产信息也不进入公开仓库。

服务器上的二进制、脚本、配置、测试证书、口令、日志、抓包、锁的私有副本、运行报告一律放在 `/root/tmp/hy2`。为每轮建立独立子目录，保留旧结果，不覆盖或递归删除用户已有文件。systemd transient unit、cgroup、网络 namespace、临时防火墙表是本轮有所有权记录的短期控制对象；它们不是部署新的持久服务。

执行边界：

- 不停止、重启、重载、替换或重新配置现有 Hysteria 和其他应用。不以它们作为负载工具的服务端，不复用生产认证或证书。
- 不使用 `pkill`、`killall`、按名字批量杀进程、全表 conntrack 删除、`iptables -F`、`nft flush ruleset`、全局防火墙恢复或批量删除 namespace。
- 不修改宿主全局 sysctl、物理网卡 MTU/offload/qdisc、生产路由或已有 XDP/TC 程序。mimic 只挂在本轮新建、与宿主网络隔离的私有 veth 上。
- 不在生产机执行全局软件安装/升级、内核升级、DKMS、`modprobe`、`insmod`、`rmmod`。缺少必需能力、现有依赖或已内建/加载的标准内核功能时，标记 `BLOCKED`，改用另行获准的隔离验收机。
- `ip link add`、iptables、TC/BPF 操作也可能触发内核自动加载模块；不能用自动加载绕过上述限制。预检无法确认所需功能已内建或已加载时，不进入该阶段。
- 所有负载先进入已验证生效的硬资源限额，再启动。`nice`、`ionice`、Go 的 `GOMEMLIMIT`、流量目标值和采样监控都不能代替 CPU/内存硬限额。
- 对公网测试只添加经过审核的精确 RST 规则，先保存删除方法，再安装。既有入站策略和云防火墙不作整段开放；如果阻断测试流，只处理已获准的两端 IP、协议和具体测试端口，不能影响其他规则或服务。

## 2. 固定候选提交和证据目录

所有本地命令在用户指定的工作区执行；本地私有记录使用仓库外的 `LOCAL_RUN`。以下变量必须由本地 Codex 明确设置，不保留占位符运行：

```sh
GCP_HOST='通过私有渠道获得的地址'
ORACLE_HOST='通过私有渠道获得的地址'
SSH_KEY='本机已有私钥的绝对路径'
LOCAL_RUN='本机仓库外的本轮私有目录'
```

使用已有、经用户确认的 SSH host key；没有已验证的 host key 时先与可信渠道核对，不使用 `StrictHostKeyChecking=no`。关闭 agent forwarding，只用指定密钥。

```sh
git fetch origin faketcp
CANDIDATE_COMMIT=$(git rev-parse --verify 'origin/faketcp^{commit}')
BASE_COMMIT=7040c16752192e1ba72ee251005809a6bd9c9fd6
printf '%s\n' "$CANDIDATE_COMMIT"
git status --short
```

将 **40 位 SHA** 与用户最终收到的提交链接核对，再建立独立、干净的 candidate worktree。不要在有用户未提交修改的工作区切分支或复原文件。后续构建、传输、测试始终使用这个 SHA；不要测试中途再次解析一个已经移动的分支名。

```sh
umask 077
mkdir -p "$LOCAL_RUN"
git worktree add --detach "$LOCAL_RUN/candidate" "$CANDIDATE_COMMIT"
git worktree add --detach "$LOCAL_RUN/baseline" "$BASE_COMMIT"
printf '%s\n' "$CANDIDATE_COMMIT" > "$LOCAL_RUN/CANDIDATE_COMMIT"
printf '%s\n' "$BASE_COMMIT" > "$LOCAL_RUN/BASE_COMMIT"
```

为两机使用同一本轮编号，例如 `UTC时间-提交前12位-轮次`，只包含字母、数字、`_`、`-`。每个目标建立 `/root/tmp/hy2/<RUN_ID>`，下文记为 `RUN_DIR`。记录：候选 SHA、基线 SHA、源码是否干净、Go/编译器版本、每个二进制 SHA256、架构、内核、实际参数、开始/结束 UTC 时间、退出码以及所有本轮控制对象的名称。源码更改后必须生成新 SHA、新构建和新结果目录，不能继续沿用旧版本的报告。

## 3. 本地回归与原始基线比较

先在本地或隔离构建环境安装仓库要求的工具；这些安装不发生在生产服务器。工具链以 `go.work` 为准，目前要求 Go 1.26。仓库 Python 测试依赖按 `uv sync` 准备，运行 Go 测试时让当前工作树的 `.venv/bin` 位于 PATH 前部。将 Go cache、临时文件和 Python 环境放在本机授权工作区；不要把测试依赖安装到服务器的系统 Python。

在 candidate 和 baseline 各自的工作树先执行 `uv sync`，并在各自测试子 shell 内执行 `export PATH="$PWD/.venv/bin:$PATH"`，使测试通过 `python` 调用的依赖也可用。然后运行同条件全量测试，分别保存 stdout、stderr 和退出码：

```sh
PATH="$PWD/.venv/bin:$PATH" go test -json -count=1 -timeout=10m ./core/... ./extras/... ./app/...
```

candidate 另运行：

```sh
go test -race -count=1 -timeout=10m ./extras/transport/faketcp/...
go test -run TestQUICBrutalMTU1280 -count=10 -v ./extras/transport/faketcp
FAKETCP_SIM_SOAK=1m go test -run TestQUICBrutalShortSoak -count=1 -v ./extras/transport/faketcp
go test -run '^$' -fuzz FuzzParseSegmentAndFrames -fuzztime=20s -parallel=2 ./extras/transport/faketcp
go test -run '^$' -bench . -benchmem ./extras/transport/faketcp
python3 -m unittest discover -s scripts/faketcp -p 'test_*.py'
```

不要通过管道末端的 `tee` 返回码掩盖 Go 失败；使用 `set -o pipefail` 或独立保存退出码。检查测试实际存在且确实运行：`go test -run` 匹配零个测试时也可能返回成功。不要将默认未启用的 soak 当成通过。

必须检查以下状态机回归包含在所测候选中，并全部通过：

- 同四元组从 A 重连到 B、再重连到 C；随后重放 A/B 的 hello 和旧 ACK，当前 peer、接收进度及发送序号不回退，旧代数据不能替换当前连接。
- 当前代 hello 重复具有幂等性；welcome 丢失可重试；cookie 更新或跨时间窗时仍可完成正确握手，不能在重试中锁死，也不能接受已淘汰代重放。
- SYN/SYN-ACK/hello/welcome 丢包、乱序、重复；序号回绕、旧 ACK、并发 close/deadline；双栈 checksum、非法 offset/长度、Host 注入拒绝和 GRO 帧截断。
- MTU 1280，QUIC 初始包 1200，PMTUD 开启；Brutal 极低 RTT 下 MTU 探测不能再次耗尽最小窗口而永久停滞。

历史开发容器中有下列四项失败，并已在原始基线复现。它们是**历史证据，不是新环境可自动豁免的名单**：

| 测试 | 当时的环境原因 |
| --- | --- |
| `TestMasqueradeProxyUnixURLStyles` | 容器没有 `/tmp` |
| `TestMasqueradeProxyUnixReusesConnections` | 同上 |
| `Test_fdControlUnixSocketImpl` | AF_UNIX 被执行环境禁止，`EPERM` |
| `tinydoh/TestResolver` | 网络拦截的 `1.1.1.1` TLS 证书缺少对应 IP SAN |

如果本机有这些失败，必须用同环境基线复现、比对原始错误，并标记为环境阻塞；不能直接 `-skip`。基线通过而候选失败，或出现新的失败，均先修正。旧报告中的测试数量不应当作当前提交的固定数量：后续 harness、监控和重放回归增加了测试。

以上测试包含模拟 packetIO；它们能发现生产协议和真实 QUIC 核心的问题，但不能证明内核 Raw Socket、NAT、网卡 offload 或公网稳定性。

## 4. 两架构构建、传输与校验

在构建环境为 Linux amd64 和 arm64 同时生成 app 与 integration 工具，不在 GCP 1 GB 机器现场编译。确保所构建源码对应固定 SHA，工作区没有未审阅修改；依赖下载如补充 `go.work.sum`，先审查和处理，不把 dirty build 标成纯提交构建。

```sh
cd "$LOCAL_RUN/candidate"
git status --short
go version
for arch in amd64 arm64; do
    mkdir -p "$LOCAL_RUN/bundle-$arch/scripts/faketcp"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=true \
        -o "$LOCAL_RUN/bundle-$arch/hysteria" ./app
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=true \
        -o "$LOCAL_RUN/bundle-$arch/faketcp-integration" ./extras/transport/faketcp/internal/integration
    cp scripts/test-faketcp-netns.sh "$LOCAL_RUN/bundle-$arch/scripts/"
    cp scripts/faketcp/preflight.sh scripts/faketcp/monitor.py "$LOCAL_RUN/bundle-$arch/scripts/faketcp/"
    printf '%s\n' "$CANDIDATE_COMMIT" > "$LOCAL_RUN/bundle-$arch/CANDIDATE_COMMIT"
    go version -m "$LOCAL_RUN/bundle-$arch/hysteria" > "$LOCAL_RUN/bundle-$arch/go-build-info.txt"
    go version -m "$LOCAL_RUN/bundle-$arch/faketcp-integration" >> "$LOCAL_RUN/bundle-$arch/go-build-info.txt"
    (
        cd "$LOCAL_RUN/bundle-$arch"
        sha256sum hysteria faketcp-integration CANDIDATE_COMMIT go-build-info.txt \
            scripts/test-faketcp-netns.sh scripts/faketcp/preflight.sh scripts/faketcp/monitor.py > SHA256SUMS
    )
done
```

核对 `file`/ELF 架构、Go build info 的 `vcs.revision` 与 `vcs.modified=false`，将实际构建命令及工具版本存入私有构建记录。GCP 使用 amd64，Oracle 使用 arm64；以预检实测架构为准。

先完成下一节的只读预检，再通过已验证的 SSH/SCP 通道传输目标架构 bundle 至 `RUN_DIR/bundle`。可以在本机打包，先检查归档不含绝对路径、`..` 或意外 symlink，再在本轮目录解包。服务器上执行：

```sh
cd "$RUN_DIR/bundle"
sha256sum -c SHA256SUMS
cat CANDIDATE_COMMIT
./hysteria version
./faketcp-integration -h
```

哈希不一致、架构不符、缺少 `-local-addr`/`-udp-pps` 或旧提交时立即停止，不带病测试。私钥绝不随 bundle 传输。生成独立随机测试口令，双端一致，保存为权限 `0600` 的测试文件；不要使用生产口令或公网测试的默认固定口令。所有密钥、证书私钥、口令文件均不进入 Git。

## 5. 首次连接仅做只读预检

SSH 选项至少包含 `BatchMode=yes`、`IdentitiesOnly=yes`、`ForwardAgent=no`、`StrictHostKeyChecking=yes` 和 `-i "$SSH_KEY"`，端口 22。先从本机将预检脚本通过 stdin 送入远端 shell，结果保存到本机私有目录，尚不启动任何负载：

```sh
ssh -p 22 -i "$SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes \
    -o ForwardAgent=no -o StrictHostKeyChecking=yes "root@$GCP_HOST" \
    'sh -s' < scripts/faketcp/preflight.sh > "$LOCAL_RUN/gcp-preflight.txt" 2>&1

ssh -p 22 -i "$SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes \
    -o ForwardAgent=no -o StrictHostKeyChecking=yes "root@$ORACLE_HOST" \
    'sh -s' < scripts/faketcp/preflight.sh > "$LOCAL_RUN/oracle-preflight.txt" 2>&1
```

脚本只读取系统状态并尝试创建后立即关闭 Raw Socket，不发送测试包。连接失败、认证失败或 Raw Socket 拒绝都要保留原始错误，不以其他未经授权的接入方式绕过。

继续只读确认：

1. `ss` 中 TCP/UDP `6666–7777` 当前占用；已有 `20000–50000` 服务的 PID、监听地址和基本健康状态。仅记录必要元数据，不转储生产凭据或完整敏感命令行。
2. 每个方向的 `ip route get <对端可见IP>`、本地接口实际地址、MTU、现有 offload 状态。云公网 IP 常由外部 NAT 提供，不一定在本机接口上，不能直接当作 bind 地址。
3. systemd 是否作为系统管理器运行、`systemd-run`/`systemctl` 版本、cgroup v2 的 cpu/memory/pids controllers 是否可用。只读查看 `/sys/fs/cgroup`、当前 cgroup 和已有控制器状态，不重挂 cgroup 或迁移生产进程。
4. 对应防火墙后端及其当前状态；所需 veth、netem、conntrack、NAT、raw/filter、IPv6、BPF 等功能是否已经内建/加载。mimic 还有独立门槛，见后文。不要把可能触发自动模块加载的试运行当成只读检查。
5. 磁盘空间、时钟、进程/线程预算、CPU steal/iowait/softirq、内存余量。对实际块设备作只读映射，后续如设置 I/O 限额须用核实过的设备。

缺少用户态工具时，先在构建环境准备、校验并将兼容的独立工具或依赖解包到 `RUN_DIR/deps`，仅为本轮设置 PATH/库搜索路径。不能 `apt install`、`apt upgrade`、系统 `pip install` 或更换生产机的 libc、iptables 后端、Python、内核。不能安全携带的依赖列为阻塞项。

在传输工具后，用 [monitor.py](scripts/faketcp/monitor.py) 采集至少 60 秒无测试负载基线。GCP 起步可要求 CPU 持续低于 50%、`MemAvailable >= 512 MiB`；Oracle 起步要求 `MemAvailable >= 4096 MiB`，同时评估真实生产占用。条件不满足时不启动压力；降低后续预算不能替代当前生产健康检查。

```sh
python3 "$RUN_DIR/bundle/scripts/faketcp/monitor.py" baseline \
    --run-id "$RUN_ID-preflight" --duration 60 --max-host-cpu 50 \
    --min-mem-available-mib 512 > "$RUN_DIR/resource-baseline.jsonl"
```

Oracle 将内存参数调整为上述起步值。`baseline` 不发送信号，退出非零意味着不能按原预算推进。保存本轮前的生产监听、路由、物理接口和防火墙摘要，最终用于核对恢复；不要用全局 restore 覆盖测试期间其他管理员的合法变化。

## 6. 硬资源封套、监控和停止阈值

### 6.1 起始预算

下表为保护生产应用的保守起始上限，预检可将它们调低；调高必须先证明余量并记录理由。一个主机同时只运行一组测试，客户端、服务端、echo 辅助程序及 mimic 都计入该组总预算。

| 项目 | GCP 起始值 | Oracle 起始值 |
| --- | ---: | ---: |
| 测试组 CPU 硬配额 | `CPUQuota=20%` | `CPUQuota=50%` |
| 内存压力阈值 / 硬上限 | `MemoryHigh=160M` / `MemoryMax=192M` | `320M` / `384M` |
| 允许 swap | `MemorySwapMax=0` | `MemorySwapMax=0` |
| 线程/任务上限 | `TasksMax=128` | `TasksMax=128` |
| 每进程文件描述符上限 | `LimitNOFILE=512` | `LimitNOFILE=512` |
| 每文件输出硬限制 | `LimitFSIZE=64M` | `LimitFSIZE=64M` |
| Go 初始设置 | `GOMAXPROCS=1`，`GOMEMLIMIT=64MiB` | 同条件比较时相同 |
| 第一轮公网负载 | 1 client × 1 stream，125000 bytes/s/方向，50 UDP pps | 相同 |

systemd 的 `CPUQuota=20%` 表示 **0.2 个逻辑核**，不是“整台机器总 CPU 的 20%”。`MemoryHigh` 是压力控制，`MemoryMax` 才是硬上限；`CPUWeight`、`IOWeight`、`Nice` 都只是权重/优先级。见 [systemd.resource-control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html) 和 [内核 cgroup v2 文档](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)。

没有可用硬限额时，不在生产机启动高负载或长跑；标记阻塞并转移到隔离验收机。不要为了获得控制器修改宿主启动参数、全局 systemd 配置或现有服务 cgroup。

### 6.2 transient unit 模板

仅在确认对应 systemd/cgroup 功能存在后使用。先生成本轮 `RUN_DIR/case.sh` 和权限 `0600` 的 `RUN_DIR/test.env`，人工查看完整内容，再启动；不要把防火墙或宿主网络变更藏进这个启动脚本。`case.sh` 必须只启动本轮程序、等待并保存退出码，包含子进程时要有明确清理。

`test.env` 写入本轮随机认证、`HY2_VALIDATION_RUN_ID`、Go 设置和 `TMPDIR=RUN_DIR/tmp`，使用实际路径和值，不把口令作为命令行参数。创建 `RUN_DIR/tmp` 和日志目录。`UNIT` 是本轮唯一名字，例如 `hy2-ft-<RUN_ID>-netns.service`；先确认不存在同名 unit。

```sh
systemd-run --unit="$UNIT" --property=Type=exec \
    --property="WorkingDirectory=$RUN_DIR" \
    --property="EnvironmentFile=$RUN_DIR/test.env" \
    --property=CPUAccounting=yes --property=MemoryAccounting=yes \
    --property=CPUQuota=20% --property=MemoryHigh=160M --property=MemoryMax=192M \
    --property=MemorySwapMax=0 --property=TasksMax=128 --property=LimitNOFILE=512 \
    --property=LimitFSIZE=64M --property=LimitCORE=0 --property=Nice=19 \
    --property=IOSchedulingClass=idle --property=RuntimeMaxSec=12min \
    --property=TimeoutStopSec=5s --property=KillMode=control-group --property=SendSIGKILL=yes \
    --property="StandardOutput=append:$RUN_DIR/unit.stdout.log" \
    --property="StandardError=append:$RUN_DIR/unit.stderr.log" \
    /bin/bash "$RUN_DIR/case.sh"
```

Oracle 使用该轮核定预算。长跑时明确设置稍长于负载持续时间的 `RuntimeMaxSec`，不要设为无限。systemd transient unit 是短期控制对象，可能由管理器在 `/run/systemd` 保存运行元数据；所有测试输出仍指向用户目录。不要写持久 `.service` 文件，不 `enable`，不 `daemon-reload`，不修改生产 unit。[systemd-run 官方说明](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html) 说明了 transient unit 的启动、环境和生命周期。

**先验证封套，再放行负载。** 初次用同等属性运行仅等待的无负载自有 unit，读取下面信息，检查实际 `cpu.max` 不是 `max`、`memory.max` 不是 `max`、`memory.swap.max=0`、`pids.max` 与预算一致，再停止该测试 unit。后续 case 也保存同样证据：

```sh
systemctl show "$UNIT" -p MainPID -p ControlGroup -p CPUQuotaPerSecUSec \
    -p MemoryHigh -p MemoryMax -p MemorySwapMax -p TasksMax -p RuntimeMaxUSec
TEST_CGROUP=$(systemctl show "$UNIT" -p ControlGroup --value)
cat "/sys/fs/cgroup$TEST_CGROUP/cpu.max"
cat "/sys/fs/cgroup$TEST_CGROUP/memory.max"
cat "/sys/fs/cgroup$TEST_CGROUP/memory.swap.max"
cat "/sys/fs/cgroup$TEST_CGROUP/pids.max"
```

空的 `ControlGroup`、文件缺失或属性未生效都不能继续。读取前确认路径确实是本 unit 的 cgroup。需要真实 I/O 带宽上限且已核对设备、io controller 时，可在本轮 unit 使用 `IOReadBandwidthMax=<设备> <上限>`、`IOWriteBandwidthMax=...` 并检查 `io.max`；设备映射不明时不猜测，不开展高 I/O 测试。普通验证也限制抓包/日志数量与大小。

停止只针对本轮准确名称：

```sh
systemctl stop "$UNIT"
systemctl show "$UNIT" -p ActiveState -p SubState -p Result -p ExecMainStatus
```

保存结果后，如该 transient unit 因失败仍被管理器保留，仅对这个准确名称执行 `systemctl reset-failed "$UNIT"`。不要对匹配前缀的全部 unit 批量操作。

### 6.3 自动停止和采集

`monitor.py watch` 只监控显式登记的测试二进制 PID：其 executable 和 cwd 均须在 `/root/tmp/hy2`，且环境含正确 `HY2_VALIDATION_RUN_ID`。工具核对启动时间并用 pidfd 发送信号；不跟随子进程，不会监控或停止未登记的后继进程。`bash`、`unshare` 的 executable 在系统目录，不能把它们冒充为可登记的 Go 测试进程。

公网单个 harness unit 可在 READY 后登记实际 Go PID；短期窗口预留服务端就绪和客户端结束时间。netns 矩阵不断更换子进程，统一 CPU/内存约束依靠整组 cgroup；主机 `baseline` 监控若返回异常，调用方必须立即 `systemctl stop "$UNIT"`。监控进程本身应在负载组外低开销运行，避免配额耗尽后无法及时报警。测试驱动应将监控非零退出、日志写入失败、SSH 控制中断和测试超时都作为终止本轮的原因。

| 停止条件 | 起始阈值/处理 |
| --- | --- |
| 整机 CPU | 连续 3 个 1 秒样本超过 70% |
| GCP 注册测试进程 CPU/RSS | 合计超过单核 40% 连续 3 次，或 RSS 超过 160 MiB |
| Oracle 注册测试进程 CPU/RSS | 合计超过单核 80% 连续 3 次，或 RSS 超过 320 MiB |
| 整机可用内存 | GCP 低于 256 MiB；Oracle 低于 2048 MiB，立即停 |
| 单测试进程 fd/线程 | 超过 256 fd 或 32 线程，先停并调查 |
| cgroup | `memory.events` 的 oom/oom_kill、意外到达 pids 上限，立即停 |
| 生产健康 | 已有健康检查恶化、已有服务重启、SSH 明显失去响应、系统出现 OOM，立即停 |
| 日志和时限 | 日志丢失、磁盘余量不足、到达本轮 RuntimeMaxSec，判本轮失败或资源阻塞 |

参数示例见 [监控说明](scripts/faketcp/README.md)。监控阈值是保护动作，不能算作性能结论；`--observe-only` 不能承担主动保护。内核 softirq 等开销不能完全归到用户进程 CPU 配额，须同时观察整机读数。测试组被明显 throttling 时可以继续判定低负载功能，但不能把结果报告成实现的峰值吞吐。

## 7. 单机真实内核隔离矩阵

在两台机器分别运行，先短矩阵，再决定是否延长。将以下内容作为审阅后的 `case.sh` 的主体，并通过上节硬限额启动；脚本、bundle 和结果路径都应使用实际值：

```sh
export FAKETCP_INTEGRATION_BIN="$RUN_DIR/bundle/faketcp-integration"
export FAKETCP_RESULTS_DIR="$RUN_DIR/netns-low"
export FAKETCP_PORT=6666 FAKETCP_CLIENTS=1 FAKETCP_PARALLEL=1
export FAKETCP_BANDWIDTH=500000 FAKETCP_UDP_PPS=100
export FAKETCP_CASE_SECONDS=15 FAKETCP_SOAK_SECONDS=0
exec bash "$RUN_DIR/bundle/scripts/test-faketcp-netns.sh"
```

`RUN_DIR` 必须在 unit 环境或脚本内定义。随机 `FAKETCP_TEST_AUTH` 从本轮环境文件继承。不要直接使用工具默认的多个客户端、100 Mbit/s 级目标和 8000 UDP pps 在 GCP 上开跑。

脚本自行创建外层 private mount/network/PID namespaces，并把私有 `/run`、`/tmp`、`/var/tmp` 绑定到本轮结果目录。它不需要宿主网卡、默认路由或宿主 SNAT；临时 client/SNAT 端口也限制在 `6666–7777`。只在私有网络里切换 GRO、设置 netem 和路由器转发 sysctl。不要把内部命令逐条搬到宿主运行。

严格检查以下矩阵及原始输出：

- UDP / native FakeTCP 同条件基线；IPv4、IPv6，MTU 1500 和 1280。
- GRO on/off 实际 feature 值，TCP stream、QUIC DATAGRAM、Host 前导、反复重连。
- 多客户端先 1，再在预算内升到 2；资源足够才更高。不能将“单客户端通过”冒充多客户端验收。
- 延迟、1% 丢包、乱序、重复；可靠 TCP 内容全部正确，UDP 内容正确并记录实际接收、重复、重试和丢失口径。
- SNAT 真实地址/端口翻译。在已收到应用数据且连接仍活动时，conntrack 必须为 `ESTABLISHED`，不能只用吞吐证明 NAT 正常。
- 双路由器的远端 MTU 1280 瓶颈：本地 MTU 1500、IPv4 fragmentation-needed / IPv6 PTB 被私有路由器丢弃时，仍能完成握手和传输。
- 超时或退出后，只有本轮进程/namespace 被清理；宿主接口、路由、生产监听和防火墙基线没有被本轮更改。

脚本日志、客户端 JSON、conntrack 原文、链路/qdisc 统计、`environment.txt` 和 `results.json` 全部保存。任何子用例失败都中止该矩阵并保留现场证据。脚本不能替代下节的公网链路，也不能证明物理网卡 GRO 或驱动表现。

## 8. 双向公网：先确定地址、端口和精确 RST 规则

每次只做一个方向：先 GCP client → Oracle server，完成清理后再 Oracle client → GCP server。客户端源端口固定 `7001`，服务端口固定 `6666`，低负载起步。不要同时运行多个占用相同元组的进程。

为每个方向填写下面的**私有**记录：

| 变量 | 含义 |
| --- | --- |
| `CLIENT_LOCAL` | client 所在系统实际拥有、到对端路由选中的本地 IP |
| `SERVER_LOCAL` | server 所在系统实际拥有的监听 IP |
| `SERVER_VISIBLE` | client 连接时使用的 server 可见 IP，可能是云公网映射地址 |
| `CLIENT_VISIBLE` | server 实际看到的 client 源 IP，可能由云 NAT 改写 |
| `CLIENT_SEEN_PORT` | server 实际看到的 client 源端口，未必仍是 7001 |
| `IFACE` | 对应端用于只读抓包的实际接口 |

本机 `ip addr` 和 `ip route get` 证明 local bind 地址；对端短时、限定 IP/测试端口的抓包或现有流记录证明 visible 地址/端口。**不要把不属于本机的公网 IP 填进 `-local-addr` 或 `listen`。** 不要假定 UDP 的 NAT 映射与 TCP 相同。

如果必须先观察 TCP NAT 源端口，可以在已核准资源封套下做一次有界握手探测并抓取测试 SYN；那次握手允许失败，只用于确认元组，不算连通性通过。抓包只匹配这两机和本轮端口，限制时长、包数和文件大小。NAT 若映射到授权范围外、无法确认精确元组或地址不断变化，停止该公网阶段，记录网络约束；不扩展为全端口 RST DROP。

### 8.1 优先：已有 nftables 上的本轮独立表

在确认 nft 和所需内核功能已存在后，选择本轮唯一表名 `hy2ft_<RUN_ID简写>_<方向>`，先只读确认不存在。把即将安装的完整规则存到 `RUN_DIR/install-rst.nft`，核对其中的实际 IP/端口，再执行。以下为 IPv4 **client 端**模板：

```nft
create table inet OWN_TABLE
add chain inet OWN_TABLE output { type filter hook output priority -300; policy accept; }
add rule inet OWN_TABLE output ip saddr CLIENT_LOCAL ip daddr SERVER_VISIBLE tcp sport 7001 tcp dport 6666 tcp flags & rst == rst counter drop comment "HY2_FAKETCP:RUN_ID:client"
```

**server 端**相应规则，注意客户端在服务端可见的源端口：

```nft
create table inet OWN_TABLE
add chain inet OWN_TABLE output { type filter hook output priority -300; policy accept; }
add rule inet OWN_TABLE output ip saddr SERVER_LOCAL ip daddr CLIENT_VISIBLE tcp sport 6666 tcp dport CLIENT_SEEN_PORT tcp flags & rst == rst counter drop comment "HY2_FAKETCP:RUN_ID:server"
```

替换全部占位符。IPv6 使用实际 IPv6 地址与 `ip6 saddr` / `ip6 daddr`，不能把 IPv4 规则当作双栈规则。选择 `priority -300` 是为了在 conntrack 前丢弃本机 RST；普通 filter OUTPUT DROP 太晚。规则的 `accept` policy 只属于本轮新链，不改变现有链策略。不要添加 NOTRACK 或 INPUT DROP。

执行与清理是分开的明确步骤：

```sh
nft -f "$RUN_DIR/install-rst.nft"
nft -a list table inet "$OWN_TABLE" > "$RUN_DIR/rst-installed.txt"
# 测试期间记录该表 counter。停止本轮两端负载、保存证据后：
nft delete table inet "$OWN_TABLE"
```

只删除已经确认由本轮创建、且内容/标识仍匹配的独立表。创建失败时不能执行删除一个原已存在的同名表。nft 使用 netlink，不需要额外 xtables 锁文件。[nftables 官方手册](https://netfilter.org/projects/nftables/manpage.html) 提供链、优先级和事务语义。

### 8.2 现有 iptables 后端的回退

不更换后端。保留系统标准 xtables 锁，使用 `iptables -w`；**不要设置独立 `XTABLES_LOCKFILE`，也不要在宿主网络仍共享时通过私有 `/run` 绕开生产锁**。标准工具的短期运行锁与本轮测试产物不同。前述 netns 矩阵同时隔离网络和挂载，才适合使用自己的 `/run`。

client 端规则数组示例：

```sh
RST_RULE=(-s "$CLIENT_LOCAL" -d "$SERVER_VISIBLE" -p tcp \
    --sport 7001 --dport 6666 --tcp-flags RST RST \
    -m comment --comment "HY2_FAKETCP:$RUN_ID:client" -j DROP)
iptables -w 5 -t raw -I OUTPUT 1 "${RST_RULE[@]}"
# 退出前，按同一组实际参数原样删除：
iptables -w 5 -t raw -D OUTPUT "${RST_RULE[@]}"
```

server 使用 `-s "$SERVER_LOCAL" -d "$CLIENT_VISIBLE" --sport 6666 --dport "$CLIENT_SEEN_PORT"` 和不同的本轮 comment。IPv6 使用 `ip6tables`。安装前确认本轮同一规则尚未存在，避免重复；将安装/删除命令以正确 shell quoting 存到本轮目录，不能只记住“第几条规则”。不使用 `-F`，不删除其他规则。

### 8.3 连接跟踪与清理

在有实际流量后只查询本轮家族、协议、原始源/目的 IP 和源/目的端口，记录原始/回复元组、状态、NAT 改写、zone（如有）。不要假设云外部 NAT 的地址与宿主 conntrack 记录相同。持续传输时应核对 FakeTCP TCP 状态，不能长期为 `CLOSE` 却据吞吐判定成功。

Raw Socket close 不提供普通 TCP 的 FIN/RST 关闭序列；测试完成后系统可能保留条目直到现有超时。不要降低宿主 conntrack 超时。先停止两端测试 unit，再保存残留条目；若要主动清除，只对本轮已观察到的精确原始元组执行 `conntrack -D`，包含家族、TCP/UDP、地址、源/目的端口及适用的 zone。示意：

```sh
conntrack -D -f ipv4 -p tcp --orig-src "$OBSERVED_ORIG_SRC" \
    --orig-dst "$OBSERVED_ORIG_DST" --sport "$OBSERVED_ORIG_SPORT" \
    --dport "$OBSERVED_ORIG_DPORT"
```

这些值必须来自本轮保存的条目，且服务端口为本轮 6666，不能套用未经核对的公网地址。非默认 zone 先查清工具的精确匹配方式，不能扩大范围删除。私有 netns 的连接跟踪随其删除回收，不需要宿主清表。

## 9. 双向公网低负载用例

随机测试口令由本轮环境文件提供，双方一致。harness 是固定 echo outbound，不会代理到任意生产目的地；但它使用自签测试证书且跳过证书验证，**不能用这个阶段证明 app 的 CA/SNI 验证正确**。严格 TLS 验证在下一节单独完成。

在 server 的受限 unit 中执行：

```sh
exec "$RUN_DIR/bundle/faketcp-integration" \
    -role server -transport faketcp -address "$SERVER_LOCAL:6666" \
    -mtu 1500 -bandwidth 125000
```

有界等待该 unit 存活且日志出现 `READY`，然后在 client 的受限 unit 中执行：

```sh
exec "$RUN_DIR/bundle/faketcp-integration" \
    -role client -transport faketcp -address "$SERVER_VISIBLE:6666" \
    -local-addr "$CLIENT_LOCAL:7001" -mtu 1500 -bandwidth 125000 \
    -parallel 1 -size 65536 -traffic tcp -duration 15s
```

命令在 IPv6 下使用 `"[$SERVER_LOCAL]:6666"`、`"[$SERVER_VISIBLE]:6666"`、`"[$CLIENT_LOCAL]:7001"`。每轮保存单独 stdout JSON 和 stderr 日志。监听就绪超时、失败退出或监控触发时停止本轮，不无限自动重试。

按以下矩阵逐项执行并反向重做；每行都需明确参数和结果：

| 用例 | 变化 | 必查结果 |
| --- | --- | --- |
| UDP 对照 | 双端 `-transport udp`，其他公共 QUIC/Brutal 参数相同 | 同路径可用性、内容及有效载荷；不需 FakeTCP RST 规则 |
| Native 基本 | 上述命令 | 双端 raw 实际收发、Brutal 已协商、TCP 内容无损坏 |
| Host | client 加 `-host www.example.org` | 外层前导 Host 正确，实际目标仍为 server；连接及内容正确 |
| UDP 应用数据 | client `-traffic udp -udp-pps 50` | 每个返回的数据报内容正确，保存 sent/verified 计数和真实发送率 |
| MTU 1280 | 双端 `-mtu 1280` | 初始握手和稳定传输；不改宿主网卡 MTU |
| 重连 | client `-reconnect 2`，视耗时延长到 30s | `connections >= 2`，同源端口可反复建立，不出现停滞 |
| 较长低负载 | 延长到 5–10 分钟 | conntrack 状态、RSS/fd/线程/资源、checkpoint 持续推进 |

在公网物理接口上只读记录 GRO/GSO/TSO/checksum 状态，不为了这个测试开关它们。真实 GRO 切换与损坏/乱序注入在私有 netns 完成。公网外层 `mtu=1280` 成功，不等于已经制造并覆盖远端 PMTU 黑洞；远端瓶颈由单机双路由器矩阵验证，两个结论分开报告。

`verified_payload_mbps` 是校验通过的回显业务量除以完整耗时，包含握手和结束等待；一次业务回显经过上下两个方向，不能乘二当作独立全双工极限。harness 的 UDP verified 计数没有去重，因此不能直接用 `1-verified/sent` 得出精确丢包率；要求准确丢包/重复率时使用带序号、去重计数的相同探针，或扩展测试工具后另建候选提交。所有内容错误都是严格失败；UDP 的天然丢失不能被错误表述为 TCP 类可靠性保证。

## 10. 完整 app YAML、严格 TLS 和 TCP/UDP 转发

此阶段在**私有 netns** 执行，使用实际 `hysteria` app，而不是 core harness。原因是 app server 连接 echo 目标时，系统会分配普通 TCP/UDP 临时源端口；在私有 netns 中可局部限制端口，不需要修改宿主 `ip_local_port_range`。公网阶段和此阶段的覆盖范围必须分别报告。

### 10.1 准备独立应用用例

本地 Codex 为本轮生成、审阅一个 `RUN_DIR/app-case.sh`，沿用已审阅网络矩阵的外层 private mount/network/PID、私有 `/run`、创建登记和 EXIT 清理结构，**不要 source 整个矩阵脚本或在它运行时接管其 namespace**。该脚本运行在同一硬资源封套内。没有提供网络隔离的 app 用例不得退回宿主执行。

内部拓扑使用 `S_NS` 的 `10.203.0.1/24` 与 `C_NS` 的 `10.203.0.2/24`，只有一对新建 veth，无宿主路由或出口；两边 loopback 启用。每个 namespace 内将 `net.ipv4.ip_local_port_range` 设为 `7002 7399`，只在私有 namespace 调整。FakeTCP client 显式使用源端口 `7001`。对这两个私有地址、6666/7001 和 RST 安装精确 raw/OUTPUT 规则。以下所有 `ip netns exec` 的 namespace 都必须是本轮已成功创建并记录的对象。

在本机构建环境生成独立测试证书（例如 DNS SAN 为 `faketcp.test`、短有效期），将证书及测试私钥安全传至本轮目录；不用生产证书，不申请真实域名证书。server 使用此证书，client 的 `tls.ca` 只信任该测试证书/CA，`tls.sni` 为 `faketcp.test`，不要设置 `insecure: true`。

server YAML 模板，路径和值由执行者明确替换：

```yaml
listen: 10.203.0.1:6666
transport:
  type: faketcp
  faketcp:
    mtu: 1280
    idleTimeout: 2m
tls:
  cert: /root/tmp/hy2/RUN_ID/tls/server.crt
  key: /root/tmp/hy2/RUN_ID/tls/server.key
auth:
  type: password
  password: REPLACE_WITH_PRIVATE_TEST_AUTH
bandwidth:
  up: 4mbps
  down: 4mbps
```

client YAML 模板：

```yaml
server: 10.203.0.1:6666
auth: REPLACE_WITH_PRIVATE_TEST_AUTH
transport:
  type: faketcp
  faketcp:
    localAddr: 10.203.0.2:7001
    mtu: 1280
    handshakeTimeout: 10s
    host: www.example.org
tls:
  sni: faketcp.test
  ca: /root/tmp/hy2/RUN_ID/tls/server.crt
bandwidth:
  up: 4mbps
  down: 4mbps
tcpForwarding:
  - listen: 127.0.0.1:6667
    remote: 127.0.0.1:6669
udpForwarding:
  - listen: 127.0.0.1:6668
    remote: 127.0.0.1:6670
    timeout: 30s
```

这是配置模板，不是支持这些大写占位符自动展开的语法。实际 YAML 权限设为 `0600`，实际口令不打印到日志。测试 echo 服务只监听 `S_NS` 内的 `127.0.0.1:6669/TCP` 和 `127.0.0.1:6670/UDP`，不开放任意目的转发，也不访问生产应用。

### 10.2 逐字节校验与去重计数

可将下面标准库工具保存为本轮 `echo-check.py`，一端 `serve`、另一端 `check`；它只测试上述私有 namespace 的 loopback 转发端口。它需要被同一资源封套、统一超时和清理管理。进程自身不是完整 supervisor。

```python
import hashlib
import json
import secrets
import socket
import struct
import sys
import threading
import time


def receive_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("TCP closed before the complete echo")
        chunks.extend(chunk)
    return bytes(chunks)


def tcp_server(listener):
    with listener:
        while True:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(30)
                try:
                    while chunk := conn.recv(65536):
                        conn.sendall(chunk)
                except (ConnectionError, socket.timeout):
                    pass


def serve():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 6669))
    listener.listen(2)
    threading.Thread(target=tcp_server, args=(listener,), daemon=True).start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 6670))
        print("ECHO_READY", flush=True)
        while True:
            payload, peer = sock.recvfrom(65535)
            sock.sendto(payload, peer)


def check(tcp_source, udp_source):
    if not (7002 <= tcp_source <= 7399 and 7002 <= udp_source <= 7399 and tcp_source != udp_source):
        raise ValueError("Choose two distinct test source ports in 7002..7399")
    verified_tcp = 0
    digest = hashlib.sha256()
    with socket.socket() as sock:
        sock.settimeout(30)
        sock.bind(("127.0.0.1", tcp_source))
        sock.connect(("127.0.0.1", 6667))
        for i in range(16):
            payload = secrets.token_bytes(65536)
            sock.sendall(payload)
            echoed = receive_exact(sock, len(payload))
            if echoed != payload:
                raise RuntimeError("TCP payload corruption")
            verified_tcp += len(payload)
            digest.update(echoed)
            if i == 7:
                time.sleep(15)  # 同一连接应用空闲后恢复；不等于线上的 QUIC 完全静默。
    payloads = {seq: struct.pack("!Q", seq) + secrets.token_bytes(1392) for seq in range(64)}
    seen = set()
    sent = duplicates = first_attempt = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", udp_source))
        sock.settimeout(0.5)
        for seq, payload in payloads.items():
            for attempt in range(3):
                sock.sendto(payload, ("127.0.0.1", 6668))
                sent += 1
                deadline = time.monotonic() + 0.5
                while time.monotonic() < deadline:
                    sock.settimeout(max(0.001, deadline - time.monotonic()))
                    try:
                        echoed, peer = sock.recvfrom(65535)
                    except socket.timeout:
                        break
                    if peer != ("127.0.0.1", 6668) or len(echoed) != 1400:
                        raise RuntimeError("Unexpected UDP peer or length")
                    echoed_seq = struct.unpack("!Q", echoed[:8])[0]
                    if payloads.get(echoed_seq) != echoed:
                        raise RuntimeError("UDP payload corruption or unknown sequence")
                    if echoed_seq in seen:
                        duplicates += 1
                    seen.add(echoed_seq)
                    if echoed_seq == seq:
                        first_attempt += int(attempt == 0)
                        break
                if seq in seen:
                    break
            if seq not in seen:
                raise RuntimeError(f"UDP sequence {seq} missing after three attempts")
    print(json.dumps({"verified_tcp_bytes": verified_tcp, "tcp_sha256": digest.hexdigest(),
                      "udp_unique": len(seen), "udp_sent": sent,
                      "udp_first_attempt": first_attempt, "udp_duplicates": duplicates}))


if sys.argv[1:] == ["serve"]:
    serve()
elif len(sys.argv) == 4 and sys.argv[1] == "check":
    check(int(sys.argv[2]), int(sys.argv[3]))
else:
    raise SystemExit("usage: echo-check.py serve | check TCP_SOURCE_PORT UDP_SOURCE_PORT")
```

内层 driver 的启动顺序为：echo → app server → app client → checker。每一步有界确认存活和就绪，记录实际 PID 和退出码；`ECHO_READY` 表示 TCP/UDP 已绑定，checker 的 TCP 校验仍是必须的。执行形态如下，清理与就绪逻辑应在已审阅 driver 中显式实现：

```sh
ip netns exec "$S_NS" python3 "$RUN_DIR/echo-check.py" serve
ip netns exec "$S_NS" "$RUN_DIR/bundle/hysteria" server -c "$RUN_DIR/server.yaml"
ip netns exec "$C_NS" "$RUN_DIR/bundle/hysteria" client -c "$RUN_DIR/client.yaml"
ip netns exec "$C_NS" timeout --signal=TERM --kill-after=5s 90s \
    python3 "$RUN_DIR/echo-check.py" check 7002 7003
```

前三项是需要由 driver 分别管理的长运行子进程，不能按上面四行串行等待。在同一个 `C_NS` 再次执行 checker 时，换用未使用的源端口对（例如 `7004 7005`），或重建整套私有 namespace；固定源端口重复连接可能遇到 TCP TIME_WAIT，UDP 也可能收到上一轮延迟回显。源端口始终限于 `7002–7399`，不要修改宿主 `tcp_tw_reuse` 等 sysctl 解决它。不要把 `timeout` 退出码 124/137 记成成功。checker 必须成功退出、TCP 字节数匹配、UDP 64 个唯一序号全部校验；它的 UDP 重试必须计入报告，不能宣称首次发送无丢包。

### 10.3 app 严格验收项

1. 上述 YAML 在真实 app 上工作，Host 开/关均能通过 TCP 和 UDP 校验，应用空闲 15 秒后同一 TCP 连接仍可传输。
2. 改错 SNI 或移除测试 CA 时，应明确出现证书校验失败；恢复正确 CA/SNI 后成功。故意错误认证应失败。不能用网络超时冒充证书/认证拒绝。
3. 在私有 veth 上抓取有界握手证据，确认 Host 前导使用配置值，不改变目标地址；不要要求它表现为真实 HTTP/WebSocket/TLS camouflage。
4. 分别用 MTU 1280/1500，GRO on/off，重复重启本轮 client 和 server，多轮连接后仍无资源泄漏。复测同四元组与新四元组重连。
5. 原始 UDP app 路径另做回归；不要把它默认的 ChromeParrot/GSO/InitialPacketSize 与已对齐参数的 harness 性能结果混为一组。
6. 配置冲突（mimic、realm、端口跳跃、非 plain obfs、不支持的 UDP sockopts）应按当前设计明确拒绝；既有生产配置不作改动。

这个局部 app 用例证明配置接入与 TLS/转发行为；公网 harness 证明两机真实 raw 链路。没有在宿主上运行完整 app outbound 的记录时，不能写成“完整 app 公网全流程已测试”。

## 11. 小时级稳定性与负载递增

所有短用例、数据正确性及生产保护检查通过后才延长。先 5–10 分钟，再至少 1 小时；UTC 起止时间、有效运行时间和终止原因必须可核对。netns 脚本 `FAKETCP_SOAK_SECONDS=3600` 对 UDP 和 FakeTCP **分别**运行一小时，连同常规矩阵总计超过两小时，unit 时限要覆盖整个计划并留有限完成余量。

公网先每方向 1 Mbit/s，再在两机均有余量时升至 4 Mbit/s；更高档位只在既定资源预算内执行，所有组使用相同目标速率和并发。GCP 1 核生产机不是无条件打满硬件的压测机。达到资源限额时停止加压，记录“预算内最大已验证负载”；不能移除硬配额、关闭监控、停止生产服务来补齐高性能结论。

至少分别记录：

- 单连接长时间连续 TCP、UDP 应用数据，以及反复重连；双向角色互换。Host 开启的长连接和重复握手分别覆盖。
- 每 30 秒 harness checkpoint 的已验证字节、heap/goroutine；每秒进程 RSS/CPU/fd/线程，以及整机 CPU、softirq、steal、可用内存。
- cgroup `cpu.stat` 的 throttling、`memory.current`/`memory.events`/峰值、`pids.current`；队列、socket 丢包、链路和 conntrack 状态。
- 错误、断连、恢复、吞吐停滞、MTU 探测异常及日志丢失。出现错误时保留首发证据，不只保留最后一次重试成功。
- 测试前后生产服务的原有健康指标、监听、资源占用与本轮对象清理结果。

**严格失败**包括内容损坏、panic/race、永久停滞、不可恢复重连、错误 peer 回退、cgroup OOM、持续资源泄漏或对生产服务造成影响。可靠 TCP 不能以自动重试掩盖错误。UDP 内容损坏同样失败；数据报丢失/重复单独量化。

资源趋势必须区分 Go GC、RSS 高水位和泄漏。建议预热 10 分钟后比较连续三个 10 分钟窗口；RSS 中位数持续增加超过 `max(16 MiB, 25%)`、fd/goroutine 不随会话回收等作为**调查阈值**，结合堆/对象/连接计数定位，不能仅凭一个最终 RSS 值宣称无泄漏。确认无界增长后属于严格失败。生产机资源不足以完成所需负载时，该稳定性档位为 `BLOCKED`，不是通过。

应用空闲不等于线路静默，QUIC keepalive 可能持续刷新 NAT。报告涉及 idle/NAT 时应同时记录实际控制包，不能把仍有 keepalive 的 15 秒空闲表述为“纯静默 NAT 超时恢复”。

## 12. mimic 公平对照与不可测范围

以 [MIMIC-PLAN.txt](scripts/faketcp/MIMIC-PLAN.txt) 为具体操作方案，执行前对固定 mimic commit 的源码和官方构建文档再核对。不得调用生产 app 的自动 mimic 集成去修改共享物理接口；本轮直接管理第三方 CLI，仅挂在自己新建的私有 veth 上。`mimic run --check` 也可能先 attach XDP/TC，不是可在生产物理接口运行的只读预检。

只在依赖、已内建/加载内核能力和版本满足条件时开始。默认 kfunc 路径依赖 mimic 模块的版本，不在生产机为它安装 DKMS 或加载模块。如果固定版本允许 `CHECKSUM_HACK=kprobe`、用户态 UDP、私有 veth 软件 TX checksum 的无新增模块路径，可单列测试这个组合；不能把结果冒充默认 kfunc + 物理 NIC offload 组合。已有模块若实际参与，也要记录。mimic 构建和版本依据见 [上游仓库及其文档](https://github.com/hack3ric/mimic)。

同一台机器、同一组私有 namespace/veth 上比较三组：

| 组 | 数据路径 |
| --- | --- |
| UDP | 同一 integration binary，`-transport udp`，无 mimic |
| Native | 同一 integration binary，`-transport faketcp`，仅本轮私有 RST 规则 |
| mimic | 同一 integration binary，`-transport udp`，两端私有 veth 上已确认 attach 的 mimic CLI |

共同条件必须相同：source SHA、Go/构建 flags、二进制 hash、TLS/认证策略、Brutal 目标、InitialPacketSize 1200、ChromeParrot/GSO 设置、PMTUD、业务类型和大小、并发、持续时间、外层 IP MTU、offload 实际状态、CPU/内存预算、日志等级。Host 先关闭；Host 开启的握手开销另列。mimic 增加的头部和 native 的帧头开销各自如实保留，不通过不同物理 MTU 隐藏差异。

只确认 mimic CLI 启动还不够：核对私有 veth 的 XDP/TC attach、实例锁/状态及线上 TCP 格式，防止失败后悄悄跑成 UDP 基线。native XDP 不支持而改为 skb 模式时必须另开 case、清晰标注，不能混合。

推荐至少 3 轮交错顺序 `UDP → native → mimic → mimic → native → UDP`，每次单独预热后做至少 60 秒正式测量，保留每轮值、中位数和范围。比较应包括：校验有效载荷 goodput、整机与进程 CPU、softirq、每 GiB 已校验业务量的 CPU 时间、RSS/峰值、实际 wire bytes、包数、应用延迟、丢失/重复以及 cgroup throttling。harness 未提供的 p95/p99 延迟不能凭平均吞吐推算；需要同一套带时间戳的探针。

下列为**建议性能目标，不是协议正确性的硬 gate**，最终报告按实际环境解释：

- 在未被 CPU/带宽硬限额封顶、同条件的测试点，native goodput 至少达到 mimic 的 90%。
- 单位有效载荷的 CPU 时间不高于 mimic 的 120%，p95 延迟增幅不高于 20%。
- 超出上述目标时先检查测量口径、拥塞/资源限额和 hot path；达标也只能说明这些测点接近，不能证明所有环境性能相同。

若双方都达到同一个较低目标速率，只能说“都能承载该负载”，不能比较最大能力。不能拿 Oracle 的 native 与 GCP 的 mimic 横比，也不能用 codec 的零分配微基准代替真实网络对照。生产机上无法安全达到非配额受限负载时，如实报告性能结论受限，另选获准独占验收机。

没有独立接口/隔离公网路径时，不把 mimic attach 到承载 SSH 或生产 Hysteria 的网卡。此时可以完成私有 veth 对照，但公网 mimic/硬件 offload 对照仍为 `BLOCKED`；mimic 本身无法加载不是 native 更快的证据。

## 13. WSL2 与 Android 单独验收

两台 Linux 云服务器不能替代以下平台：

| 平台 | 需要额外确认和执行 |
| --- | --- |
| WSL2 | 实际 WSL/kernel 版本、Linux 架构、CAP_NET_RAW、标准 raw/conntrack 功能、WSL NAT/镜像网络模式、Windows 防火墙、接口地址变化、宿主休眠/恢复、网络切换、至少小时级运行 |
| Root Android | 真实 Android/API/厂商内核、ABI、SELinux 域、Raw Socket 能力、标准防火墙后端、可执行目录、Wi‑Fi/蜂窝切换、后台/休眠、电源策略、长时间 CPU/内存与温度 |

WSL2 使用相应 Linux 架构构建。Android 按 [构建说明](FAKETCP.md#构建) 使用 NDK 生成目标产物，并核对 loader、API level 和 SHA256；目前构建路径面向 API 29，ARMv7 还要求设备支持 32 位用户空间。先取得这类设备的明确访问和测试授权，在其获准私有测试目录中操作，不修改两台云服务器的边界来模拟平台支持。

每个平台重复功能、Host、MTU 1280、TCP/UDP 内容、同四元组重连、NAT、空闲/恢复、资源和长跑用例；按平台实际可用能力记录 IPv6/offload。不能仅凭 root UID、成功交叉编译或能运行 `version` 就标记支持已验收。没有目标设备时对应结果为 `NOT_RUN`，最终版本说明保留这一限制。

## 14. 严格 gate 与允许保留的限制

| Gate | 放行条件 | 不满足时 |
| --- | --- | --- |
| G0 可追溯与保护 | 固定提交/哈希、预检、权限、依赖、有效硬配额、生产余量、所有权及删除计划 | 不启动负载 |
| G1 本地回归 | 所有新增/受影响测试通过；既有失败按同环境基线逐项解释；race/fuzz/重放回归有实证 | 修复或记录环境阻塞，不宣称全量 PASS |
| G2 真实内核矩阵 | 两架构的必测 namespace 用例全部正确，NAT/MTU/GRO/重连及清理证据完整 | 当前平台功能验收失败/阻塞 |
| G3 公网与 app | 两方向受限源端口公网内容验证；私有完整 app 配置/严格 TLS/转发通过 | 不把部分路径结果扩大为全流程支持 |
| G4 持续稳定性 | 已约定档位达到小时级有效时长，无数据错误、死锁、泄漏或生产影响 | 停止，诊断并重测相应档位 |
| G5 性能证据 | 有同条件可复现对照，或明确说明 mimic/峰值/硬件环境不可测 | 禁止“达到/超越 mimic”结论 |
| G6 平台/发布 | 各宣称支持的平台有对应证据；未测平台显著标注；最终构建来自最终提交 | 保持实验性候选标签 |

性能建议阈值可用于优化优先级，不能把低于阈值的正确程序说成协议失败；也不能因为性能达标就忽略错误。保护阈值触发属于必须终止的测试事件，不是可选的性能建议。

## 15. 失败处理、修复和最小必要回归

出现失败时，先停止本轮 unit，保存错误首发时间、日志、参数、source SHA、二进制 hash、conntrack/包头/cgroup 快照，确认生产服务恢复基线。不要无限重试、无界增加带宽/超时、关闭 PMTUD/GRO 来把问题隐藏为通过。

在本地修复和加有针对性的回归，不直接修改服务器生产安装：

1. 最小复现到 codec、状态机、QUIC 模拟链路或真实内核阶段；区分网络本身不支持、环境依赖缺失与实现错误。
2. 为错误代 hello/ACK 回退、cookie 刷新和 welcome 重试等状态问题先证明修复前失败、修复后通过，再补真实 QUIC 和内核必要回归。
3. 检查热路径成本、锁/缓冲区生命周期、MTU、checksum、并发和关闭行为；避免为单个环境加入广泛防御性分支或关闭核心功能。
4. 代码、测试与文档一起审查，生成新提交。重新构建两架构并复验 hash，旧二进制和旧报告保留在旧轮目录。
5. 重跑新失败相关的最小回归及必要完整 gate；最终用于发布的那一提交必须有最终测试记录。实质影响状态机/收发路径的修复后，旧的小时级结果不能直接迁移为新提交通过。

测试环境问题也如实记录。任何只读诊断不能因方便而扩展为安装模块、改宿主 sysctl/物理 NIC 或调整生产服务。需要额外资源或设备的阶段记为阻塞，交给用户选择获准验收环境。

## 16. 本轮结束、公开报告与最终发布清单

结束顺序：停止本轮 clients → servers/echo/mimic → 监控与抓包；保存退出码和指标；删除本轮精确防火墙规则/独立表，按需精确删除本轮观察到的 conntrack 元组；确认自建 namespace/veth/XDP/TC 和 transient unit 已回收。保留本轮用户目录中的报告和原始证据，除非用户要求删除。核对生产监听、服务状态、物理接口、路由、防火墙和资源基线；其他管理员的变化不能用旧快照覆盖。

公开仓库只保留代码、测试、可复现步骤及脱敏摘要：

- 原始服务器预检日志、pcap、真实 IP/主机名、SSH 密钥/路径、测试认证、证书私钥不进 Git。原始证据保存在服务器 `/root/tmp/hy2` 和本机受控目录。
- 公开报告使用 `GCP` / `Oracle` 角色名；保留 source SHA、内核/架构、构建和测试条件、资源配额、实际结果与未测范围，不能为了脱敏删除可复现所需的非秘密参数。
- 提交前逐个列出要加入的源文件；使用精确路径 `git add <file1> <file2> ...`，禁止盲目 `git add -A` 把 logs/keys/captures 带入。
- 推送候选实现已经获得授权；创建正式稳定 release、扩大平台宣称和部署替换生产服务是不同动作，不能由一次候选分支推送自动推导。

最终报告至少包含以下表格，而不是只写“测试通过”：

| 信息 | 内容 |
| --- | --- |
| 精确版本 | 40 位 commit、tree/dirty 状态、源码/二进制 SHA256、构建工具与命令 |
| 环境 | GCP/Oracle 角色、架构、系统/内核、能力、防火墙后端、实际 offload/MTU |
| 测试 | 每个 case 的参数、有效时长、退出码、PASS/FAIL/BLOCKED/NOT_RUN、原始证据私有位置 |
| 正确性 | TCP 校验字节、UDP 唯一/重复/发送/重试计数、重连数、状态机回归、MTU/NAT/GRO 结果 |
| 资源 | CPU/softirq/RSS/heap/fd/线程/goroutine、cgroup 配额和 throttling/OOM、生产前后状态 |
| 性能 | 测量口径、每轮值及分布、与 UDP/mimic 相同条件的比值、限额/硬件局限 |
| 兼容性 | Linux 两架构、WSL2、Android 分开；缺失平台与路径显著列明 |
| 清理 | 本轮控制对象、规则、conntrack 处理、生产保护核对结果 |

最终发布前逐项确认：

- 所有计划宣称已通过的严格 gate 有对应最终提交证据，没有把环境阻塞或被保护阈值终止的 run 算作通过。
- 最终构建来自最终 commit，目标架构、loader、版本标识、SHA256 清单及下载文件互相对应；测试修复之后重新构建，而非继续分发修复前程序。
- 准确区分“预算内低负载稳定”“小时级高负载”“私有 veth mimic 对照”“公网 native”与“目标设备验证”，不给不可测部分补造结论。
- 无 SSH/测试秘密或原始生产信息进入 Git；review diff、文件列表及公开报告的脱敏结果。
- 没有替换现有生产 Hysteria；用户尚未授权的生产部署或额外发布动作保持待办。

## 17. 一手资料

- [Linux Raw Socket 语义与权限](https://man7.org/linux/man-pages/man7/raw.7.html)
- [unshare：私有 mount/network/PID 与子进程生命周期](https://man7.org/linux/man-pages/man1/unshare.1.html)
- [ip-netns：命名 namespace 与挂载点](https://man7.org/linux/man-pages/man8/ip-netns.8.html)
- [systemd-run：transient unit](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html)
- [systemd resource control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)、[执行环境与日志](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)、[service 生命周期](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
- [Linux cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
- [nftables 官方手册](https://netfilter.org/projects/nftables/manpage.html)、[conntrack-tools 手册](https://www.netfilter.org/projects/conntrack-tools/conntrack-manpage.html)
- [Linux IPv4 hook 优先级](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv4.h)、[TCP conntrack 状态机](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_conntrack_proto_tcp.c)
- [mimic 上游](https://github.com/hack3ric/mimic)；具体对照必须固定其 commit，不以浮动分支名作为版本证据。

执行时以目标机已有版本的帮助/手册和固定源码为准；不为使示例命令可用而升级生产系统。
