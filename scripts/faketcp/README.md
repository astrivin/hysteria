# 实机验证资源监控

这里是仓库 `scripts/faketcp/` 下的独立预检与监控工具，不会建立 SSH 连接、启动网络负载、修改防火墙或系统参数。实际服务器上的脚本、程序和日志都应放在授权的 `/root/tmp/hy2` 目录。先获取只读预检结果，再决定是否运行负载和设置预算。完整测试顺序见 [FAKETCP_TESTING.md](../../FAKETCP_TESTING.md)，传输配置见 [FAKETCP.md](../../FAKETCP.md)。

| 文件 | 用途 |
| --- | --- |
| `preflight.sh` | 输出系统、能力、资源、测试端口占用及工具信息；创建后立即关闭 IPv4/IPv6 Raw Socket 检查权限，不发送报文 |
| `monitor.py` | 只读资源基线，或对明确注册的测试 PID 监控并执行资源保护 |
| `test_monitor.py` | 本地行为回归，验证只读基线、拒绝错误标记和仅终止指定 PID；仅启动临时测试用 `sleep` 进程 |

文件不包含 SSH 配置、服务器真实地址、私钥或密码。部署目录是服务器上的约定，**不应改成仓库路径**；本地自测通过 `--work-dir` 显式指定临时目录。

## 只读预检

```sh
cd /root/tmp/hy2
sh preflight.sh > preflight.txt
python3 monitor.py baseline --run-id preflight --duration 10 > resource-baseline.jsonl
```

`preflight.sh` 只读取现有状态并进行无发包的 socket 权限检查，不会安装缺少的工具或创建测试目录。它会显示 CPU 占用靠前的进程名称和资源信息，不读取其命令行、环境或文件内容。输出可能包含主机名、接口地址等环境信息，分享前应检查；无需提供 SSH 私钥。

`monitor.py baseline` 不接受 PID，也不发送信号。输出包含整机 CPU 利用率、iowait、steal、硬中断和软中断占比，以及 `MemTotal` 和 `MemAvailable`。默认整机 CPU 连续三次超过 70%，或可用内存低于 256 MiB，就返回非零状态，应停止推进负载阶段。它不扫描其他应用的进程、命令行或环境。

## 监控已经明确授权启动的 PID

整合启动器需要为每个本轮测试进程设置同一环境标记 `HY2_VALIDATION_RUN_ID=本轮唯一编号`，让它的工作目录和可执行文件都位于 `/root/tmp/hy2` 内，并记录实际 PID。

```sh
python3 monitor.py watch --run-id 本轮唯一编号 --pid 12345 --duration 120 > resource-watch.jsonl
```

需要监控多个本轮进程时，重复 `--pid`。工具核对 PID 的启动时间、环境标记、程序路径与工作目录，使用 `pidfd` 绑定进程身份；不会按名称、用户、端口或进程组批量结束进程，也不跟随子进程。执行停止前会重新核对身份，PID 复用不会让信号发送到新进程。

主动保护要求 Linux 支持 `pidfd_open`，且 Python 提供 `os.pidfd_open` 与 `signal.pidfd_send_signal`，通常需要 Linux 5.3+、Python 3.9+。缺少能力时 `watch` 拒绝启用主动保护；`baseline` 仍可使用。`--observe-only` 只记录，不会发送任何信号，因此不能承担自动保护职责。

默认每秒记录一次：每个注册 PID 的 CPU、RSS、fd 数、线程数；所有注册 PID 的 CPU/RSS 总量；整机 CPU、IRQ、softirq、iowait、steal 和内存余量。CPU 指标是相邻采样的差值，第一条为 `null`：进程 CPU 的 100% 表示一个逻辑核，整机 CPU 的 100% 表示全部逻辑核。整机 CPU 包括 IRQ、softirq 和 steal，扣除 idle 与 iowait；IRQ/softirq 无法准确归因到单个用户态进程，因此比较 mimic 等实现时必须同时观察整机数据。

| 参数 | 默认值 | 触发条件 |
| --- | ---: | --- |
| `--max-host-cpu` | 70 | 整机 CPU 超限连续 3 次 |
| `--max-test-cpu` | 40 | 注册 PID 合计超过单核 40%，连续 3 次 |
| `--cpu-breach-samples` | 3 | 上述 CPU 连续超限样本数 |
| `--min-mem-available-mib` | 256 | 整机可用内存低于此值，立即触发 |
| `--max-test-rss-mib` | 160 | 注册 PID 的 RSS 合计超限，立即触发 |
| `--max-fds` | 256 | 任一注册 PID 的 fd 超限 |
| `--max-threads` | 32 | 任一注册 PID 的线程数超限 |
| `--duration` | 120 秒 | `watch` 的硬截止时间；`baseline` 的采样时间 |
| `--term-grace` | 2 秒 | 先 SIGTERM，仍未退出再发送 SIGKILL |

阈值触发、监控错误、监控收到终止信号或到达 `watch` 截止时间，都会只停止已注册且身份仍匹配的本轮 PID。每次发出的信号记录在 JSONL 中。正常退出码为 0，资源超限为 2，`watch` 截止为 124，错误为 1。监控工具不约束系统调度，不能保证采样间隙没有瞬时尖峰；1 核 1 GiB 且承载现有应用的主机应先确认余量，再从小流量、单客户端、单流开始。

## 测试负载口径

`faketcp-integration` 新增 `-udp-pps`，单位为 1400 字节应用 UDP 数据报/秒，默认 8000；低资源用例可设为 50 或 100。这是请求速率，实际数量以 `sent_datagrams` 为准。`-local-addr :7001` 可指定客户端源端口；默认服务地址端口为 6666。测试认证可用双方相同的 `FAKETCP_TEST_AUTH` 环境变量替换；未设置时保留原隔离测试默认密码。

`verified_payload_bytes` 只将通过校验的回显业务数据计一次；一次回显在链路上经过两个方向，不能将该数值当作双向 wire bytes。`verified_payload_mbps` 包含握手、重连及传输完成等待的实际耗时。UDP 的 `verified_datagrams` 统计通过内容校验的回显次数，没有去重，不能据此精确估计丢包率。原 harness 的 Go heap 和 goroutine 数据不等于进程 RSS、峰值内存或 CPU；本工具补充操作系统口径。

## 本地工具回归

在仓库根目录运行；不需要连接服务器或运行 FakeTCP：

```sh
sh -n scripts/faketcp/preflight.sh
python3 -B -m unittest discover -s scripts/faketcp -p test_monitor.py -v
```

测试会在 `scripts/faketcp/` 下建立并清理临时目录；`test_monitor.py` 从自身位置寻找同目录的 `monitor.py`，复制这两份文件到同一目录后仍可运行。测试中的终止行为只涉及该测试自己创建且带匹配标记的进程。
