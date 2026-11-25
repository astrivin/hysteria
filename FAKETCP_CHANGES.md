# 原生 FakeTCP 候选修改总结

本文件记录 `faketcp` 分支相对基础提交 `7040c16752192e1ba72ee251005809a6bd9c9fd6` 的实现范围与历史开发验证结果。**这仍是实验性候选：尚未完成持续高负载、硬件 offload、WSL2/Android 真机及 mimic 性能对照验收。** 后续 Linux 两架构、双向公网低负载、各61分钟观测及清理实证见 [实机测试报告](FAKETCP_TEST_RESULTS.md)；构建、模拟和真实环境的结论按报告范围分别记录。

配置与部署边界见 [FAKETCP.md](FAKETCP.md)，后续复测与本地 Codex 交接见 [FAKETCP_TESTING.md](FAKETCP_TESTING.md)。

## 1. 生产代码改动

| 位置 | 修改内容 |
| --- | --- |
| [extras/transport/faketcp](extras/transport/faketcp) | 新增独立的 `net.PacketConn` 传输：地址处理、Linux Raw Socket、TCP 编解码、握手与数据报状态、非 Linux 平台错误入口 |
| [app/cmd/faketcp.go](app/cmd/faketcp.go) | 新增配置结构、原生连接工厂、监听创建及互斥项校验 |
| [app/cmd/client.go](app/cmd/client.go)、[server.go](app/cmd/server.go) | 接入 `transport.type: faketcp`；保持 UDP 为默认传输；对原生 FakeTCP 设置安全的 QUIC 初始包大小并禁用不适用的选项 |
| [core/client](core/client)、[core/server](core/server) | 各增加 `QUICConfig.InitialPacketSize` 字段及到 quic-go 配置的一处映射；零值沿用原默认，不增加新的 YAML 旋钮 |
| [core/internal/congestion/brutal](core/internal/congestion/brutal) | 将最小拥塞窗口从一包修正为两包，处理低 RTT 与丢失 MTU 探测包的交互；详见下节 |

服务端配置构造过程中，如果后续填充步骤失败，现在会关闭已经创建的连接和清理对象，避免配置错误后仍占用监听端口。相关回归测试验证 UDP 端口可以重新绑定。

新增传输直接在 Hysteria 进程内工作，不启动 udp2raw、Phantun 或 mimic，不增加本地 UDP 中转进程。QUIC 的 TLS、Hysteria 认证、可靠流、DATAGRAM 和拥塞控制仍由原有核心处理；外层 FakeTCP 不对业务数据再次重传，也不引入标准 TCP 的可靠字节流和拥塞控制。

### 原生传输与协议

- Linux 后端使用 `AF_INET`/`AF_INET6` Raw IP Socket，自行生成 TCP 头与校验和；普通未连接的 TCP socket 仅用于保留本地端口。
- 使用经典 socket BPF 过滤目标端口，减少无关包进入用户态；不使用 eBPF、TC/XDP、TUN 或专用内核模块。程序不会修改防火墙或加载模块。
- 实现外层 SYN/SYN-ACK/ACK 和协议前导交换，包括握手重试、重复报文处理、SYN cookie 校验、同四元组重连、服务端状态过期与回收；服务端状态上限为 4096 个对端。
- 重连用的 SYN cookie 绑定当前连接的双方初始序号，防止 A→B→C 重连后，仍在时间窗内的旧 A/B hello 把服务端切回旧连接。当前连接的重复 SYN 复用同一 cookie，客户端每轮重试重新发送 SYN，以便竞争握手改变 cookie 后仍能完成握手；这些运算只在控制面，不增加数据包热路径的 HMAC。
- 数据报有 4 字节长度帧头，接收端可从一个合并负载中取出多个完整数据报；包含非法长度、截断帧、序号回绕、乱序/丢包/重复、并发关闭与 deadline 的测试。
- 对多本地地址监听保留实际目的 IP，使服务端回复使用正确源地址。发送缓冲区与编解码逻辑集中在新包内，未引入通用包编码器或新的第三方传输依赖。

这是新的线协议，两端都必须使用本实现；不能与 Hysteria 1 FakeTCP、udp2raw、Phantun、mimic 或普通 TCP 服务互通。严格状态检查、NAT、网络切换及实际网卡 offload 的兼容性仍须实测。

### MTU、GRO 与 QUIC 接入

配置的 MTU 表示完整外层 IP 包的发送上限。数据包开销为 IPv4 20 字节或 IPv6 40 字节，加 TCP 20 字节和帧头 4 字节；MTU 1280 时分别最多承载 1236 或 1216 字节 QUIC 数据报。超过配置预算的发送返回包装后的 `EMSGSIZE`，并使用禁止 IP 分片的路径 MTU 设置。

FakeTCP 双端固定从 1200 字节 QUIC 初始包开始，随后继续使用 DPLPMTUD。这样避免初始包在远端 IPv6 1280 MTU 瓶颈上过大而黑洞，不能只依赖本地接口 MTU 或即时 `EMSGSIZE`。FakeTCP 客户端自动禁用会覆盖初始包大小的 ChromeParrot，双端禁用 UDP GSO；原有 UDP 的这些配置默认值不变。

长度帧支持 GRO 合并后的数据报拆分，但没有将其声明为已通过所有驱动、网卡或硬件 GRO 测试。任意 TCP 字节流重分段、TCP 代理和 HTTP 反向代理不属于当前协议支持范围。

## 2. 配置与权限边界

| 配置 | 使用端 | 默认值 |
| --- | --- | --- |
| `transport.type: faketcp` | 双端 | 未设置时仍使用 UDP |
| `transport.faketcp.mtu` | 双端 | 1500，允许 1280～65535 |
| `transport.faketcp.localAddr` | 客户端 | 按路由选源地址并分配临时 TCP 端口 |
| `transport.faketcp.host` | 客户端 | 空，不添加 HTTP Host 前导 |
| `transport.faketcp.handshakeTimeout` | 客户端 | 5 秒 |
| `transport.faketcp.idleTimeout` | 服务端 | 2 分钟，回收 FakeTCP 对端状态 |

HTTP Host 仅用于外层握手中的短 HTTP 前导，不改变实际服务器地址，不参与证书验证，不提供 WebSocket、REALITY 或外层 TLS SNI。原 Hysteria 的 `tls.sni`、证书校验与鉴权保持独立。本版满足简单 Host 伪装的选项，没有额外的外层 SNI 配置。

明确拒绝与 mimic、realm/STUN、端口跳跃、salamander/gecko 和 UDP 专用 `quic.sockopts` 同时启用，避免配置表面生效、实际被忽略。标准分享 URI/二维码不包含新增参数；FakeTCP 使用 TCP 端口，不能与相同地址端口上的 `masquerade.listenHTTPS` 等 TCP 服务共存。

服务端 `:port` 或 `0.0.0.0:port` 选择 IPv4；`[::]:port` 是 IPv6-only，双栈需要两个实例。Linux 内核目标包括具备实际权限的 WSL2 和 Android；非 Linux 平台选择此传输返回不支持错误，仍可使用 UDP。

运行时需要 `CAP_NET_RAW`；非 root 绑定受保护端口时还可能需要 `CAP_NET_BIND_SERVICE`。配置防火墙需要管理员/`CAP_NET_ADMIN` 权限；预先配置好规则后，Hysteria 不需要为了维护规则保留该能力。标准 Netfilter `raw` 表是否可用仍取决于系统内核和防火墙后端。

部署必须在 **conntrack 之前的 `raw/OUTPUT`** 丢弃匹配该服务的本机 RST，普通 filter 表的位置太晚；不能照搬 udp2raw 的 INPUT DROP，否则 Raw IP Socket 也收不到入站数据。具体命令、删除规则和双栈差异集中在 [部署文档](FAKETCP.md#权限与防火墙)。

## 3. Brutal 两包最小窗口修正

模拟真实 QUIC 传输时，低 RTT、MTU 1280、没有注入故障的用例暴露了停滞：quic-go 将 MTU 探测包计入在途字节，但只剩 MTU 探测包时不会单独启动 PTO。原先一个 MSS 的最低窗口可能被一个更大的、已经丢失的探测包占满，无法再发普通数据，也没有新的 ACK 推动判丢。

修正仅将 `GetCongestionWindow` 的最低值改为 `2 * maxDatagramSize`。目标速率、pacing、带宽延迟积乘数和丢包补偿不变；这项修正也影响普通 UDP 在极低带宽延迟积下的窗口下限，不能宣称 Brutal 完全没有变化。[RFC 9002 §4.8](https://www.rfc-editor.org/rfc/rfc9002#section-4.8) 同样建议两包的最小拥塞窗口。

新增回归验证：MSS 1200/1280 时，孤立 MTU 探测包不会阻止继续发送数据；未知 RTT 的默认窗口、常规带宽延迟积与丢包补偿计算仍符合原行为。相同新测试在原一包窗口的诊断副本中稳定失败，修正后通过。

## 4. 测试、工具与 CI

- [packet_test.go](extras/transport/faketcp/packet_test.go)：校验和参考实现、IPv4/IPv6 编解码、MTU 边界、HTTP 前导、GRO 帧边界、截断及非法格式；提供 fuzz 与局部微基准。
- [conn_test.go](extras/transport/faketcp/conn_test.go)：模拟包 I/O 的握手丢失/重复、cookie、超时、重连、服务端重启、多地址回复、并发与 deadline 等回归。
- [quic_test.go](extras/transport/faketcp/quic_test.go)：真实 Hysteria 核心、QUIC/TLS/Brutal 和数据内容校验，底层包 I/O 模拟 MTU、丢包、乱序及 GRO；包括可显式启用的短 soak。
- [app/cmd/faketcp_test.go](app/cmd/faketcp_test.go)：配置字段、互斥项、默认 UDP、Host/SNI 独立、QUIC 初始包设置及错误资源清理。
- [integration/main.go](extras/transport/faketcp/internal/integration/main.go)：UDP/FakeTCP 对照负载，可靠流与 DATAGRAM 回显校验、重连、运行时内存和 goroutine 记录。新增 `-bandwidth`、`-udp-pps`、`-local-addr` 与 `FAKETCP_TEST_AUTH`，支持逐步降低负载、固定源端口和本轮随机测试口令；默认服务地址端口为 6666。
- [test-faketcp-netns.sh](scripts/test-faketcp-netns.sh)：真实 Raw Socket 测试脚本，包含双栈、MTU 1280、远端 MTU 瓶颈且 ICMP 被屏蔽、GRO 开关、故障注入、重连和 SNAT/conntrack 状态检查。外层 mount/network/PID namespace 隔离网卡、挂载、规则、sysctl 与测试子进程；临时文件放在结果目录，服务/客户端/SNAT 端口限制在 6666～7777。它不测试两台机器之间的公网路径，也没有 mimic 对照组。
- [scripts/faketcp](scripts/faketcp)：只读预检、明确 PID 的资源监控和本地监控行为测试；不会自动 SSH、启动网络负载或修改防火墙。主动监控核对运行标记、启动时间和目录，并通过 pidfd 防止 PID 复用误杀。
- [.github/workflows/faketcp.yml](.github/workflows/faketcp.yml)：分支推送/手动触发；先运行回归、竞态、微基准和真实 Linux 网络任务，成功后再构建四个平台并上传校验和。构建标为 `faketcp-candidate-<sha>`/`dev`。工作流文件存在不代表任务已成功执行。

负载中的 `verified_payload_bytes` 将回显业务数据只计一次；不是双向 wire bytes。UDP 已验证回显计数没有去重，不能当作精确丢包率。Go heap 不是 RSS；独立监控还记录 CPU、RSS、fd、线程、整机可用内存以及 IRQ/softirq，比较内核参与程度不同的实现时应同时观察整机开销。

提交前新增的两项握手回归覆盖普通和 HTTP Host 模式：A→B→C 后重放旧 hello、重放当前 hello、当前 SYN 幂等，以及竞争握手造成 cookie 失效后的重新获取。原代码在旧 hello 测试中可复现连接回退；仅修改服务端时，竞争握手测试会超时；客户端同步刷新后，定向竞态测试和未修改的 QUIC MTU 1280 双栈矩阵均通过。此前下载的候选程序不包含这项后续修复，实机验收应从待验提交重新构建。

## 5. 实际已完成的开发验证

以下为 **2026-11-24（America/Los_Angeles）的开发验证记录**，是不同阶段的独立结果，不能相加为“当前完整测试全部通过”。提交前的最终全量回归已包含三个 harness 测试和两项握手代际回归。

| 项目 | 实际结果 | 适用范围 |
| --- | --- | --- |
| 提交前最终全量 `go test` | 顶层测试 295 通过、4 失败、2 跳过；包级 28 通过、3 失败、14 无测试 | 已包含 Brutal 修正、harness 和握手代际回归；四项失败仍与基础版本的环境失败相同，整体命令未通过 |
| FakeTCP 编解码、状态与配置定向测试 | 通过；相关竞态测试通过 | 用户态与配置路径，不是实际 Raw Socket 链路 |
| QUIC/Brutal MTU 1280 矩阵 | IPv4/IPv6 × 有/无故障，10 轮共 40 个子用例通过；另一次 race 矩阵通过 | 真实核心与密码学，底层包 I/O 模拟 |
| 提交前双栈短 soak | 握手代际修复后，两个地址族分别持续约 60 秒并通过 | 模拟丢包、乱序、GRO；不是长期实机压力 |
| 编解码 fuzz | 约 20 秒、1,113,669 次执行，通过 | 已执行样本范围内的格式健壮性 |
| 新增 harness 局部测试 | 三个测试通过，包含 `-race` | UDP 发送节奏、测试认证覆盖、指定 UDP 源端口绑定；已包含在最终全量回归中 |
| 监控工具回归 | 三项通过 | 基线只读、错误运行标记拒绝发信号、超限只终止指定 PID 并保留旁边未注册进程 |
| 历史候选构建 | Linux amd64/arm64、Android arm64/armv7 候选已构建 | Android 使用 NDK r29/API 29；这些产物早于最终握手代际修复，应从新提交重新构建；只验证目标代码生成与 ELF 信息 |
| 本机可执行文件检查 | Linux amd64 的 `version` 命令成功 | 不是该二进制的 FakeTCP 运行验收 |

最终短 soak 校验的 TCP 数据量分别为 IPv4 **177,209,344 字节**、IPv6 **178,257,920 字节**，覆盖 676/680 条 TCP 流与 169/170 个 UDP 会话。IPv4 注入 7,588 次丢包、13,011 次乱序和 22,158 次 GRO 合并，IPv6 对应为 7,700 / 13,343 / 22,807；观测到的最大模拟 IP 包均为 1279 字节。它说明这组模拟故障与负载期间内容校验通过，不能用其换算真实网卡吞吐，也不能据此比较 mimic。

最终全量的四项失败在基础版本中也存在，记录原因如下；没有通过删测试、修改 TLS 校验或放宽条件把它们变成通过：

| 测试 | 当前执行环境中的原因 |
| --- | --- |
| `TestMasqueradeProxyUnixURLStyles` | 测试使用的硬编码 `/tmp` 不存在 |
| `TestMasqueradeProxyUnixReusesConnections` | 同上 |
| `Test_fdControlUnixSocketImpl` | Unix socket 创建被执行环境拒绝，`operation not permitted` |
| `TestResolver` | 访问 `1.1.1.1` 时得到的 TLS 证书没有对应 IP SAN，证书校验失败 |

两项跳过是需要额外权限的 `TestUDPPortRedirectIntegration`，以及未在该全量命令中开启的 `TestQUICBrutalShortSoak`；短 soak 已用独立命令执行，结果如上。后续应在正常测试环境对最终提交重新运行全量测试，并记录新结果，不能把这些历史原因当作未来失败的自动豁免。

## 6. 尚未完成与后续验收

下文保留提交前开发环境的历史限制；后续已执行项目及仍受限范围以 [实机测试报告](FAKETCP_TEST_RESULTS.md) 为准。

开发环境不具备实际 Raw Socket 链路测试所需权限。两个 Linux 目标的远端连接也未能建立 SSH，认证没有开始，因此没有远端配置变更或实机运行结果。

尚未验证：真实 Linux Raw Socket 收发与 NAT/conntrack、实际硬件 GRO、WSL2 和 Android 真机、跨机公网路径、长时间高负载资源增长、不同 MTU/网络切换、以及与 mimic 在相同机器和路径上的吞吐/CPU/内存对照。短模拟 soak、UDP 对照脚本及微基准均不能替代这些验收。

下一位执行者应先运行只读预检，检查能力、依赖、6666～7777 端口和资源余量，再选择低负载起点。在承载重要服务的 1 核 1 GiB 主机上，namespace 不提供 CPU/内存隔离，监控阈值也不能消除采样间隙的瞬时尖峰；具体负载、硬资源限制与退出策略应按实际预检结果确定。完整步骤与证据保存要求见 [测试交接](FAKETCP_TESTING.md)。
