# FakeTCP v2：连接恢复、代际隔离与 GRO 修复

本轮以 `c14bce98d797ffa8131987fe8704347f126e23f0` 为修复基线。用户已在 WSL2 和 root Android 运行该旧候选，并报告 Windows 休眠或 Android 待机后反复出现 `reserve TCP port: address already in use`。

**客户端和服务端必须一起升级。** 当前线协议升级为 v2，不与 `c14bce9` 及更早候选互通；没有保留会绕过会话隔离的旧协议回退。YAML 参数、Host 用法和 raw OUTPUT RST 规则不变。先在独立测试端口验证，不替换其他正在运行的生产实例。

## 修复内容

### 1. 休眠后端口持续占用

`core/client/reconnect.go` 原先在收到 `ClosedError` 时直接清空旧客户端引用。下一次重连看见 nil，便不再执行原有关闭逻辑；旧 QUIC transport / PacketConn 仍持有本地 socket。FakeTCP 固定 `localAddr` 的 TCP 端口预留会使后续重连持续返回 EADDRINUSE。普通 UDP 的临时源端口使这个资源问题不容易以相同错误暴露。

修复只在已有互斥锁与代际相等检查内增加旧客户端 `Close()`，随后才清空引用。下一次连接必须等待端口释放；迟到的旧请求不会关闭新客户端。不使用 SO_REUSEPORT、不改自动端口选择，也不掩盖真实的其他进程占用。

### 2. 迟到旧数据污染新连接 ACK

旧实现只隔离了握手 hello，合法格式的旧 data 仍可在 QUIC 校验前推进新 peer 的外层 ACK。v2 hello 携带客户端随机 64 位 nonce，welcome 回显该 nonce 并提供服务端随机 64 位 session ID。SYN cookie 同时绑定被替换 peer 的会话；同一客户端 ISN 被再次使用时，也需要新的 cookie 挑战。

每个业务帧携带 8 字节 session ID。接收端在更新 ACK、活动时间或交付数据前逐帧检查它，包括 GRO 聚合中的每个后续帧。合法丢包、乱序、重复及 32 位序号回绕仍按数据报处理，不增加 TCP 重组或可靠重传。会话 ID 是公开的代际标识，业务认证和内容完整性仍由 QUIC 提供。

### 3. 控制回复阻塞读超时和关闭

服务端 SYN-ACK / welcome 和客户端重复 SYN-ACK 的回复原先在 `ReadFrom` 内等待共享写锁及发送队列。读 deadline 不能中断这些写等待，而当前 quic-go 对外部 PacketConn 的关闭恰好依赖读 deadline。

控制回复改为 `TryLock` 加 `RawConn.Control` / `MSG_DONTWAIT`。忙时丢弃控制回复，由已有客户端握手重试恢复；不添加队列、定时器或后台 goroutine。首次客户端握手仍使用有总写期限的发送。新 peer 的发送序号通过 `ready` 原子状态发布，读取路径不再为此等待数据写锁。

### 4. 软件 GRO 与 BIG TCP 接收

普通业务包仅设置 ACK，握手前导继续保留 PSH。这样移除每包 PSH 导致的软件 GRO flush 条件，但不保证每条实际链路都会发生聚合。

接收缓冲独立扩大为每个 PacketConn 512 KiB，覆盖 Linux 的 `GRO_MAX_SIZE = 8 * 65535`；IPv4 聚合长度大于 65535 时，识别 BIG TCP 的零 total-length 表示。发送缓冲和 MTU 上限仍为 65535，不发送 IP jumbo 包，不修改接口或 sysctl。相比旧版本约增加 448 KiB / PacketConn；服务端多个 peer 共用这一接收缓冲。

v2 的业务封装为 TCP 头 20 字节 + 帧头 4 字节 + session ID 8 字节。MTU 1280 时，IPv4 / IPv6 可承载 QUIC 数据报分别为 1228 / 1208 字节，仍容纳 1200 字节初始包。没有增加逐包 HMAC 或第二层加密。

## 验证边界

本地 Go 1.26.11 环境没有 CAP_NET_RAW / CAP_NET_ADMIN，未连接两台生产服务器。使用了普通测试、race、真实 loopback TCP 端口、真实 Unix datagram socketpair、实际 quic-go transport，以及模拟包网络。合成 IPv4 BIG TCP 报文不是实际网卡 GRO 证据。

本地验证结果如下，生产代码及测试在最终 gates 运行前冻结，结束后逐文件核对一致：

| 项目 | 结果与范围 |
| --- | --- |
| 真实本地端口重绑 | TCP / UDP 调用路径、关闭返回错误、旧请求迟到及普通 DialError 回归通过；重连定向 race 重复 50 轮通过。原始 c14 负对照真实返回 EADDRINUSE |
| 控制回复 | SYN / hello / 重复 SYN-ACK 共 6 个控制子例通过。原始 c14 负对照均复现读超时或真实 quic-go Transport.Close 等待写入；新增 Unix socketpair 测试验证真实 poller 写等待期间 TryWritePacket 立即返回 EAGAIN |
| 旧代数据与会话 | 双向 IPv4 / IPv6、同 ISN / 旧 welcome、GRO 旧尾帧、序号回绕及无 PSH 回归通过。原始 c14 在模拟网络中将 ACK 从 10014 推到旧帧末尾 1000037，并实际发出该错误 ACK |
| BIG TCP 接收 | 合成 IPv4 包通过真实 recvmsg：1500、65535、70 KiB、512 KiB 均通过；8 种畸形头及截断后恢复通过；race 重复 10 轮通过。原始 ReadPacket 的负对照丢弃 70 KiB 包并超时 |
| 最终受影响包 race | `./core/client ./extras/transport/faketcp/...`：42 个顶层 / 117 个含子例 PASS，3 个包通过；默认未启用的 soak 随后显式执行 |
| MTU 1280 | IPv4 / IPv6 × 有无故障，重复 10 轮共 40 子例通过 |
| 覆盖率引导 fuzz | 20 秒、429037 次执行，通过 |
| 显式双栈模拟 soak | 每个地址族 60 秒，通过；校验业务字节 IPv4 180355072、IPv6 175112192，含丢包、乱序和合成 GRO；最大模拟 IP 包均为 1279 字节 |
| 本地普通全量 | 308 个顶层 PASS / 5 FAIL / 2 SKIP，整体退出 1；失败情况见下文，未伪报全绿 |

全量的四项环境失败与原始 c14 对照一致：两个 Unix masquerade 用例使用不可见的 `/tmp`，Unix stream 控制 socket 被环境拒绝，DoH 的 `1.1.1.1` TLS 证书没有对应 IP SAN。第五项是 `TestClientServerTrafficLoggerUDP` 的异步离线回调期望时序：候选定向 10/10 通过，未经修改的 c14 定向 9/10 通过并复现同一失败。未删断言、未关闭 TLS 验证，也未修改这个既有测试来掩盖失败。两项默认 skip 是需要额外权限的 UDP 端口重定向，以及已另行显式通过的模拟 soak。

会话校验、逐帧 ACK、welcome nonce 和 PSH 的测试还通过仓库外定向缺陷回注确认能抓住回归；这些人为回注与原始 c14 负对照分开记录。提交后的完整 CI、真实 Raw Socket、netns、NAT、故障和构建结果，以该 SHA 对应的 Native FakeTCP Actions 为准。

旧版本的两机 61 分钟记录继续保存在 [FAKETCP_TEST_RESULTS.md](FAKETCP_TEST_RESULTS.md)，不能迁移为当前 v2 的小时级验收。

## 给本地 Codex 的简短复测清单

1. 拉取 `faketcp`，记录完整 SHA；使用同一个修复提交构建或下载客户端和服务端。核对程序 SHA256，双方一起更新。服务器工作目录仍限定 `/root/tmp/hy2`，测试端口使用 6666–7777，保留现有生产服务及其 20000–50000 端口。
2. 沿用现有可用 YAML、认证、证书与 RST 规则，保留固定 `localAddr: ":7001"`。第一次设双端 MTU 1280，保持 PMTUD 开启；随后再按实际需要检查 MTU 1500 与 Host。不要靠改临时源端口掩盖本次端口问题。
3. 启动新的独立测试实例，通过 SOCKS5 请求实际 HTTPS 网页，确认基础连接正常。
4. WSL2：让 Windows 休眠后恢复，等待原连接超时，再重复请求网页。Android：锁屏待机超过连接空闲期限后唤醒，再请求网页。各重复 3 次即可作为首次恢复验收；不要求重新运行小时压力测试。
5. 预期允许失效旧连接上的首次请求返回关闭错误，后续请求应自动建立新连接；不得持续循环 EADDRINUSE，也不得靠退出整个客户端恢复。记录恢复耗时、是否更换网络/IP、相关日志和可用的进程 fd 计数。fd 不应随每次恢复持续增长。
6. 若连通后仍卡住，先区分：是否仍为本地 `reserve TCP port`，还是外层握手超时、TLS 或远端错误；确认规则还在、IP 和端口未变。不要关闭证书验证、清空防火墙或改生产 sysctl 来掩盖原因。

有正常开发环境时，针对性自动回归可用：

```sh
go test -race -count=10 -timeout=10m ./core/client ./extras/transport/faketcp/...
go test -run TestQUICBrutalMTU1280 -count=10 ./extras/transport/faketcp
FAKETCP_SIM_SOAK=1m go test -run TestQUICBrutalShortSoak -count=1 ./extras/transport/faketcp
go test -run '^$' -fuzz FuzzParseSegmentAndFrames -fuzztime=20s -parallel=2 ./extras/transport/faketcp
```

真实内核网络矩阵沿用 [scripts/test-faketcp-netns.sh](scripts/test-faketcp-netns.sh)，应在专用测试机或 CI 运行。它会覆盖 GRO 开关，但真正的 BIG TCP / 硬件 offload、吞吐收益和 mimic 对照仍需相应设备与测量；构建或合成测试通过不能替代这些结果。
