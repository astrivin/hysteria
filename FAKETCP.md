# 原生 FakeTCP（实验性候选）

本分支把 FakeTCP 直接接入 Hysteria 2 的 `net.PacketConn`：进程通过 Raw IP Socket 收发 TCP 格式的数据包，不经过本地 UDP 转发程序，也不需要 TUN、eBPF 或 mimic 的专用内核模块。QUIC 的 TLS、认证、数据可靠性和拥塞控制仍由原有 Hysteria 核心负责；外层不会再次重传业务数据或施加 TCP 拥塞控制。

**当前仍是实验性候选。当前线协议为 v2，不能与 `c14bce9` 及更早的候选混用。** v2 为业务帧增加会话标识，修复旧连接迟到数据影响新连接 ACK 的问题；同时修复休眠恢复后的端口预留泄漏、读路径控制回复阻塞，并允许软件 GRO 聚合。修复说明见 [FAKETCP_FIXES.md](FAKETCP_FIXES.md)。可选的 `autoFirewall` 按进程管理固定规则，不改变线协议，与 `be0c5964` 等 v2 构建兼容，双方可以分别升级。

Linux 两架构的旧候选已完成报告所列的真实 Raw Socket、双向公网低负载及各61分钟观测；用户也已在 WSL2 和 Android 运行旧候选，并报告休眠恢复缺陷。旧版本测试不能替代修复版本的设备恢复验收。持续高负载、mimic 对照与硬件 offload 仍未完成；历史证据见 [实机测试报告](FAKETCP_TEST_RESULTS.md)。

## 兼容范围

- 客户端和服务端都必须使用支持本协议的构建，并同时选择 `transport.type: faketcp`。
- 这是独立的线协议，不能与 Hysteria 1 FakeTCP、udp2raw、Phantun、mimic 或普通 TCP/HTTP 服务互通。普通 UDP Hysteria 客户端也不能直连此监听端口。
- 实现针对 Linux 内核，包括具备相应权限的 WSL2 和 Android。其他操作系统选择此传输时会返回不支持错误；其他操作系统仍可使用原有 UDP 传输。
- TCP 格式有助于通过接受此类流量的网络设备，但并不实现标准 TCP 字节流语义。严格检查 TCP 状态的网关、TCP 代理及各类 NAT 仍需逐一验证。

## 配置

以下地址、证书路径和密码均为示例。示例开启自动防火墙；省略 `autoFirewall` 时，沿用后文的手工规则方式。

### 服务端 `server.yaml`

```yaml
listen: 0.0.0.0:443

transport:
  type: faketcp
  faketcp:
    autoFirewall: true
    mtu: 1500
    idleTimeout: 2m

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

auth:
  type: password
  password: replace-with-your-own-password
```

### 客户端 `client.yaml`

```yaml
server: 198.51.100.10:443
auth: replace-with-your-own-password

transport:
  type: faketcp
  faketcp:
    autoFirewall: true
    mtu: 1500
    handshakeTimeout: 5s
    # 可省略；默认按路由选择本地 IP，并分配临时 TCP 源端口。
    # localAddr: 0.0.0.0:30443
    # 可省略；只影响外层握手中的 HTTP Host。
    host: www.example.org

tls:
  sni: tunnel.example.net

socks5:
  listen: 127.0.0.1:1080
```

`tls.sni` 必须匹配实际服务器证书或你的原有 TLS 校验配置。`transport.faketcp.host` 不参与证书验证，也不改变连接目标。已有的 `bandwidth`、`congestion`、代理入口和转发配置继续按原方式设置；示例没有修改它们。

下面将所选构建记作 `./hysteria`，执行时按实际下载或构建的文件路径替换：

```sh
sudo ./hysteria server -c server.yaml
sudo ./hysteria client -c client.yaml
```

| 配置项 | 使用端 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `transport.type` | 双端 | `udp` | 选择 `faketcp` 启用本实现 |
| `transport.faketcp.autoFirewall` | 双端 | `false` | 启动时添加固定 RST 规则，退出时删除；重连不修改规则 |
| `transport.faketcp.mtu` | 双端 | `1500` | 外层 IP 包的发送大小上限，允许 `1280`～`65535`；不修改网卡 MTU |
| `transport.faketcp.localAddr` | 客户端 | 空 | 本地 IP 与 TCP 源端口；端口 `0` 表示自动分配 |
| `transport.faketcp.host` | 客户端 | 空 | 可选 HTTP Host，最多 253 字节；只允许主机名/IP及可选端口所需的字符 |
| `transport.faketcp.handshakeTimeout` | 客户端 | `5s` | 外层 TCP 和可选 HTTP 前导交换的总握手超时 |
| `transport.faketcp.idleTimeout` | 服务端 | `2m` | 回收空闲 FakeTCP 对端状态的期限；不是 QUIC 保活设置 |

### IPv4 和 IPv6

服务端 `:443` 或 `0.0.0.0:443` 选择 IPv4。IPv6 必须显式设置 `listen: "[::]:443"`，这是仅 IPv6 的监听。当前单个 FakeTCP 监听不同时覆盖两个地址族；需要双栈时运行两个分别配置的实例。绑定具体地址也可以，例如 `192.0.2.10:443` 或 `[2001:db8::10]:443`。

IPv6 客户端使用 `server: "[2001:db8::10]:443"`，防火墙规则相应使用 `ip6tables`。填写 `localAddr` 时，其地址族应与服务器一致。域名会按现有解析方式选择目标地址，不会自动同时建立双栈 FakeTCP 连接。

## 权限与防火墙

创建 Raw Socket 需要运行进程在其网络命名空间内拥有 `CAP_NET_RAW`。本实现还通过绑定普通 TCP socket 预留端口：非 root 进程绑定 443 等受保护端口时，通常另需 `CAP_NET_BIND_SERVICE`，是否需要取决于系统的低端口策略。配置防火墙需要管理员权限或 `CAP_NET_ADMIN`。**手工规则预先装好且 `autoFirewall: false` 时，程序不需要为了维护规则持有 `CAP_NET_ADMIN`；自动模式需要实际执行 nft/iptables 的子命令在启动和退出时均有管理权限。** 参见 Linux 的 [raw(7)](https://man7.org/linux/man-pages/man7/raw.7.html)。

自动管理只处理本机 FakeTCP RST 规则，不改变 INPUT 策略、云安全组、路由、网卡或 NOTRACK，不调用 modprobe。root UID 本身不能覆盖容器能力边界或 Android SELinux 的限制；目标系统必须实际允许相应操作。

### 自动管理：启动一次，退出一次

双方均可独立设置 `transport.faketcp.autoFirewall: true`。客户端规则只匹配**服务器目标 IP 和目标端口**，覆盖所有本地源 IP 和源端口；服务端只匹配**监听源端口**。以 IPv4、服务器 `198.51.100.10:6666` 为例，iptables 后端执行的规则为：

```sh
# 客户端启动
iptables -w 5 -t raw -I OUTPUT 1 -p tcp -d 198.51.100.10 --dport 6666 --tcp-flags RST RST -j DROP
# 客户端退出
iptables -w 5 -t raw -D OUTPUT -p tcp -d 198.51.100.10 --dport 6666 --tcp-flags RST RST -j DROP

# 服务端启动
iptables -w 5 -t raw -I OUTPUT 1 -p tcp --sport 6666 --tcp-flags RST RST -j DROP
# 服务端退出
iptables -w 5 -t raw -D OUTPUT -p tcp --sport 6666 --tcp-flags RST RST -j DROP
```

IPv6 使用 `ip6tables`。iptables 不创建额外链，不添加源 IP/客户端源端口条件，也不使用规则引用计数数据库。每个进程始终插入一条，正常退出删除一条完全匹配的规则；不使用 `-C` 后跳过安装，以免多个进程共用唯一规则、其中一个退出后影响其他进程。已存在相同手工规则时，进程的这一次添加和删除保持原有规则数量。

默认优先使用 PATH 中的 `nft`，没有时使用相应地址族的 iptables。nft 后端为本进程建立一张私有表，使用相同的目标/端口匹配和 output priority `-300`；这张表同样只在启动与退出时操作。可以通过已有环境变量选择后端：

```sh
sudo env HYSTERIA_FIREWALL_BACKEND=iptables ./hysteria client -c client.yaml
sudo env HYSTERIA_FIREWALL_BACKEND=nftables ./hysteria server -c server.yaml
```

**重连、切换本地网络、源端口改变和握手失败重试均不重新安装或删除运行中的客户端规则。** 规则由最外层客户端持有，直到程序关闭；服务端规则由已有的服务器清理对象持有。Raw Socket 传输层没有防火墙回调或规则对象。

自动模式启动时解析并固定本进程使用的服务器 IP/端口，后续重连继续使用该目标；原域名或显式 `tls.sni` 保留用于 TLS 校验。服务器 DNS 地址变化时重启进程，使目标和规则一起更新。即使使用 `lazy: true`，自动模式也需要在启动阶段确定目标地址。未开启自动管理时保留原有重连解析行为。

要支持 Wi-Fi/移动网络切换，客户端 `localAddr` 留空，或只固定端口，例如 `localAddr: ":6666"`；不要绑定某个 Wi-Fi 的具体 IP。每次新连接仍按当前路由选择本地源 IP。已建立连接不原地迁移到另一个源 IP，切网后的请求可能先触发旧连接超时，再由现有重连机制恢复。

正常关闭、SIGINT/SIGTERM 以及已覆盖的初始化/运行失败出口会清理规则。初始化期间的信号可能等待当前初始化或握手结束。删除失败会记录错误；SIGKILL、崩溃或断电无法执行清理。升级旧逐连接版本时先正常停止旧进程；新版不扫描或接管旧 `HY2-FT-*` 链。

### 手工管理规则

外层 TCP 由用户态处理，内核没有对应的已建立 TCP 连接，可能对收到的包产生 RST。双方需要在 **conntrack 处理之前** 丢弃这些本机 RST，而不仅是阻止它们离开机器。以下规则使用 `raw` 表的 `OUTPUT` 链，只匹配所选服务的 RST；每套规则只添加一次，并按实际端口/IP修改。

Linux 的 raw hook 默认优先级为 `-300`，conntrack 为 `-200`，普通 filter 为 `0`。如果只在 filter 表 DROP，conntrack 已可能将连接改成 `CLOSE`、缩短超时，从而影响后续状态检查和 NAT 映射；最后丢包不会撤销先前的状态变化。这里仅提前丢弃 RST，不对业务连接设置 NOTRACK，正常 FakeTCP 报文仍接受 conntrack/NAT 处理。依据见内核的 [IPv4 hook 优先级](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv4.h)、[IPv6 hook 优先级](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv6.h) 和 [TCP conntrack 状态处理](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_conntrack_proto_tcp.c)。

IPv4 服务端，服务端口为 443：

```sh
sudo iptables -t raw -I OUTPUT 1 -p tcp --sport 443 --tcp-flags RST RST -j DROP
```

IPv4 客户端，服务器为 `198.51.100.10:443`：

```sh
sudo iptables -t raw -I OUTPUT 1 -p tcp -d 198.51.100.10 --dport 443 --tcp-flags RST RST -j DROP
```

对应的 IPv6 规则：

```sh
# 服务端
sudo ip6tables -t raw -I OUTPUT 1 -p tcp --sport 443 --tcp-flags RST RST -j DROP

# 客户端
sudo ip6tables -t raw -I OUTPUT 1 -p tcp -d 2001:db8::10 --dport 443 --tcp-flags RST RST -j DROP
```

客户端规则使用实际服务器 IP。域名解析结果或端口变化后，应同步更新规则；是否跨重启保存由系统的防火墙管理方式决定。停止使用时可用相同匹配条件执行 `iptables -t raw -D OUTPUT ...` 或 `ip6tables -t raw -D OUTPUT ...` 删除规则。必须保留 `-t raw`，删除命令不带上面插入位置的 `1`。例如，删除上述 IPv4 客户端规则：

```sh
sudo iptables -t raw -D OUTPUT -p tcp -d 198.51.100.10 --dport 443 --tcp-flags RST RST -j DROP
```

`raw` 表是标准 Linux Netfilter 功能，不是本项目或 mimic 的专用内核模块；仍需目标内核和所用 iptables 后端实际支持。以官方配置为例，[WSL2 的 6.18 x86 配置](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.18.y/arch/x86/configs/config-wsl) 将 `CONFIG_IP_NF_RAW` 和 `CONFIG_IP6_NF_RAW` 配置为标准模块，[Android 16 / 6.12 ARM64 GKI 配置](https://android.googlesource.com/kernel/common/+/refs/heads/android16-6.12/arch/arm64/configs/gki_defconfig) 则将两者内建。具体 WSL2 安装的模块、Android 厂商内核、iptables 版本及 SELinux 权限仍须在设备上确认，不能仅凭 root 或 Raw Socket 权限推定。如果使用 nftables 管理规则，等价 RST DROP 也必须位于 conntrack 之前的 output hook，例如 priority `raw`（`-300`）；不能退回普通 filter 链代替。

**不要照搬 udp2raw 的 INPUT DROP 规则。** 此实现使用 `AF_INET`/`AF_INET6` Raw IP Socket。以 Linux IPv4 为例，`LOCAL_IN`/INPUT 处理完成后才会调用 `raw_local_deliver`；在 INPUT 丢弃服务报文，也会让本实现收不到它们。参见内核 [ip_input.c](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c)。系统现有入站策略、云防火墙及 NAT 映射仍应允许该 TCP 服务与回包。

## Host 伪装的边界

设置 `host` 后，客户端在外层 TCP 握手之后发送带该 Host 的短 HTTP 前导，服务端应答后进入 FakeTCP 数据传输；握手阶段会重试，业务包不重复携带 HTTP 头。留空即可省略这层简单伪装。

它不建立真实 HTTP 隧道，不是 WebSocket、TLS SNI 或 REALITY，也不能通过普通 HTTP 反向代理/CDN转发。Host 不会让流量发往所填写的站点。这里没有额外的外层 SNI 配置；实际 Hysteria TLS 的 `tls.sni`、证书校验和认证仍保留。

## MTU、GRO 与 QUIC

业务包的外层开销为：IPv4 头 20 字节或 IPv6 头 40 字节，加 TCP 头 20 字节，加长度帧头 4 字节和会话标识 8 字节。v2 每个数据报比旧候选增加 8 字节，不增加逐包加密或 HMAC。此处不计算握手 SYN 选项或额外的网络隧道开销。

| 外层 MTU | IPv4 可承载的 QUIC 数据报 | IPv6 可承载的 QUIC 数据报 |
| --- | --- | --- |
| 1500 | 1448 字节 | 1428 字节 |
| 1400 | 1348 字节 | 1328 字节 |
| 1280 | 1228 字节 | 1208 字节 |

`mtu` 是该端的发送上限，建议两端使用适合实际路径的值。代码要求至少 1280，发送超过预算时返回 `EMSGSIZE`，并启用禁止 IP 分片的路径 MTU 设置，不会把一个业务数据报拆成多个外层 TCP 段。

FakeTCP 双方从 **1200 字节 QUIC 初始包**开始，后续继续由 QUIC 的 DPLPMTUD 探测更大数据报。这也避免仅依赖本地接口 MTU 或即时 `EMSGSIZE`、在远端 IPv6 瓶颈处丢失初始包。FakeTCP 客户端自动禁用会强制更大初始包的 ChromeParrot；双端禁用 UDP GSO。原有 UDP 传输的这些配置默认值不变。

Brutal 保留目标速率、发送节奏和丢包补偿；本分支将其**最小拥塞窗口由一包修正为两包**，防止极低 RTT 时单个丢失的 MTU 探测包占满窗口，导致后续数据无法发送、缺少新的 ACK 来完成探测判丢。该修正也适用于普通 UDP 的低带宽延迟积路径。[RFC 9002 §4.8](https://www.rfc-editor.org/rfc/rfc9002#section-4.8) 同样建议 QUIC 使用两包的最小拥塞窗口。[Brutal 回归测试](core/internal/congestion/brutal/brutal_test.go) 覆盖探测包之后仍能发送数据，并检查原有未知 RTT、常规带宽延迟积及丢包补偿计算；[真实 QUIC 模拟链路测试](extras/transport/faketcp/quic_test.go) 覆盖 MTU 1280 下的双栈、有故障与无故障传输。

每个数据报包含长度帧头和会话标识，接收端逐帧校验当前会话后才更新外层 ACK 和活动时间。普通数据段不再设置 PSH，避免每包强制刷新 Linux 软件 GRO；握手前导仍保留 PSH。接收缓冲区为每个 PacketConn 512 KiB，覆盖 Linux 的 `GRO_MAX_SIZE = 8 * 65535`，并识别 IPv4 BIG TCP 的零 total-length 表示。发送 MTU 上限仍为 65535，不发送 IP jumbo 包，也不修改网卡或系统 offload 设置。

格式非法、会话不匹配或截断的帧会丢弃，业务数据完整性仍由 QUIC 校验。**这些机制和合成聚合回归不代表已经完成所有网卡、驱动或硬件 GRO 验收，也不保证实际链路一定发生聚合。** 实际 GRO 开关、低 MTU、丢包和乱序验证由后文脚本提供；中间设备任意重分段或代理 TCP 字节流不在协议支持范围内。Linux 定义见 [GRO_MAX_SIZE](https://github.com/torvalds/linux/blob/v6.12/include/linux/netdevice.h#L2247-L2251) 与 [IPv4 BIG TCP 长度](https://github.com/torvalds/linux/blob/v6.12/include/linux/ip.h#L52-L58)。

## 当前限制

- 不能同时启用 `mimic.enabled`、realm/STUN 打洞模式或端口跳跃。
- `obfs.type` 只允许留空或 `plain`；本版不叠加 salamander/gecko，以免额外封装绕过明确的 MTU 预算。
- 不支持 `quic.sockopts.bindInterface`、`fwmark`、`fdControlUnixSocket`；指定它们会报配置错误，不会静默忽略。
- FakeTCP 占用 TCP 端口，`masquerade.listenHTTPS` 等普通 TCP 服务不能占用同一个绑定地址和端口。原来 UDP 443 与 HTTPS TCP 443 可共存的配置需要调整。
- 标准 Hysteria 分享 URI和二维码没有编码这些新增传输参数。双方需要保留 YAML 配置，不能只靠分享链接启用 FakeTCP。
- 服务端最多保留 4096 个 FakeTCP 对端状态；空闲状态按 `idleTimeout` 回收。对端状态重建、连接迁移、各类 NAT及网络切换的行为仍需真实环境验证。

## 构建

从仓库根目录使用满足 `go.work` 的 Go 1.26 工具链。Linux/WSL2 可以直接构建，WSL2 使用与其 Linux 架构匹配的程序：

```sh
mkdir -p build
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o build/hysteria-linux-amd64 ./app
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o build/hysteria-linux-arm64 ./app
```

Android 使用仓库已有的 NDK 构建路径，以 NDK r29 为例，替换为实际安装目录：

```sh
ANDROID_NDK_HOME=/path/to/android-ndk-r29 \
HY_APP_PLATFORMS=android/arm64,android/armv7 \
uv run python hyperbole.py build
```

当前 `hyperbole.py` 为这些 Android 目标使用 API 29 的编译器，产物位于 `build/`。交叉编译只验证目标代码能够生成：Linux 二进制构建、WSL2 实际运行和 Android 真机运行是三项独立验证。Android 还需要在合适的 root/SELinux 环境中配置同样的防火墙规则。

## 测试与验收

### 不需要 Raw Socket 权限的测试

```sh
uv sync
PATH="$PWD/.venv/bin:$PATH" go test -count=1 -timeout=10m ./core/... ./extras/... ./app/...
go test -race -count=1 -timeout=10m ./extras/transport/faketcp/...
go test -run '^$' -bench . -benchmem ./extras/transport/faketcp
```

这些测试覆盖协议处理和原有功能回归；微基准用于观察局部代码开销，不能据此推算真实链路吞吐或与 mimic 比较。

### 真实 Linux Raw Socket 与 QUIC/Brutal

[scripts/test-faketcp-netns.sh](scripts/test-faketcp-netns.sh) 在临时 network namespace/veth 中运行真实 Hysteria 核心。它需要 root、`CAP_NET_RAW`、`CAP_NET_ADMIN`、`CAP_SYS_ADMIN` 和 mount/network/PID namespace 支持，以及 `ip`、`tc`、`iptables`、`ip6tables`、`ethtool`、`timeout`、`sysctl`、`conntrack`、`unshare`、`mount`、Python 3。后两项 namespace 权限属于测试隔离设施，不是 Hysteria 进程本身新增的运行要求。

脚本先通过 `unshare --mount --net --pid --fork --kill-child=KILL --mount-proc --propagation private` 建立外层隔离，再创建命名 namespace 和 veth；不会先在宿主网络中创建临时网卡。私有 `/run`（包括 `/var/run/netns` 和 xtables 锁）、`/tmp`、`/var/tmp` 均绑定到结果目录中本次专属的 `runtime.*` 子目录，`TMPDIR` 也指向该处；这些挂载不传播到宿主。防火墙、路由、MTU、offload、临时端口范围及转发 sysctl 只在测试 namespace 中调整。退出清理仅操作登记为本次成功创建的 namespace/veth 和本次子进程；PID namespace 结束后，其剩余子进程也由内核终止。相关语义见 [unshare(1)](https://man7.org/linux/man-pages/man1/unshare.1.html)、[ip-netns(8)](https://man7.org/linux/man-pages/man8/ip-netns.8.html) 和 [mount_namespaces(7)](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)。

```sh
go build -trimpath -o build/faketcp-integration ./extras/transport/faketcp/internal/integration
sudo bash scripts/test-faketcp-netns.sh

# 在常规用例之后，分别对 UDP 和 FakeTCP 各做 1 小时压力测试。
sudo env FAKETCP_SOAK_SECONDS=3600 FAKETCP_CLIENTS=4 bash scripts/test-faketcp-netns.sh
```

脚本包含 IPv4、IPv6 MTU 1280、GRO 开/关、QUIC 流和 DATAGRAM、HTTP Host、反复连接、SNAT、延迟/丢包/重复/乱序等用例；另用双路由器建立远端 1280 MTU 瓶颈，在两端本地 MTU 为 1500 且 ICMP PMTU 响应被屏蔽时测试 IPv4/IPv6 初始握手和传输。它以相同 QUIC/Brutal 设置比较普通 UDP 与 FakeTCP，验证实际回显内容，并记录内存、goroutine和重连数据。FakeTCP 的 SNAT 用例在每个客户端已验证业务数据、连接仍活动时读取 conntrack，要求对应 TCP 流处于 `ESTABLISHED`，同时核对实际地址/端口翻译并保存原始条目；不会仅凭连续传输成功判断 NAT 状态正常。**此脚本没有 mimic 对照组，也不测试两台服务器之间的公网路径。**

主要负载参数如下；UDP 和 FakeTCP 对照使用相同设置。

| 环境变量 | 默认值 | 含义 |
| --- | --- | --- |
| `FAKETCP_PORT` | `6666` | 服务端口，允许 `6666–7777` |
| `FAKETCP_CLIENTS` | `2` | 独立客户端连接数 |
| `FAKETCP_PARALLEL` | `2` | 每个客户端并发 TCP 流数，范围 `1–128` |
| `FAKETCP_BANDWIDTH` | `12500000` | 每个连接、每个方向的 Brutal 目标速率，单位 bytes/s |
| `FAKETCP_UDP_PPS` | `8000` | 每个客户端的 UDP 应用数据报目标发送率，每包 1400 字节 |
| `FAKETCP_CASE_SECONDS` | `15` | 每个常规用例的负载持续秒数 |
| `FAKETCP_SOAK_SECONDS` | `0` | UDP、FakeTCP 各自追加的压力测试秒数，`0` 表示不追加 |
| `FAKETCP_RESULTS_DIR` | `build/faketcp-results` | 日志、JSON 和私有 runtime 文件的保存位置 |
| `FAKETCP_INTEGRATION_BIN` | `build/faketcp-integration` | 预先构建的负载工具路径 |

客户端临时源端口和 SNAT 翻译源端口也限制在 `6666–7777`，并与服务端口所在区段分开。服务端口位于 `6666–6999` 时，分别使用 `7000–7399` 和 `7400–7777`；位于 `7000–7399` 时，分别使用 `6666–6999` 和 `7400–7777`；位于 `7400–7777` 时，分别使用 `6666–6999` 和 `7000–7399`。这些端口仅存在于测试 namespace，不占用宿主监听端口。

生产服务器上先使用低负载配置，并由调用方给整个进程树设置统一 CPU/内存/I/O 限额和退出期限。namespace 隔离不限制 CPU 或内存；`nice` 和 `GOMEMLIMIT` 也不替代硬资源上限。以下示例将脚本、工具和全部测试文件放在 `/root/tmp/hy2`，其中每个连接每方向目标为 4 Mbit/s，UDP 应用发送目标约为 1.12 Mbit/s。结果目录应为本次专用的新目录。

```sh
# 已将脚本和对应版本的负载工具放到 /root/tmp/hy2；在 root shell 执行。
env GOMAXPROCS=1 GOMEMLIMIT=96MiB \
    FAKETCP_INTEGRATION_BIN=/root/tmp/hy2/faketcp-integration \
    FAKETCP_RESULTS_DIR=/root/tmp/hy2/results-low-load \
    FAKETCP_PORT=6666 FAKETCP_CLIENTS=1 FAKETCP_PARALLEL=1 \
    FAKETCP_BANDWIDTH=500000 FAKETCP_UDP_PPS=100 \
    FAKETCP_CASE_SECONDS=10 FAKETCP_SOAK_SECONDS=0 \
    nice -n 10 timeout --signal=TERM --kill-after=10s 10m \
    bash /root/tmp/hy2/test-faketcp-netns.sh
```

脚本会自行进入私有 namespace，不要在宿主执行其中的 mount、sysctl 或防火墙命令。程序、脚本和结果目录不能位于系统 `/run`、`/tmp` 或 `/var/tmp` 下，因为这些路径在私有 mount namespace 内会被替换；`/root/tmp/hy2` 不受影响。正常退出保留日志和 `runtime.*` 目录以便审阅，不删除其他目录。结束测试时应终止整个调用方进程组或 cgroup；若仅向旧版 `unshare --fork` 的父进程发送 TERM，它可能等待子进程而不转发信号，所以上述示例保留了最终 KILL 期限。

结果包括各客户端 JSON、日志、链路统计、参数记录 `environment.txt` 与汇总 `results.json`。负载工具使用测试证书；可通过 `FAKETCP_TEST_AUTH` 为本轮两端设置相同测试口令，未设置时沿用固定隔离测试口令。它仅供隔离验收环境使用。

### CI 与尚待完成的验证

自动防火墙另有 [scripts/test-faketcp-firewall.sh](scripts/test-faketcp-firewall.sh)。它在私有 mount/network/PID namespace 内运行真实应用入口，覆盖 iptables/nftables 与 IPv4/IPv6。每组同时运行固定源端口和自动源端口客户端，切换 A→B→A 两条网络路径并重启服务端，要求相同客户端进程恢复 SOCKS5 回显，同时防火墙规则和修改命令记录保持不变；另检查正常/失败退出与同规则多实例共存。需要上文的 namespace 权限以及 `nft`，不需要在宿主预先添加规则。

```sh
go test -c -o build/faketcp-firewall.test ./app/cmd
sudo bash scripts/test-faketcp-firewall.sh
```

[.github/workflows/faketcp.yml](.github/workflows/faketcp.yml) 配置了 `faketcp` 分支推送和手动触发：运行现有测试、竞态检查、微基准及上述 Linux 网络用例；手动压力时间允许每种传输 1～120 分钟。只有测试和网络任务都成功，才继续构建 Linux amd64/arm64 与 Android arm64/armv7，并把二进制和 `SHA256SUMS` 上传为该次 Actions 的 artifact。

工作流文件存在不代表已经运行或成功；应检查具体提交对应的任务状态与原始日志。完整验收仍需在具备权限的 Linux、WSL2、Android 上实测，并在相同机器、路径、MTU、offload、Brutal 目标速率和流量模式下另做 mimic 对照。长期压力应持续观察数据正确性、资源增长、重连、MTU变化和网络切换，不能用一次握手或构建成功替代。

实现入口为 [extras/transport/faketcp](extras/transport/faketcp)，配置接入在 [app/cmd/faketcp.go](app/cmd/faketcp.go)，网络负载工具在 [internal/integration/main.go](extras/transport/faketcp/internal/integration/main.go)。设计参考包括 [Hysteria 1 FakeTCP](https://github.com/HyNetworks/hysteria/tree/hy1/core/pktconns/faketcp)、[udp2raw](https://github.com/wangyu-/udp2raw)、[Phantun](https://github.com/dndx/phantun) 和 [mimic](https://github.com/hack3ric/mimic)；本分支的协议、性能与兼容性需独立验证。

完整修改范围见 [FAKETCP_CHANGES.md](FAKETCP_CHANGES.md)。本地 Codex 接管实机测试时，请按 [FAKETCP_TESTING.md](FAKETCP_TESTING.md) 固定源码提交、设置资源预算、逐项记录验收状态；只读预检和资源监控工具位于 [scripts/faketcp](scripts/faketcp)。
