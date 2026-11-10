# S5M-Agent-WireGuard 架构设计

## 1. 仓库与镜像隔离

本仓库只负责 WireGuard + Agent。现有 Mihomo + Agent（包括 SmartDNS/no-SmartDNS）仍由 `Tony855/S5M-Agent-SmartDNS` 独立维护。两边可以复用协议约定，但不共享二进制、配置目录、容器、私钥、Token、发布标签或升级流程。

每台物理设备允许注册多个独立 Agent Instance。WireGuard 实例使用独立 instance ID、token、配置 revision、命令序列和状态，不得复用 Mihomo 实例的运行状态或命令队列。

## 2. 控制面与数据面

- 控制面：Agent 主动连接 S5M Master。WebSocket 是状态、配置同步、命令、结果和 ACK 的主通道；HTTP 仅用于初始注册和基础健康检查。
- 数据面：WireGuard backend。Linux Docker 首选内核 WireGuard；RouterOS Container 首选由 Agent 通过受限 RouterOS API 管理 RouterOS 原生 WireGuard。
- RouterOS 原生 backend 下，WireGuard interface 属于 RouterOS 主机，不属于容器网络命名空间。Agent 只通过 API 管理受控资源，不能把它报告成容器内 wg0。
- `wireguard-go-experimental` 只有在设备明确提供可用的 TUN 设备和所需权限时才允许启用。RouterOS 容器文档中可映射设备不等于此 backend 已经通过设备验收。

## 3. Runtime Adapter

`Runtime` 接口隔离配置应用、状态探测和停止操作。每个 backend 必须先 Probe，验证能力后才能 Apply。能力不足时拒绝启动，不得降级为任意 shell/CLI 执行。

### Linux kernel backend

- 通过固定参数调用 `ip` 与 `wg`，禁止 shell 拼接。
- 私钥只通过文件路径交给 WireGuard 工具，不输出到日志。
- 应用前快照 interface、peer 和路由；变更失败恢复旧配置。
- 不默认添加 default route；明确校验 AllowedIPs 路由冲突和管理控制面回程。

### RouterOS native backend

- Agent 通过 RouterOS API TLS 连接设备；凭据最小权限、加密保存、可轮换。
- 仅实现 interface、peer、address、route 的受控 CRUD；不支持 arbitrary command。
- 对每个请求设置 deadline、幂等 operation ID 和审计记录。
- 变更前读取现状，变更后复查；失败按逆序恢复旧对象。
- 默认不修改 RouterOS 默认路由、防火墙全局规则或现有 NAT。
- API 断连时报告 degraded，不重复创建 peer/interface。

### Container userspace backend（实验）

需要实机验证 TUN 可用性、权限、吞吐、重启、路由和资源占用。任何单项失败都应显示 unsupported，不自动切换到 RouterOS native backend。

## 4. 配置与密钥

- 配置 API 版本化，所有字段严格解析；未知字段拒绝。
- 私钥和 PSK 仅引用数据目录内的文件，不允许 YAML inline secret。
- 密钥文件权限目标 0600，数据目录 0700；备份和导出不得默认包含私钥。
- Agent 日志、心跳、错误、命令结果只包含 peer 名称、公钥指纹、状态和计数，不包含 privateKey/PSK/Token。
- AllowedIPs 按 Peer 全局检测重叠；默认拒绝歧义路由。
- Client 必须有 endpoint；Server 可省略 endpoint。

## 5. 运行状态

Agent 需分别上报 desired revision 与 applied revision、配置 SHA-256、backend capability、interface 状态、peer latest handshake、RX/TX bytes、错误码和时间戳。只有实际读取 backend 状态后才能标记 running/healthy；进程存活或心跳新鲜不能替代隧道健康。

## 6. 命令安全

所有命令带唯一 command ID、instance ID、config revision、deadline。重复命令必须幂等；过期命令拒绝；ACK 结果先持久化后清理 pending。网络操作支持 prepare/apply/verify/commit，失败 rollback。默认拒绝任意命令字符串。

## 7. RouterOS 网络拓扑

RouterOS Container 使用 VETH 接入独立受控 bridge/VLAN。容器管理流量与 WireGuard 转发流量分离。RouterOS native backend 的隧道终结在 RouterOS host；容器只需要到 RouterOS API 与 Master 的管理路径。不得将 Docker NET_ADMIN、Host Network 或 Linux kernel module 能力假定为 RouterOS Container 能力。

建议先在非生产 RouterOS 设备完成 PoC：容器架构、VETH 管理可达性、API TLS、原生 WG interface/peer 创建、AllowedIPs 路由、重启恢复、回滚、API 凭据权限。RouterOS 7.x 各设备/版本的容器能力需按官方文档和实机验证。

## 8. 当前实现状态

当前仓库第一阶段只提供严格配置模型和 Runtime 契约。Linux/RouterOS backend、Agent WebSocket、Docker 镜像和 RouterOS 实机验收尚未完成，不得把示例配置或 CI 通过误认为生产可用。
