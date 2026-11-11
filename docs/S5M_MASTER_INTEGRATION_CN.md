# WireGuard 接入 S5M 共用主控面板方案

## 目标与边界

WireGuard Agent 必须进入现有 S5M Master 主控面板，与 S5M-Agent-SmartDNS 使用同一个登录入口、设备/节点列表、实时状态通道、授权管理和审计视图。用户不应部署第二套 Master，也不应在 Mihomo 与 WireGuard 两个 Agent 之间重复绑定同一台物理设备。

运行时仍保持隔离：WireGuard 与 Mihomo/SmartDNS 使用独立容器镜像、数据目录、密钥、配置 revision、实例 ID、命令队列和升级/回滚生命周期。共享的是 Master 控制面与 UI，不是运行进程、配置文件或凭据。

## 从现有 Master 契约确认的兼容事实

当前 `S5M-Master/docs/AGENT_API_CONTRACT.md` 和 `source/internal/app/agent_websocket.go` 的实现提供：

- `POST /api/v1/agent/register`：请求字段为 `machine_code`、`secret`，返回专属 Agent JWT。
- `GET /api/v1/agent/ws`：Agent 使用 `Authorization: Bearer <JWT>` 建立主动 WebSocket。
- 欢迎消息：`welcome` / protocol 1 / heartbeat interval。
- 当前 Agent 心跳校验器强制要求 Mihomo 字段（`mihomo_version`、`mihomo_healthy`、流量、连接数、`config_sha256`、`last_error`）。
- 当前配置请求、配置下发和命令 ACK 均以单一 `machine_code` 作为状态/配置/命令存储键。
- 当前连接注册表也以 `machine_code` 为 key；同一 machine code 的新连接会取代旧连接。

因此，**当前 Master WebSocket 不能直接接受 WireGuard 专用心跳**。WireGuard Agent 不得伪造 Mihomo 状态字段，也不得复用 Mihomo 配置、密钥或命令队列来绕过这个限制。

## Master 必须先完成的兼容扩展

### 1. Agent 实例身份与授权

增加稳定的 `instance_id` 和受约束的 `agent_type`（至少 `mihomo`、`wireguard`）。物理设备 machine code 作为父级设备身份；每个运行实例独立授权、撤销、在线状态和连接 generation。

- 允许同一 machine code 同时注册 Mihomo Agent 与 WireGuard Agent。
- 注册/续期凭据必须按 instance_id 隔离；不能继续仅以 `agent_machine_<machine_code>` 作为唯一凭据槽。
- WebSocket 连接、pending command、command result、desired config、revision/hash 均按 instance_id 隔离。
- 旧版 SmartDNS Agent 保持兼容：缺少 agent_type/instance_id 时按既有 Mihomo 逻辑处理，不能导致现有节点掉线或授权失效。
- 撤销某个实例只断开和清理该实例，不影响同设备的另一个 Agent。

### 2. 类型化状态模型

WebSocket envelope 增加协议版本和 agent_type/instance_id。心跳按 agent_type 分派严格校验器：

- Mihomo：保留当前 Mihomo/SmartDNS telemetry schema。
- WireGuard：只上报 backend、capability、interface name/state、role、listen port、peer 公钥指纹、peer handshake 时间、RX/TX counters、desired/applied revision、config SHA-256、last error。
- WireGuard 状态绝不包含 private key、PSK、注册 token、RouterOS API 密码或完整配置。
- Master UI 按类型渲染状态卡片，不把 WireGuard 的 running 映射成 mihomo_healthy。

### 3. 配置与命令隔离

WireGuard 配置单独存储为版本化 `s5m.wireguard/v1alpha1` YAML，不复用 Mihomo YAML 编辑器或 `node_configs(machine_code)` 单槽。

WireGuard 命令采用显式 allowlist（例如 apply、stop、status、peer rotate 等后续经安全评审的操作），带 command_id、instance_id、revision、deadline。禁止任意 shell、RouterOS CLI 或自由命令字符串。ACK 必须先持久化再清除 pending；重复投递和重复 ACK 必须幂等。

### 4. 共用面板 UX

在现有“节点实例管理”视图中增加 Agent 类型标识与实例分组：

- 一个物理设备卡片下可显示 Mihomo/SmartDNS 与 WireGuard 两个独立实例。
- 共用设备搜索、在线总览、授权/撤销入口和实时事件通道。
- 各实例分别显示在线状态、最近心跳、运行后端、版本、配置 revision/hash、错误诊断。
- Mihomo 操作仅作用于 Mihomo 实例；WireGuard 启停/配置/Peer 操作仅作用于 WireGuard 实例。
- 不增加第二套主控登录、第二套用户/权限或重复的节点管理菜单。

## WireGuard Agent 实现顺序

1. Master 已支持复合 `(machine_code, agent_type, instance_id)` 身份、独立 JWT、WebSocket 会话代际、状态/配置/命令队列隔离和旧 Mihomo Agent 兼容；WireGuard Agent 现在开始携带实例身份注册。
2. 本仓库实现与 Master 契约一致的注册客户端、单一 WSS 长连接、心跳 ACK、配置 SHA-256 校验、命令执行 journal、幂等 ACK、断线指数退避。
3. 将 Linux kernel backend 接入 Agent service；Agent 控制面断线时不得清除已应用隧道配置或重复执行破坏性命令。
4. 加入 RouterOS 原生 API Adapter；RouterOS 原生隧道状态明确标记为 host-side resource，不伪装成容器内接口。
5. 增加独立 AMD64/ARM64 镜像与部署/升级/回滚流程，并完成 RouterOS 实机验证。

## 当前状态与验收门槛

当前 WireGuard Agent 已实现初始 HTTP 注册、JWT 0600 保存、WSS typed heartbeat/ACK 和指数退避重连；本分支补齐可选的 agentType/instanceID 注册字段，并保留旧机器级配置兼容。Master 已支持复合实例身份及类型隔离的配置/命令存储，但 WireGuard Agent 尚未实现配置拉取、命令请求/分发器；Master 也继续拒绝 WireGuard 远程命令投递，直到专用执行器通过安全评审。RouterOS 原生 API Adapter 与实机验收仍未实现。

因此，在 Master 兼容 PR、Agent WSS 集成测试、旧版 Mihomo 回归测试、授权隔离测试和设备验收完成前，不得宣称 WireGuard 已接入共用主控面板或可用于生产。CI 通过仅证明代码检查，不代表真实 RouterOS 兼容性。
