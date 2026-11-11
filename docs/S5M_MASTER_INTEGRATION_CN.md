# WireGuard 接入 S5M 共用主控面板方案

## 目标与边界

WireGuard Agent 必须进入现有 S5M Master 主控面板，与 S5M-Agent-SmartDNS 使用同一个登录入口、设备/节点列表、实时状态通道、授权管理和审计视图。用户不应部署第二套 Master，也不应在 Mihomo 与 WireGuard 两个 Agent 之间重复绑定同一台物理设备。

运行时仍保持隔离：WireGuard 与 Mihomo/SmartDNS 使用独立容器镜像、数据目录、密钥、配置 revision、实例 ID、命令队列和升级/回滚生命周期。共享的是 Master 控制面与 UI，不是运行进程、配置文件或凭据。

## 从现有 Master 契约确认的兼容事实

当前 `S5M-Master/docs/AGENT_API_CONTRACT.md` 和 `source/internal/app/agent_websocket.go` 的实现提供：

- `POST /api/v1/agent/register`：兼容旧 `machine_code`/`secret` 注册，也支持 `agent_type`/`instance_id` 复合实例注册并签发独立 JWT。
- `GET /api/v1/agent/ws`：Agent 使用 `Authorization: Bearer <JWT>` 建立主动 WebSocket。
- 欢迎消息：`welcome` / protocol 1 / heartbeat interval。
- 心跳按身份类型分派：Mihomo 使用现有 telemetry schema；WireGuard 使用独立的 backend/interface/peer/counter/revision 状态模型。
- 实例型配置、命令队列、ACK 结果和授权按 `(machine_code, agent_type, instance_id)` 隔离；旧版机器级 Agent 仍保留兼容路径。
- 实例型 WebSocket 会话代际、连接替换和心跳顺序均按复合实例身份隔离；同一物理设备可同时保持 Mihomo 和 WireGuard 两条独立连接。

因此，**Master 已能接受 WireGuard 专用心跳和实例配置同步**。WireGuard Agent 不得伪造 Mihomo 状态字段，也不得复用 Mihomo 配置、密钥或命令队列。

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

1. **已完成**：Master 复合实例身份、独立 JWT、WebSocket 会话代际、状态/配置/命令队列隔离和旧 Mihomo Agent 兼容。
2. **已完成**：WireGuard Agent 复合实例注册、WSS typed heartbeat/ACK、按实例请求配置、校验精确 SHA-256 和严格 YAML 后以 0600 原子保存；配置同步不会自动应用隧道。
3. **待开发**：WireGuard typed command dispatcher、执行 journal、deadline/idempotency、配置 apply/stop 的安全 reconcile 与回滚；Master 目前仍拒绝 WireGuard 远程命令。
4. **进行中**：RouterOS HTTPS REST 只读传输层基础；尚未接入 Runtime，也没有开放写操作。完整 RouterOS adapter 需要受控 reconcile、凭据/CA 管理和 host-side 状态标记。
5. **待验收**：Linux/RouterOS 运行时集成、部署升级/回滚，以及 RouterOS 实机测试。

## 当前状态与验收门槛

当前 WireGuard Agent 已实现实例注册、JWT 0600 保存、WSS typed heartbeat/ACK、断线指数退避，以及按实例拉取 desired YAML。配置下发时先验证 Master 提供的精确字节 SHA-256，再验证 `s5m.wireguard/v1alpha1` schema 和本地密钥文件路径，最后原子保存为 0600；私钥/PSK 内容不从 Master 下载，也不会因配置同步自动 apply。Master 的命令队列和 ACK 已按实例隔离，但 WireGuard 命令投递仍被拒绝，因为 Agent typed dispatcher 和 apply/stop 安全 reconcile 尚未完成。RouterOS 当前只有只读 HTTPS REST 传输基础，尚未集成 Runtime 或实机验证。

Master/Agent 的实例隔离、WSS 心跳和配置同步已有 CI 回归；Master 还完成了 500 个并发实例的内存型 WebSocket 命令隔离测试（约 16 秒），但这不等同于 500 台真实设备的持续负载认证，也不覆盖 CPU/RAM、p95/p99、生产 SQLite 锁等待或重连风暴。RouterOS 写操作、实机兼容性和生产部署验收仍未完成。因此不得宣称 WireGuard 已具备完整生产级共用面板控制能力。
