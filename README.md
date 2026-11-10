# S5M-Agent-WireGuard

独立的 S5M WireGuard Agent 项目。该仓库与 [S5M-Agent-SmartDNS](https://github.com/Tony855/S5M-Agent-SmartDNS) 分开开发、构建、发布和回滚；不会把 WireGuard 功能塞进 Mihomo + Agent 镜像。

## 项目目标

- 独立 WireGuard + Agent OCI 镜像，独立数据目录、配置版本、实例身份和升级生命周期。
- 支持 WireGuard Client 与 Server 两种角色；同一实例可按明确配置启用一种角色，避免隐式混合路由。
- Linux Docker：优先使用 Linux kernel WireGuard；在明确允许且有 TUN 能力时评估 userspace backend。
- MikroTik RouterOS Container：Agent 作为容器控制平面；WireGuard 数据平面优先通过受限 RouterOS API 管理 RouterOS 原生 WireGuard interface。容器内 wireguard-go + `/dev/net/tun` 是独立实验后端，不宣称所有 RouterOS 设备都支持。
- WebSocket 是 Agent 与 S5M Master 的主要控制通道：状态、配置、命令、结果和 ACK。HTTP 仅用于初始注册、基础健康与必要回退。
- 密钥只在需要的端点生成/持有；私钥不进入日志、状态上报、普通 API 响应或主控明文数据库。
- 所有网络变更可审计、幂等、具备超时和回滚策略；默认不接管系统默认路由。

## 镜像边界

| 镜像 | 运行核心 | 配置/状态 | 生命周期 |
|---|---|---|---|
| Mihomo + Agent | Mihomo（可选 SmartDNS） | 现有 S5M-Agent-SmartDNS 数据目录 | 独立 |
| WireGuard + Agent | WireGuard runtime + S5M Agent | 本仓库独立数据目录 | 独立 |

两个镜像不共享容器、不共享配置文件、不共享密钥、不互相升级或重启。它们可以注册到同一个 S5M Master，但必须使用独立的 Agent instance identity / token / command queue。

## 开发阶段

1. **基础契约与安全边界**：配置模型、密钥脱敏、运行时接口、命令幂等与审计。
2. **Linux Docker MVP**：kernel WireGuard Client/Server、Peer 生命周期、健康检查、配置原子应用与回滚。
3. **S5M 控制面接入**：注册、WebSocket、心跳、配置 SHA、命令 ACK、断线恢复。
4. **RouterOS 原生 WireGuard Adapter**：最小权限 API、接口/Peer/地址/路由管理、回滚与设备能力探测。
5. **RouterOS Container 验证**：VETH、持久化挂载、架构、资源与实际数据面测试。
6. **多架构 CI 与发布**：amd64、arm64 优先；armv7/arm32v5 单独验证，不以交叉编译成功代替设备验收。

## 安全原则

- 禁止远程执行任意 shell、RouterOS CLI 或用户拼接命令。
- RouterOS API 只暴露受控操作集合；凭据加密存储、最小权限、可轮换。
- 默认不创建 `0.0.0.0/0` 或 `::/0` 路由；保留 Agent 到主控的管理路径。
- Peer AllowedIPs 冲突、路由覆盖、端点不可达、配置语法错误必须在应用前拒绝。
- 私钥、预共享密钥、Token 和完整 WireGuard 配置不得进入日志或 telemetry。
- 破坏性变更前保存状态快照；失败时恢复到上一个已知健康配置。

## 当前状态

仓库刚初始化。当前不代表已经具备可运行镜像或 RouterOS 兼容性。所有运行时能力必须由自动化测试和真实设备验收逐项证明。
