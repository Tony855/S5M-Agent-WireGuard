# S5M-Agent-WireGuard

独立的 S5M WireGuard Agent 项目。该仓库与 [S5M-Agent-SmartDNS](https://github.com/Tony855/S5M-Agent-SmartDNS) 分开开发、构建、发布和回滚；不会把 WireGuard 功能塞进 Mihomo + Agent 镜像。

## 项目目标

- 独立 WireGuard + Agent OCI 镜像，独立数据目录、配置版本、实例身份和升级生命周期。
- 支持 WireGuard Client 与 Server 两种角色。
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

## 当前开发状态

<badge>Foundation / in progress</badge>

- [x] 独立仓库和 Runtime 分层契约。
- [x] 严格版本化 YAML 配置模型、Peer/AllowedIPs 校验。
- [x] 私钥文件生成和读取（0600/0700、路径边界检查、拒绝覆盖）。
- [x] Go 单元测试、race test、vet、gofmt CI。
- [x] Linux kernel WireGuard 首次创建流程、Peer/地址配置、状态探测、停止和新接口失败清理（不支持原地更新；默认路由拒绝）。
- [ ] Agent WebSocket 注册、状态、配置同步和命令 ACK。
- [ ] RouterOS 原生 WireGuard API Adapter。
- [ ] RouterOS Container 实机兼容性与多架构镜像。
- [ ] 发布、升级和回滚流程。

当前 CLI 基础命令：

```sh
wg-agent version
wg-agent keygen --data-dir /data --output secrets/server.key
wg-agent config-validate --config /data/config.yaml
wg-agent apply --data-dir /data --config /data/config.yaml
wg-agent status --data-dir /data --interface wg0
wg-agent stop --data-dir /data --interface wg0
```

密钥命令只写入文件，不打印私钥。示例配置仅用于说明格式，不代表可直接部署。

## 安全原则

- 禁止远程执行任意 shell、RouterOS CLI 或用户拼接命令。
- RouterOS API 只暴露受控操作集合；凭据加密存储、最小权限、可轮换。
- 默认不创建 `0.0.0.0/0` 或 `::/0` 路由；保留 Agent 到主控端管理路径。
- Peer AllowedIPs 冲突、路由覆盖、端点不可达、配置语法错误必须在应用前拒绝。
- 私钥、预共享密钥、Token 和完整 WireGuard 配置不得进入日志或 telemetry。
- 破坏性变更前保存状态快照；失败时恢复到上一个已知健康配置。

所有后端能力必须由自动化测试和真实设备验收逐项证明。CI 成功不等于 RouterOS 硬件兼容验收。
