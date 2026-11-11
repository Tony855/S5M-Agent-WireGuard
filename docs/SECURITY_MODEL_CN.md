# 安全模型与威胁边界

## 资产

- WireGuard private key、peer PSK、Agent token、RouterOS API 凭据。
- WireGuard interface、peer、AllowedIPs、路由和防火墙相关状态。
- Master WebSocket 会话、命令队列、配置 revision 和设备身份。

## 强制约束

1. 配置只允许引用 data directory 内的密钥文件；拒绝绝对路径、路径穿越和逃逸到数据目录外的符号链接。
2. 密钥文件创建时使用 0600，父目录使用 0700；读取时校验普通文件类型和权限，发现权限过宽则拒绝读取。
3. 日志字段采用 allowlist；禁止 dump YAML、环境变量、RouterOS API 原始响应和完整命令参数。
4. Agent token 与 RouterOS API 密码不得作为命令行参数；使用受限权限文件或 secret provider。
5. 所有 API 操作使用 TLS；RouterOS API TLS 必须验证证书，禁止默认跳过证书验证。
6. 不接受任意 shell、脚本、RouterOS CLI 或用户提供的二进制命令。
7. 所有控制命令必须绑定 instance ID、command ID、deadline、期望配置 revision；重复请求返回已存结果，不重复执行。
8. 路由变更必须先检查管理路径和 AllowedIPs 冲突；未经显式批准不得安装默认路由。
9. 配置应用采用 prepare -> apply -> verify -> commit；失败恢复前一份配置与运行态。
10. 遥测不包含 private key、PSK、Token、RouterOS 凭据或完整配置内容。

## 当前实现与待实现

当前已实现严格 YAML 字段解析、密钥路径词法/符号链接边界、Key 格式、重复 Peer key、AllowedIPs 重叠校验，以及私钥文件生成/读取（0600/0700、拒绝覆盖、拒绝路径逃逸、拒绝权限过宽）。密钥轮换、命令授权/审计、路由保护和运行时回滚仍属于后续开发任务，不能视为已完成。


## Linux Runtime 密钥处理补充

- 生成的 `wg setconf` 临时文件权限为 0600；完成后先尽力覆盖为零，再删除。闪存、写时复制文件系统和快照可能保留旧块，因此这不是安全擦除保证。
- 配置文本在写入临时文件后，对可控的内存缓冲区执行清零；Go 运行时及编译器仍可能存在不可控副本，不能承诺绝对内存擦除。
- 外部命令的 stderr 不进入应用日志或 RPC 错误，避免 `wg` 在配置错误时回显包含私钥的配置行。
- Peer 遥测通过 `wg show` 的独立字段读取，不调用会包含接口私钥的 `wg show dump`；只返回公钥、Endpoint、AllowedIPs、握手时间、流量计数和 Keepalive，不读取或返回私钥/PSK。

- Agent 在 `dataDir/runtime/<interface>.managed` 写入 0600 所有权标记；状态读取和停止操作必须先验证标记，避免管理主机上其他 WireGuard 接口。
- Linux Apply 在接口创建后失败时，会使用独立且最长 5 秒的清理上下文删除本次创建的接口；不会继承已取消/超时的命令上下文，也不会启动无期限后台清理。该回滚目前只覆盖本次新建接口，不代表已支持更新既有接口的快照恢复。
- Linux `stop` 在删除接口前还必须由 `wg show` 确认该接口确实是 WireGuard，避免误删 `eth0` 等普通网卡；状态采集也不会把普通网卡误报为 WireGuard 正常运行。
- 重复 `stop` 仅在 `wg show interfaces` 成功确认目标接口已不存在时返回成功；若接口仍存在但缺少 Agent 所有权标记，或无法读取 WireGuard 接口清单，则拒绝操作。
