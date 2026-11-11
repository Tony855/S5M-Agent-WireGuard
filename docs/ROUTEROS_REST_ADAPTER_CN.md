# RouterOS 原生 WireGuard REST Adapter 阶段说明

## 本阶段实现范围

本分支新增 `internal/runtime/routeros` 的只读 REST 传输层，目标 RouterOS 为启用 HTTPS REST 服务的 RouterOS v7。

当前固定只读资源：
- `/rest/system/resource`
- `/rest/interface/wireguard`
- `/rest/interface/wireguard/peers`
- `/rest/ip/address`

安全边界：
- 只接受 HTTPS endpoint；拒绝 HTTP、URL userinfo、query、fragment 和非 `/rest` 路径。
- 使用 HTTP Basic Auth，但禁止跟随重定向，避免把凭据转发到其他主机。
- 强制 TLS 1.2 或更高版本，拒绝 `InsecureSkipVerify`、自定义 TLS 拨号器和无法检查 TLS 配置的非标准 RoundTripper；允许通过标准 Transport 配置受信任 CA。
- 响应体上限 1 MiB；错误只报告 HTTP 状态，不回显 RouterOS 响应体。
- 资源路径为固定 allowlist；本阶段没有 POST、PATCH、PUT、DELETE 或任意 CLI 能力。
- 不把 RouterOS 用户名/密码放入 WireGuard telemetry、日志或 Master 配置。
- 测试使用 TLS httptest server，覆盖鉴权、路径约束、重定向、错误脱敏和响应大小限制。

## 还没有完成的部分

这不是完整 RouterOS Runtime，也不能作为生产可用的 RouterOS WireGuard 控制器。尚未实现：
- 安全凭据文件/证书 CA 管理和 `agent-run` 装配。
- Runtime Probe/Status 接入当前 `Runtime` 接口。
- Interface、Peer、Address、Route 的受控创建/更新/删除。
- 资源所有权标记、desired/applied revision、幂等重试和失败回滚。
- RouterOS 7.x 版本差异检测与真实设备验收。

写操作必须在后续批次加入事务式 reconcile 和回滚保护；不能通过开放通用 REST 路径或 RouterOS CLI 来实现。
