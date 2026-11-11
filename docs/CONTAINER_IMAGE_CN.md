# WireGuard Agent 多架构容器镜像

## 镜像构建

仓库 CI 为每次 Pull Request 构建并 Smoke Test：

- `linux/amd64`
- `linux/arm64`

Pull Request 验证不会推送镜像。合并到 `main` 或推送 `v*` tag 后，发布工作流才会推送 GHCR：

- `ghcr.io/tony855/s5m-agent-wireguard:latest`
- `ghcr.io/tony855/s5m-agent-wireguard:<commit-sha>`

## Linux kernel backend 运行要求

本镜像当前只包含 Linux kernel WireGuard Runtime 所需的 `iproute2` 和 `wireguard-tools`。容器必须使用宿主机内核；容器镜像不会在内部加载宿主机内核模块。

Docker 示例：

```sh
docker run -d \
  --name s5m-agent-wireguard \
  --restart unless-stopped \
  --cap-add NET_ADMIN \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -v /opt/s5m-agent-wireguard/data:/data \
  -p 51820:51820/udp \
  ghcr.io/tony855/s5m-agent-wireguard:latest
```

- `/data/agent.yaml`、`/data/config.yaml` 和密钥目录必须持久化。
- `agent.yaml` 应为 0600；数据目录和密钥目录应限制为 0700。
- 不要使用 `--privileged` 或 `--network host` 作为默认部署方式。
- 是否需要额外的模块加载能力取决于宿主机内核；应在宿主机预先确认 WireGuard 内核支持。
- UDP 51820 仅在此节点承担 WireGuard Server 且配置对应监听端口时开放。客户端无需发布该端口。
- 当前镜像不包含 RouterOS API Adapter。RouterOS 原生 WireGuard 不能通过该 Linux kernel 容器镜像冒充支持；RouterOS 适配必须单独实现并在真实设备验收。

## 验收边界

镜像 CI 的多架构构建和 `wg-agent version` Smoke Test 仅证明二进制可在对应架构容器启动，不代表：

- 宿主机具备 WireGuard kernel module / generic-netlink 能力；
- 容器已获得正确网络权限或路由策略；
- RouterOS Container 已兼容；
- WSS 注册、心跳和远程命令已完成端到端验收。

远程配置同步和命令 Dispatcher 尚未实现；当前 Agent 仍是状态上报阶段。不要把该镜像当作已完成主控远程管理的生产版本。
