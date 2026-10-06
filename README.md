# 司南 Sinan

自托管的服务器与代理节点控制面板。面板保存期望配置；Agent 主动连接，负责对账、应用恢复、系统遥测和命令执行。代理运行时由独立系统服务管理，Agent 重启时继续提供服务。前端支持简体中文和 English，语言选择会保存在浏览器，管理员也可在「管理与安全」中保存界面语言偏好。

[使用文档](docs/README.md) · [安装部署](docs/deploy.md) · [开发指南](docs/dev.md) · [代码目录](docs/repository.md) · [验证进度](PROGRESS.md) · [平台扩展](docs/operations-expansion.md)

## 快速开始

准备 Docker Engine、Compose 插件与 Python 3，按[部署文档](docs/deploy.md)核对仓库内发布公钥，在仓库根目录安装：

```sh
python3 scripts/panel.py install --public-url https://panel.example.com
```

面板默认在 `http://127.0.0.1:8080`。远端 Agent 接入需要可达的 HTTPS 地址。面板管理工具提供状态、日志、自检和私有备份，升级会先备份，保留凭据与数据卷。

登录后，在「服务器」新增设备并复制一次性安装命令；Shell 入口用于 Linux、macOS、FreeBSD，PowerShell 入口用于 Windows。安装前，维护者需按[制品导入流程](docs/deploy.md#导入签名-release)准备对应架构的已签 Release。入口自动选择最新兼容的已签稳定版本，也可指定版本。

## 功能与使用入口

| 功能 | 说明 | 文档 |
| --- | --- | --- |
| Passkey 登录 | 管理员通行密钥；代理用户独立开通、登录和自身订阅/用量入口 | [Passkey](docs/passkeys.md) |
| 服务器看板 | 独立卡片/表格视图、实时刷新、分层历史、延迟与丢包；可选公开访问，默认需要登录 | [看板](docs/server-display.md) |
| 统计与资产 | 网卡与代理流量趋势、服务器排行、成本到期、续费记录、流量额度与每日汇率缓存；管理统计仅管理员可见 | [统计](docs/statistics.md)、[资产](docs/server-assets.md) |
| Agent 运维 | 系统信息、远程命令执行状态与取消、自动更新；运行时状态、脱敏日志、重启和部署重试 | [运维](docs/agent-runtime-and-chains.md) |
| 监控与通知 | 统一 TCP/ICMP 任务，离线、资源、到期和流量提醒，Telegram/Webhook 独立投递与重试 | [监控](docs/monitoring.md) |
| sing-box 插件 | 节点库、批量整理、外部节点直接授权、策略与套餐、订阅预览/复制/下载；机场订阅与有序混合链路 | [节点库](docs/node-catalog.md)、[协议](docs/proxy-protocols.md)、[套餐](docs/singbox-groups.md)、[链路](docs/agent-runtime-and-chains.md) |
| DDNS 插件 | 复用 Agent 上报的 IP，选择 IPv4、IPv6 或双栈；同步 Cloudflare、腾讯云、阿里云、华为云 A/AAAA 记录 | [DDNS](docs/ddns.md) |
| 阿里云插件 | CDT 用量与账单、ECS/EIP 公网带宽、ECS 启停、阈值与每日计划、抢占式保活、账单和余额缓存 | [阿里云管理](docs/alicloud.md) |
| 诊断插件 | 独立 IP 查询、NodeQuality 和 TCP 连接诊断；任务受设备能力、授权及安全门禁约束 | [插件目录](docs/plugin-catalog.md)、[验收边界](docs/acceptance/ordered-remediation.md) |

服务器看板位于 `/#/dashboard`，旧 `/#/overview` 链接继续可用；后台统计仪表盘位于 `/#/statistics`。侧栏「插件目录」用于查找插件及分发版本，按服务器进入相应管理页。

代理协议包括 VLESS + Reality、Hysteria2、Shadowsocks 2022、TUIC v5、AnyTLS、Naive 和 Snell v6。TLS 支持手动证书及自动申请、续期；节点可配置监听/公开端点、启停与高级参数，订阅链接可重置。通知只负责提醒；阿里云自动控制独立配置，默认关闭。

## 平台扩展

新增日常运维、网络与验机、网络与证书、批量运维与恢复、管理与安全入口；服务器详情进入时保留目标上下文。功能及工具、许可和实机验收条件见[扩展记录](docs/operations-expansion.md)。

## 部署与平台边界

Agent 支持 Linux systemd/OpenRC、macOS launchd、FreeBSD rc.d 和 Windows 计划任务。各平台制品、服务、升级与验收范围见[设备平台与能力](docs/platforms.md)。

Agent 二进制从 GitHub Release 或配置的独立 HTTPS 镜像下载，面板不提供 Agent 二进制。安装和自动更新独立验签，设备只应用内嵌公钥认可的制品；运行时和配置仍经面板分发。单行安装入口校验固定摘要、准备验证工具并核验签名，无需预装 `sinan-bootstrap`；其可信 Linux 执行器保留旧 `agent-v0.3.0` 制品安装兼容，其他平台仍需对应已签制品。

运行时固定上游 sing-box 1.14.2，保留官方默认构建标签并启用统计 API。NodeQuality 完整验机仍暂停新任务，当前限制见[安全门禁](docs/acceptance/nodequality-full-start-gate.md)。

管理员登录支持限速、TOTP 二步验证和 Passkey。Passkey 需要实际使用的 HTTPS 域名，本地开发可用 localhost；代理用户与管理员使用独立会话。删除在线设备时先停服务、清凭据；离线设备仅删除面板记录。生产迁移、发布与实机验收须按各功能文档的边界执行。

## 开发与维护

- 从[代码目录与维护约定](docs/repository.md)了解面板、Agent、插件、前端、脚本和测试的归属。
- 本地构建与检查见[开发指南](docs/dev.md)；签名和公钥轮换见[发布流程](docs/release.md)。
- 接口契约见 [HTTP API](docs/api.md) 与[设备协议](docs/protocol.md)；设计依据见[架构决策索引](docs/adr/README.md)。
- 当前进度见 [PROGRESS](PROGRESS.md)，实机门禁及历史证据见[验收索引](docs/acceptance/README.md)。

GitHub Actions 当前按协作安排暂停，只做本地验证。未运行或取消的 CI 不代表通过，恢复条件见 [AGENTS.md](AGENTS.md#临时-ci-暂停2026-10-01-用户要求)。

许可证：[AGPL-3.0-only](LICENSE)。
