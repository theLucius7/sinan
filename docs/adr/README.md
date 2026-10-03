# 架构决策索引

[文档导航](../README.md) · [目录与维护约定](../repository.md) · [协作约束](../../AGENTS.md)

按主题查找 ADR；编号保留决策顺序，文件名和历史链接保持稳定。早期范围限制可能由后续用户授权覆盖，判断现行约束须结合 AGENTS.md 与对应后续 ADR。例如 Agent 二进制下载以 ADR 0038 为准，替代 ADR 0010 中的面板同源限制；链路能力由 ADR 0040/0045 扩展。设计决策不代表已经通过实机验收。

## 配置、协议与计量基础

- [ADR 0001：声明式全量快照](0001-declarative-snapshots.md)
- [ADR 0002：Agent 三层结构与无状态适配器](0002-agent-layering.md)
- [ADR 0004：单端计量与持久化差值账本](0004-durable-usage-accounting.md)
- [ADR 0005：统计用户名按用户与节点唯一](0005-user-node-stat-name.md)
- [ADR 0007：应用前写入意图日志](0007-intent-journal.md)
- [ADR 0008：串行应用并合并为最新版本](0008-latest-revision-coalescing.md)
- [ADR 0009：统一信封与前向兼容](0009-forward-compatible-envelope.md)
- [ADR 0011：本地 API 仅监听回环地址](0011-loopback-local-api.md)
- [ADR 0012：异步流工具和日志订阅器](0012-async-streams-and-log-subscriber.md)
- [ADR 0014：在构建时生成统计协议消息](0014-protobuf-build-tooling.md)

## 部署、身份、服务与运维

- [ADR 0059：管理员与代理用户 Passkey](0059-passkeys-and-proxy-user-access.md)

- [ADR 0003：运行时使用独立 systemd 服务](0003-independent-runtime-service.md)
- [ADR 0006：特权操作经由统一 trait](0006-privileged-trait.md)
- [ADR 0010：Agent 只从面板下载](0010-panel-only-downloads.md)
- [ADR 0013：在进程内安全解包运行时制品](0013-archive-decoding.md)
- [ADR 0015：扩展 Agent 编译产物的平台](0015-agent-build-platforms.md)
- [ADR 0017：minisign 发布制品、构建时信任根与 Release 导入](0017-signed-release-artifacts.md)
- [ADR 0018：单管理员登录限速与 TOTP](0018-login-security.md)
- [ADR 0019：删除服务器前完成在线退役](0019-server-retirement.md)
- [ADR 0021：增加 OpenRC 独立服务管理](0021-openrc-services.md)
- [ADR 0022：补齐 Agent 监控、任务、升级和多系统部署](0022-agent-capability-alignment.md)
- [ADR 0037：可复制接入入口与按服务器架构导入](0037-bootstrap-and-selective-import.md)
- [ADR 0038：服务器运营设置、看板访问和 GitHub Agent 下载](0038-server-operations-and-public-dashboard.md)
- [ADR 0041：跨平台单行 Agent 接入](0041-cross-platform-enrollment.md)
- [ADR 0075：节点高级参数与后台刷新呈现](0075-node-options-and-background-refresh.md)
- [ADR 0042：节点配置与面板部署管理](0042-node-settings-and-panel-operations.md)
- [ADR 0043：运行时状态、脱敏日志与明确运维操作](0043-runtime-operations.md)
- [ADR 0044：远程命令的持久状态和确认取消](0044-command-lifecycle.md)

## 代理业务、协议与混合链路

- [ADR 0076：节点库、来源预览与外部订阅授权](0076-node-catalog-and-external-access.md)

- [ADR 0020：链式中转的内部凭证、入口计量与依赖发布](0020-chained-transit.md)
- [ADR 0023：服务器核心与 sing-box 代理业务分层](0023-proxy-business-boundary.md)
- [ADR 0030：sing-box 业务搬迁与服务器启用证据](0030-singbox-plugin-business.md)
- [ADR 0034：现代代理协议与托管证书](0034-modern-protocols-and-certificates.md)
- [ADR 0035：sing-box 策略组、套餐快照与受控两跳链路](0035-singbox-policy-package-groups.md)
- [ADR 0040：有序混合链路与机场订阅来源](0040-mixed-chains-and-subscriptions.md)
- [ADR 0045：混合链路的执行与验证](0045-mixed-path-execution.md)
- [ADR 0054：链路写入时复核资源快照与原选择](0054-chain-resource-snapshot-writes.md)
- [ADR 0077：代理流量按天汇总与数据保留](0077-usage-daily-rollup-and-retention.md)
- [ADR 0078：管理界面重排、节点页分区与离线时间](0078-admin-layout-and-node-sections.md)
- [ADR 0079：重新架构：插件边界、订阅来源与链路模型（提议）](0079-rearchitecture-plugins-sources-chains.md)

## 诊断、IP 查询与执行保护

- [ADR 0016：IP 质量与节点诊断外插](0016-nodequality-diagnostics.md)
- [ADR 0024：IP 查询错误的类型与来源](0024-ip-provider-error-classification.md)
- [ADR 0025：按 IP 与入口保留逐数据库成功快照](0025-ip-provider-cache.md)
- [ADR 0026：诊断取消由设备确认清理](0026-confirmed-diagnostic-cancellation.md)
- [ADR 0027：IP 查询入口适配与正式凭据](0027-ip-provider-adapters.md)
- [ADR 0028：共用诊断任务服务](0028-shared-diagnostic-job-service.md)
- [ADR 0029：TcpQuality 许可核对与原生 Rust 路径](0029-tcpquality-license-and-native-probes.md)
- [ADR 0031：暂缓 NodeQuality 不受控完整任务的新执行](0031-nodequality-full-start-gate.md)
- [ADR 0032：原生 TCP 工具的固定源码与完整签名制品](0032-native-tcp-artifacts.md)
- [ADR 0033：TCP 诊断登记与配置目标快照](0033-tcpquality-panel-registration.md)
- [ADR 0046：有授权范围的轻量三网周期监控](0046-authorized-periodic-network-monitoring.md)
- [ADR 0049：NodeQuality 的离线 Debian 12 rootfs 准备链](0049-nodequality-offline-rootfs.md)
- [ADR 0050：使用节点私有凭证的正式 IP 查询](0050-official-node-ip-query.md)
- [ADR 0051：带目标授权的轻量三网周期监控](0051-authorized-carrier-monitoring.md)
- [ADR 0052：诊断终态以停止和清理证明为准](0052-confirmed-diagnostic-completion.md)
- [ADR 0053：周期拨测使用可撤销的短期执行许可](0053-authorized-probe-leases.md)
- [ADR 0055：诊断材料收集的下载失败证据与工厂容量](0055-diagnostic-material-download-evidence.md)

## 资产、监控与通知

- [ADR 0036：服务器资产配置与账单周期网卡用量](0036-server-assets-and-traffic.md)
- [ADR 0039：统一延迟任务与完整服务器通知](0039-latency-tasks-and-notification-rules.md)
- [ADR 0047：实时监控、历史粒度、每日汇率与多渠道通知](0047-monitoring-refresh-history-and-channels.md)

## DDNS 与云资源插件

- [ADR 0060：DDNS 双栈配置入口](0060-ddns-dual-stack-creation.md)

- [ADR 0048：使用 Agent 已上报地址的 Cloudflare DDNS](0048-cloudflare-ddns.md)
- [ADR 0056：多云 DDNS 插件](0056-multicloud-ddns.md)
- [ADR 0057：阿里云 CDT 与公网带宽管理](0057-alicloud-cdt-management.md)
- [ADR 0058：阿里云 ECS 启停、自动策略与费用缓存](0058-alicloud-power-and-billing-cache.md)

## PR151 追加决策及来源

以下来自作者独立实现，按主线追加编号；本聊天整合验证另记。

- [ADR 0059：singbox-plugin-lifecycle](0061-singbox-plugin-lifecycle.md)
- [ADR 0060：nodequality-artifact-lineages](0062-nodequality-artifact-lineages.md)
- [ADR 0061：nodequality-input-collection](0063-nodequality-input-collection.md)
- [ADR 0062：runtime-checkpoints-and-recovery-barriers](0064-runtime-checkpoints-and-recovery-barriers.md)
- [ADR 0063：nodequality-factory-capacity](0065-nodequality-factory-capacity.md)
- [ADR 0064：confirmed-diagnostic-completion](0066-confirmed-diagnostic-completion.md)
- [ADR 0065：authorized-probe-leases](0067-authorized-probe-leases.md)
- [ADR 0066：independent-node-ipquality](0068-independent-node-ipquality.md)
- [ADR 0067：ipquality-derived-debian-inputs](0069-ipquality-derived-debian-inputs.md)
- [ADR 0068：ipquality-minimal-profile-chain](0070-ipquality-minimal-profile-chain.md)
- [ADR 0069：proxy-resource-batch-lifecycle](0071-proxy-resource-batch-lifecycle.md)
- [ADR 0070：subscription-source-lifecycle](0072-subscription-source-lifecycle.md)
- [ADR 0071：ordered-path-publication-and-native-probe](0073-ordered-path-publication-and-native-probe.md)
- [ADR 0072：private-panel-certificate-authorities](0074-private-panel-certificate-authorities.md)
