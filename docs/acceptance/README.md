# 验收记录索引

- [2026-10-03 全部开放 issues 集成交付](all-open-issues-20261003.md)

- [PR155 节点目录、来源与外部授权整合：本聊天本地证据](pr155-root-integration-20261003.md)

[文档导航](../README.md) · [执行进度](../../PROGRESS.md) · [整改顺序与当前门禁](ordered-remediation.md)

本目录保留每次检查对应的源码、运行条件与未验证范围。源码审查、本地隔离测试、历史 CI 和实机签收分别成立；文件名含“验收”不表示所有场景已通过。当前 CI 暂停，NodeQuality 完整执行及后续诊断能力仍按整改顺序签收。查当前状态先读上面的门禁和 PROGRESS，再查具体记录。

## 入口、整合与待验条件

- [2026-10-03 全仓缺陷扫描与修复（按严重程度清单）](defect-scan-20261003.md)
- [2026-10-03 代理流量按天汇总与数据保留（D5–D7）](usage-rollup-retention.md)
- [2026-10-03 管理界面重排与 D12–D16](ui-relayout-20261003.md)

- [已完成测试材料清理与最新制品保留](test-material-cleanup.md)

- [NeXus 精确容器上下文与交付收尾](nexus-app-context.md)

- [NodeFlare 看板重新对齐与后台汇率](dashboard-nodeflare-refresh.md)

- [管理员/代理用户 Passkey 与 DDNS 双栈本地验证](passkeys-and-ddns.md)

- [第二批五项问题源码整改（2026-10-01）](issues-batch-2.md)
- [第五批：服务器资产、NIC、拨测、套餐及显式安装](issues-batch-five.md)
- [开放 issue 第一批：#3、#4、#6、#14、#15](issues-batch-one.md)
- [第六批：公共访问材料与授权草稿](issues-batch-six.md)
- [第三批：独立 IP、共用诊断、响应确认与原生 TCP](issues-batch-three.md)
- [开放 issues 分批整合与最终验证](issues-batches-validation.md)
- [开放问题统一修复与验收边界](issues-integration-20261001.md)
- [2026-10-02：当前剩余 issues 组合验收](open-issues-20261002.md)
- [整改顺序与验收状态](ordered-remediation.md)
- [PR #138：监控、通知与 Cloudflare DDNS 整合验收](pr138-monitoring-ddns-validation.md)
- [PR #140 最新主线整合与统一验证](pr140-current-main-validation.md)
- [PR #145：最终整合验收](pr145-integration-20261002.md)
- [PR #148 多云功能与保护补修整合](pr148-cloud-guards-integration.md)
- [PR #151 主线兼容整合与集中本地验证](pr151-main-compatibility.md)
- [剩余 issue 集成验收（2026-10-02）](remaining-issues-20261002.md)
- [剩余安装、Reality 与 TCP 验收准备](remaining-native-validation-preparation.md)

## 服务器、遥测与通知

- [#63 轻量三网周期监控验收](carrier-monitoring.md)
- [每日汇率来源与整合边界](exchange-rate-integration.md)
- [通知渠道与告警对齐验收](notification-alignment.md)
- [常驻服务优先级独立验收](resident-service-priority.md)
- [独立服务器看板验收](server-dashboard.md)
- [遥测实时读取与分层历史：实现和本地验证](telemetry-history.md)
- [心跳与遥测隔离的独立验收](telemetry-isolation.md)

## 代理业务、链路与运行时

- [节点库与外部授权本地验证](node-catalog-20261003.md)

- [混合链路本地隔离夹具记录](mixed-path-local-fixtures.md)
- [混合链路面板与发布状态验证](mixed-path-panel.md)
- [核心与代理业务边界：独立验收](proxy-business-boundary.md)
- [Reality 传输失败证据：独立验收](reality-failure-evidence.md)
- [运行时运维独立验收](runtime-operations.md)
- [通用运行时验证与恢复下界验收](runtime-validations.md)
- [sing-box 策略组与套餐组本地验收](singbox-groups.md)
- [sing-box 业务搬迁独立验收（Issue #26）](singbox-plugin-business.md)
- [订阅 HTTP/H2 转换与解析器升级](subscription-transport-conversion.md)

## IP 查询

- [IP 查询入口适配独立验收](ip-provider-adapters.md)
- [IP 查询成功缓存独立验收](ip-provider-cache.md)
- [IP 查询错误分类独立验收](ip-provider-errors.md)
- [IP 未知字段独立验收](ip-quality-unknown.md)
- [IP 查询显式错误响应确认独立验收](ip-response-confirmation.md)
- [节点正式 IP 接口与凭据边界（#24、#122）](node-official-ip-providers.md)
- [服务器 IP 信息与 NodeQuality 视图拆分验收](server-ip-view.md)

## 诊断执行、NodeQuality 与资源保护

- [专用 Debian 12 测试节点：准备与独立验收](dedicated-debian12-node.md)
- [诊断整改基线与独立验收](diagnostic-baseline.md)
- [确认式取消独立验收（Issue #19）](diagnostic-cancellation.md)
- [诊断材料下载失败证据验收](diagnostic-material-download-evidence.md)
- [日常检查与完整验机独立验收（Issue #21）](diagnostic-modes.md)
- [诊断启动预检与运行中内存保护独立验收](diagnostic-preflight.md)
- [诊断章节与执行状态独立保存](diagnostic-report-sections.md)
- [诊断资源预算独立验收](diagnostic-resource-budget.md)
- [诊断单元 swap 系统调用保护](diagnostic-swap-syscalls.md)
- [NodeQuality 制品自身的完整执行准入](nodequality-artifact-execution-admission.md)
- [NodeQuality 第四批源码修复与未完成条件](nodequality-batch4-readiness.md)
- [NodeQuality 实际执行依赖审计（Issue #28）](nodequality-chain-audit.md)
- [NodeQuality 完整任务安全门禁独立验收](nodequality-full-start-gate.md)
- [NodeQuality r13 未知 IP 评分独立验收](nodequality-ip-score-unknown.md)
- [NodeQuality r14 Netflix 请求与页面判定修复](nodequality-netflix-http.md)
- [NodeQuality r9 禁止运行时安装依赖](nodequality-no-runtime-install.md)
- [NodeQuality r8 禁止脚本修改 swap](nodequality-no-swap.md)
- [离线 NodeQuality 工具链准备与当前验收边界](nodequality-offline-rootfs.md)
- [完整 NodeQuality：小内存节点 OOM 基线](nodequality-oom-baseline.md)
- [NodeQuality r10 七份静态数据独立验收](nodequality-pinned-data.md)
- [NodeQuality 首层脚本固定来源独立验收（关联 #28）](nodequality-pinned-first-level-sources.md)
- [NodeQuality 公共认证材料访问边界](nodequality-public-access-policy.md)
- [NodeQuality r7 三处公开报告 POST 策略验收](nodequality-public-report-policy.md)
- [NodeQuality r12 硬件百分位上传独立验收](nodequality-ranking-upload.md)
- [NodeQuality ARM rootfs 静态盘点独立验收](nodequality-rootfs-arm-inventory.md)
- [NodeQuality amd64 rootfs 静态盘点独立验收](nodequality-rootfs-inventory.md)
- [NodeQuality r11 脚本供给失败独立验收](nodequality-source-failure.md)
- [专用 Debian 12 虚拟机与有限 P0 验收](p0-dedicated-vm.md)
- [P0 有限联合负载验收](p0-joint-load.md)
- [真实注册 Agent 的日常诊断故障矩阵](registered-nodequality-daily.md)
- [共用诊断任务服务验收](shared-diagnostic-service.md)

- [作者原生制品交接及提交收尾](native-artifact-handoff.md)
- [托管验收工具与主线 API 合同](managed-tool-api-compatibility.md)
- [当前 Linux 节点与构建环境](current-linux-readiness.md)
- [安装前的端点与原生工具预检](installation-readiness.md)
- [NeXus 当前连接上下文补验](nexus-context-recovery.md)

## 原生 TCP 与制品发布

- [原生 TCP 固定源码与签名制品：独立验收](native-tcp-artifacts.md)
- [原生 TCP 工具独立验收](native-tcp-probe.md)
- [Release 发布身份保留验收](release-publication-identity.md)
- [原生 TCP 无状态适配器独立验收](tcpquality-adapter.md)
- [TcpQuality 许可独立验收](tcpquality-license.md)
- [TCP 诊断面板登记独立验收](tcpquality-panel-registration.md)
- [TCP 报告界面独立验收](tcpquality-report-view.md)

## DDNS

- [Cloudflare DDNS 插件主线整合与验证边界](cloudflare-ddns-integration.md)

## 结构化证据

[evidence/](evidence/) 保存对应记录引用的 JSON 证据；以各记录说明的提交、范围和时间为准，不把旧记录自动视为当前代码的验证。另有保留原路径的[流量 outbox 有界读取验收](../acceptance-bounded-usage.md)。
