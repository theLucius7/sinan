# 文档导航

先按使用场景选择入口；代码位置见[目录说明](repository.md)，近期实现与验证见 [PROGRESS](../PROGRESS.md)。本文是导航，具体限制和验收结果以对应专题为准。

## 安装与日常管理

| 需要做什么 | 文档 |
| --- | --- |
| 安装面板、备份升级、导入制品、接入 Agent | [部署与节点接入](deploy.md) |
| 确认系统、架构、服务管理与升级能力 | [设备平台与能力](platforms.md) |
| 查看服务器状态、历史曲线及公开看板 | [服务器看板](server-display.md) |
| 查看流量趋势与统计口径 | [统计仪表盘](statistics.md) |
| 配置地区、成本、到期、续费及网卡额度 | [服务器资产](server-assets.md) |
| 配置延迟检测、告警、Telegram 与 Webhook | [延迟检测与通知](monitoring.md) |
| 管理管理员及代理用户的通行密钥 | [Passkey 登录与开通](passkeys.md) |
| 查找插件并选择执行服务器 | [插件目录与执行边界](plugin-catalog.md) |

## 插件与代理业务

| 需要做什么 | 文档 |
| --- | --- |
| 配置代理协议、端点和证书 | [协议与证书](proxy-protocols.md) |
| 配置策略组、套餐、授权和周期 | [sing-box 策略与套餐](singbox-groups.md) |
| 查看运行时、执行/取消命令、导入机场订阅与创建混合链路 | [Agent 运维与混合链路](agent-runtime-and-chains.md) |
| 配置多云 DNS 自动更新 | [DDNS 插件](ddns.md) |
| 管理 CDT、ECS 启停、自动策略、带宽及费用缓存 | [阿里云插件](alicloud.md) |

## 开发与设计

- [仓库目录与维护约定](repository.md)：修改入口、模块归属、脚本及测试的位置。
- [本地开发、构建与检查](dev.md)：Rust、PostgreSQL、Bun 与条件测试。
- [HTTP API](api.md)、[面板与 Agent 协议](protocol.md)、[术语表](glossary.md)：公共契约。
- [架构决策索引](adr/README.md)、[执行中的问题与选择](open-questions.md)：设计依据及范围变更。
- [原始 MVP 任务](requirements.md)、[G1–G9 计划](PLAN.md)：历史基线；后续授权和现行约束以 [AGENTS.md](../AGENTS.md) 及相应 ADR 为准。
- [混合链路设计](node-chain-design.md)、[订阅来源设计](chain-subscription-sources.md)、[订阅实现与参考记录](subscription-source-implementation-notes.md)。
- [节点库与外部订阅](node-catalog.md)：导入预览、标签与排序、来源更新和外部节点授权。
- [服务器展示数据说明](server-display-data.md)：刷新与参考项目的实现差异。

## 发布与验收

- [签名发布与信任根](release.md)：签署、发布身份和公钥轮换。
- [真实 Reality 验收](e2e.md)：专用环境操作及证据要求。
- [验收索引](acceptance/README.md)：按主题定位源码检查、隔离测试与实机证据。
- [整改顺序与验收状态](acceptance/ordered-remediation.md)、[NodeQuality 安全门禁](acceptance/nodequality-full-start-gate.md)：签收与发布前置条件。
- [流量 outbox 有界读取](acceptance-bounded-usage.md)：保留原独立验收入口。

当前 GitHub Actions 暂停；本地测试、历史 CI、源码合入与实机能力签收分别记录，不互相替代。

## 平台扩展

- [全部21类任务与入口](operations-expansion.md)
- [管理与安全](control-center.md)
- [本轮集中验收](acceptance/operations-platform-expansion.md)
