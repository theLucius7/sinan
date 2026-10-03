# 平台扩展分块交付

本轮按用户清单21类实施，复用现有 Agent、插件及诊断任务，整体集成分支交付。实现阶段不运行验证、测试或构建；完成所有模块后集中验收，再修复受影响范围。源码、签名工具供应、许可、实机签收和正式部署分别记录。

| 清单 | 入口与实现记录 |
| --- | --- |
| 1–3 服务器接入、监控与日常操作 | [日常运维](fleet-operations.md)，`/#/fleet`；服务器详情的日常运维保留上下文 |
| 4–9 网络、路径、吞吐、硬件、IP 与综合报告 | [网络与验机](network-workbench.md)，`/#/network-workbench`，复用共用诊断生命周期 |
| 10–13 DNS、证书、NAT、私有组网与调优 | [网络与证书](network-configuration.md)、[DDNS](ddns.md)，`/#/network-configuration` |
| 14–15 sing-box 运维与代理用户业务 | [代理业务流程](singbox-operations-workflows.md)，现有节点、运行时和代理用户入口 |
| 16–19 批量任务、故障事件、备份恢复与云费用 | [批量运维与恢复](operations-recovery.md)，`/#/operations` |
| 20–21 权限安全、工作区效率与开放接口 | [管理与安全](control-center.md)，`/#/system/control-center` |

NodeQuality 完整验机仍按[原门禁](acceptance/nodequality-full-start-gate.md)拒绝新执行，工作台不能绕过。Geekbench 和 Speedtest 按许可及可证明预算处理执行或外部原始结果导入；缺少有效工具、未知结果、过期采样及未回收资源分别展示。真实云资源变更、DNS 写入、外部证书签发、服务部署及高负载实机测试未在开发阶段执行。

集中实现和失败修复已完成；本轮Rust按目标与失败方法替换后1216通过、0失败、25条件忽略，前端173通过，实际浏览器16个不同场景通过；最终源码面板内嵌35文件匹配，真实定时/单作业去重备份与57迁移隔离恢复通过。源码身份、实际结果及条件未执行项见[集中验收](acceptance/operations-platform-expansion.md)，不复用历史PR数字。
