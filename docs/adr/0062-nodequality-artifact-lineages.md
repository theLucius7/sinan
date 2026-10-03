# ADR 0062：NodeQuality 整合的制品身份与未授权查询

> 主线整合编号 0062；作者原独立分支编号 0045。旧主线同号决策及链接保留，历史验收仅认证原冻结输入。

## 决策

主线普通单文件r18与本分支de54084的离线双辅助文件r18是不同制品；数值r14–r17的策略链在两侧也有不同字节。保留历史提交、报告与收据，不以同名版本推断来源一致，不重签旧身份下的新内容。

本分支最初原生策略身份为 `a92fca6c0067df29ddd03fdc2fee6f3000f64545-sinan-native-r1`，包含更严格的原生curl、逐源错误、有界YouTube和Netflix链，以及明确停止未授权OpenAI请求的新增层。主线当前默认身份为 r22；显式原生策略构建在2026-10-03章节目录保护和上传边界补修后使用独立 `sinan-native-r2`，不把新字节重标为 native-r1。

显式离线准备 `a92fca6c0067df29ddd03fdc2fee6f3000f64545-offline-rootfs-r1` 仍只从精确历史 native-r1 包装器受控派生，并要求已签 `rootfs.tar.gz` 与 `rootfs-manifest.json`。`historical-native-r1` 保存必要的原 runner/report，`historical-r19` 保存既有共享 rootfs 原字节；历史读取严格校验固定摘要，不随当前 helper 修改而改变旧签名身份。辅助文件的来源、摘要、字节和数量在Release与Agent分别核验。

旧r2–r18可回收已有报告，r4–r18保留日常模式；普通旧版本不接收离线辅助文件。本分支旧离线r18仅有准备夹具证据，没有正式发布/部署记录，不作为当前运行版本。旧已签制品按其实际证明和字节单独保留；新包不能借用旧版本名或旧收据。

## OpenAI 与查询边界

之前固定r17的OpenAITest仍带上游公共cookie，其他访问层没有覆盖此函数。新层只替换精确固定IP输出中的该函数，并补齐JSON的 `Sources.OpenAI`、`Media.ChatGPT`；不复制凭证、不发请求、不改变匿名YouTube探测或其他源的既有结果。

未配置独立正式授权源时，结果为未知、`credential_not_configured`/`not_attempted`，`Attempted=false`、`Attempts=[]`、真实尝试时间与耗时为null。检查时间不能冒充请求时间。保留成功缓存与来源字段；未知不能显示为成功或零分。正式来源如另行配置，应使用既有面板provider适配器，不将秘密放入脚本参数或报告。

包装器版本变更同样绑定report.py的章节校验与独立错误隔离修订。测试及最终摘要只认证冻结的当前组合；不更改原canonical源码锁或许可证，不宣称此前所有provider路径都已修复。

## 验收边界

2026-10-03完整编辑冻结后，固定源策略与历史实际派生的111个定点方法已有实际通过证据，其中历史派生29项、原/native报告接线4项及native真实签名1项均不重复累计。该范围与首轮29套的框架计数分别记录，详见[r22分项记录](../acceptance/nodequality-r22-upload-and-history.md)；其他整合范围由[本轮统一验收](../acceptance/all-open-issues-20261003.md)记录。没有Geekbench Pro许可、真实离线工具链、双架构rootfs复建或Agent/代理完整联合负载，完整验机保持封闭。CI仍暂停，不自动正式签署、发布或部署。
