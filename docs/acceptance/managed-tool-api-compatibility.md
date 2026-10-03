# 托管验收工具与主线 API 合同

关联 [Issue #156](https://github.com/theLucius7/sinan/issues/156)，基线为已合并主线 `b9a9c725fdb92dd19e836a63820463dd1b176891`。本步骤修复验收工具的实际请求；面板旧 API、数据库及代理用户授权模型保持其当前合同。

原工具在来源创建／刷新、job 轮询、链路创建／重放、版本应用及退役时，仍请求保留的旧路径。当前有序合同分别位于 `/api/plugins/sing-box/ordered-subscription-sources`、`ordered-subscription-source-jobs`、`ordered-proxy-resources` 和 `chains/ordered-batch`。工具使用明确的四个路由常量，来源和链路资源 ID 仍是数值；请求、外部节点、节点版本、来源 revision 和 job 仍使用各自 UUID，策略组继续使用数值 `chain_ids`。

新增合同场景实际调用 driver 的创建与原子重放、inline 刷新与 job 轮询、follow／pinned 版本应用及失败来源、退役与删除后重放。测试使用明确的 TEST_ONLY 响应，不向数据库写设备回执。工具中的原生路径证明不创建周期拨测 `ProbeSpec` 或执行租约；当前已有周期拨测工具保留自身来源、地区和许可合同。

实现、合同测试代码及文档全部完成后冻结 11 份输入，冻结收据 SHA256 `f9dbde316ee4a72abdc4260306e917ba4bcbc61021f3602b3e18bfdf77c4a872`。三个控制程序只编译语法成功，冻结输入在集中执行后逐字及稳定身份保持。最初冻结工具将读取会改变的 atime 纳入相等判断，执行前触发 AssertionError；修正为设备、inode、大小、mtime、ctime、mode、uid，保留原失败记录，没有据此声称源码曾改变。

驱动合同首次 23 项执行：22 通过，新增 setup 夹具遗漏服务器响应的数值 `id` 导致 1 错误。原失败日志 SHA256 `6fceeffcae8b299f5588db05f43d29a55fa47a21ef85c72a5caf7762ff0aed08` 保留；只补齐夹具 `id`，其它 10 份冻结输入保持，重新冻结受影响输入后仅补验失败项，通过日志 SHA256 `c346f1228fe88f4ab3cb336ffa610dc3a34ec7c7bb7d05df7a1c222f2d928881`。最终有效去重 23 项通过、0 跳过；未重复 Rust、前端及不受影响工具验收。

单次只读 SSH 仅到已有跳板，继承有效的正常 agent、保存私有原始 stderr 并绑定 config／key／socket。实际连接成功，退出码 0，耗时 2.461 秒，stderr 0 字节，绑定保持且自有进程组收尾确认；收据 SHA256 `90a541b3543d41d1ef46a4cec70e2d748d356c6ba5edac955326a1ecc4dc4e5c`，840 字节。没有改远端、连接测试节点或安装服务，因此原测试节点失败原因仍未知。

测试节点连通、当前原生制品、真实注册 Agent 故障矩阵、三设备整链、完整 NodeQuality 许可／工厂及实机验收分别待验，合同回归与跳板成功不能替代它们。CI 保持暂停。

## 2026-10-03 集成补强与集中验收

上述计数和摘要只证明历史输入。本轮补强按面板当前 `subscription_sources/models.rs`、`ordered_paths/models.rs` 和 `chains.rs` 的真实序列化模型实施：来源、链路、入口节点及策略组中的 `chain_ids` 为正 `i64`，范围至 `9223372036854775807`；没有收窄到 JavaScript 安全整数。请求、外部节点、版本、来源 revision 与 job 分别保留规范非空 UUID。数值字符串、布尔值、越界数值和 UUID 资源编号在进入 URL／控制器证据前拒绝。

来源详情、节点页和节点版本绑定同一数值来源；节点版本绑定成功 revision 和身份代数。更新回执绑定来源、下一修订及更新／更换身份语义；job 必须同时匹配其 UUID、来源、修订和身份代数，避免以其它任务的成功回执推进。当前夹具是 inline 来源，更新内容使用有序 `PATCH`，遵循面板“inline 不支持在线 `/refresh`”合同。旧任务仍在取消、回执暂时没有 job 时，等待此更新修订成为成功批次，不能使用旧成功批次立即宣布更新完成。

有序批量创建与创建后／删除后重放检查请求 UUID、回执数量、合法且唯一的数值链路／入口 ID；版本应用检查请求 UUID、链路 ID、资源类型、新修订及新 generation。退役仍经有序资源接口，策略组撤权仍经现有数值 `chain_ids`／`group_ids` 模型；没有修改面板旧 API、数据库或授权模型。

新增源码合同实际调用 driver 的来源节点读取、inline 更新、job 轮询与原子重放，覆盖完整合法 i64 上界、错误成功 job、旧批次和畸形重放回执。已有 follow／pinned、失败来源、版本应用与退役场景的边界响应补齐真实模型字段。所有响应明确为 TEST_ONLY，不写数据库设备回执。

本轮修改阶段没有运行测试、构建、语法检查或验证。冻结全部集成输入后，统一验收使用 `python3 -B` 执行下列四套合同，每套各执行一次，合计 86 项通过、0 失败、0 跳过。此计数独立于上述历史 23 项，不叠加历史或重复执行；最终输入及证据统一见[全部开放 issues 集成交付](all-open-issues-20261003.md)。

| 合同套件 | 实际通过 | 失败／跳过 |
| --- | --- | --- |
| `tools/test-managed-paths-preparation.py` | 17 | 0／0 |
| `tools/test-managed-paths-linux-contracts.py` | 31 | 0／0 |
| `tools/test-managed-paths-fixtures.py` | 21 | 0／0 |
| `tools/test-ordered-paths-native-contracts.py` | 17 | 0／0 |

真实签名 Agent／CA 下三设备注册、11 个托管整链场景、来源真实导入及切换、精确账本、故障恢复与原生进程清理仍需独立真实环境证据。工具合同通过不能替代这些实机条件，CI 保持暂停。

最终冻结前的交叉审查补齐失败导入的延期分支：无 job 回执时，来源详情仍须匹配本次 source／新修订／epoch；旧 cancelling job 不证明新导入完成，发现新代 job 后固定其 UUID 并核对终态 failed。新代 job 在两次观察之间已结束时，仅以没有 active job、本次新错误（或旧错误对应的更新尝试时间）及保持旧成功 revision 确认失败，旧成功批次本身不能证明失败完成。新增合同覆盖旧任务仍在取消、新任务失败、快速失败无 UUID、保留旧错误仍待完成及错误来源／epoch／成功身份；该补充已包含在本轮托管 API 驱动合同的 31 项通过结果中。
