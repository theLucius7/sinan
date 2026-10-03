# 独立节点 IPQuality 验收

对应 ADR 0051。整步源码冻结后已执行本地统一验收，失败修复只补验受影响范围。专用 Linux、实际制品、许可审查、签署和部署仍待验；本地通过不等于整体整改完成。

2026-10-03 对 Issue #24 的本轮静态核对：check-place 继续作为一个 `aggregator` provider 展示七个数据库，正式 AbuseIPDB 带凭据接口与节点 Ipregistry／DB-IP 使用独立 provider；凭据缺失保持未知，不转回聚合入口冒充正式查询。独立 IPQuality 结果由共用诊断章节事务保存，provider、目标出口和任务 generation 分别绑定；媒体结果保持节点实际出口，不能用面板所在机器的访问代替。上述既有实现保留，本轮修复最小制品读取和实际库存绑定，见 [闭包补充记录](ipquality-minimal-profile.md)。修改期间未运行中间测试；最终十套 IP／工厂回归有效去重 275 项通过、2 个真实 loop 文件系统场景因未启用专用条件而跳过。首轮两个通用 profile fixture 错误已集中修复，仅补验受影响 rootfs-build 40 项，全部通过，原失败收据保留。输入身份和机器收据见 [本轮统一记录](all-open-issues-20261003.md)。正式账号、获准 builder、完整签名最小制品及节点联合负载仍待，不补写外部成功证据或关闭实际签收条件。

最终统一验证后的静态闭包复核另发现源码派生的 media policy 回退文件名不匹配：独立 IP profile 固定的 browser／netflix 摘要对应已审核 native helper，而仓库无 `policies/` 时原回退读取普通 helper。现显式映射到 `native-browser-policy.py` 和 `native-netflix-policy.py`，固定摘要及拒绝篡改边界不变；发布对应源仍使用独立角色名称 `policies/browser-policy.py`、`policies/netflix-policy.py` 携带同一份精确正文。修复冻结后，独立 source-policy 使用实际固定四角色缓存执行 30 项，全部通过、0 跳过，覆盖完整派生、Bash 语法、上游 serializer，以及正确回退、普通正文误置和公开副本篡改回归；这些本地源证据不替代正式 provider 或节点运行证据。

## 前次已执行的本地验收

最终 672 份功能输入索引 SHA256 为 `8dae808a159fe3b4636c230316ac63c17cfc5680da7f19546110d2949822672e`，基于父提交 `7c455bcd08e4f1254430e17bde69a767b32758be`。索引覆盖源码、迁移、构建工具、测试和 AGENTS；文档及 19 个生成 dist 文件另记。脱敏方法计数、原始收据摘要、条件忽略和 dist 摘要见 [本地验收记录](node-ipquality-local.json)。失败记录原样保留，不算成功。

| 范围 | 实际结果 | 证据边界 |
| --- | --- | --- |
| Rust workspace / PostgreSQL | 11 crates、72 个不同 target，去重 646 通过、0 失败、18 条件忽略 | 首轮全覆盖通过后，受影响面板范围 18 项替换旧 16 项；私有 PostgreSQL 已核对身份停止，端口及 socket 清理确认 |
| IPQuality 适配器 | 9/9 | 固定版本、单栈、签名和私有普通文件、归档与执行身份、有界结果、部分章节、重启读取、禁止重跑 |
| 面板 IPQuality 解析与账本 | 18/18，其中 6 项使用真实 PostgreSQL | server→job 锁序、章节与缓存同事务、幂等、晚到旧 generation、NAT 出口、失败保留最近成功、部分结果；缺原始 JSON 保留有效收据但字段未知 |
| Python | 去重 237 通过、0 失败/错误、19 既有平台条件跳过，共 256 项 | 11 个 suite；新 IPQuality policy/runner/artifact/build suite 无跳过；保留未变范围，仅重验失败的 policy |
| 固定上游源码派生与 transport | 27/27 | 实际离线固定四份源码、完整 Bash 语法与原 serializer 断言；DNS/连接/TLS/403/429/超时/非 JSON/字段/超限/未知模拟；未请求第三方 |
| 前端 | Bun 58/58、1154 断言，TypeScript/Vite 构建一次，19 个 dist 文件 | 8 个不同实际 dist 浏览器 suite，桌面 1440 与手机 390；历史出口、逐源失败、取消等待、跨服务器回调及读取失败；人工查看两种布局 |
| 静态检查 | fmt、warnings-deny Clippy、core 分层、diff 通过 | 最后 Python 修复不改变已验 Rust、前端或 dist；CI 保持暂停 |

最终验收发现的错误在同一步内修正：Rust fixture 可见性和 Clippy 条件表达式；浏览器替身的真实 API 路径与过期提示断言；节点/面板对缺少原始 JSON 的处理不一致；固定脚本函数替换误截内嵌函数和 pipeline 的闭括号。最终函数跨度按固定源码的明确尾命令核对，不越过别的函数，不删除函数间声明；新增广告嵌套和多行 JSON 回归。没有降低原完整 Bash 语法、serializer、来源身份或公共出口校验。

Rust 的 18 条件忽略涉及 Linux/root/systemd/cgroup、ICMP 权限、真实 sing-box/openssl 导入与授权/流量、Pebble ACME。Python 的 19 条件跳过涉及 Linux root 安装器、waitid 子进程回收、真实挂载及 loop 文件系统；具体 test 和原因逐项记录。这些均未执行，不算通过。模拟资源和 HTTP 失败不能替代真实小内存、磁盘不足、重启、断连、挂载清理及持续业务矩阵。

## 仍需专用 Linux 节点

必须用本次相同版本、对应架构的完整签名最小制品执行；不以 inert fixture、旧 daily 报告或当前 NodeQuality 准备包代替。

需要完成原生 Debian 12 builder 审核、认证最小 package/source 收集、prepare/build/export、逐包许可证及对应源审查。工具 profile 与声明是实现输入，不能当作已构建制品或授权证明；本步骤也不解决 Geekbench/Ookla 完整验机许可。

在专用节点记录任务前后资源、Agent 心跳/最后指标、systemd cgroup、OOM 日志、磁盘及清理结果，覆盖小内存拒绝、磁盘不足拒绝、运行内存下降、第三方拒绝/限流/超时、任务中 Agent 重启、面板断连、取消、重复提交、部分报告，以及 sing-box 持续流量。拒绝预检必须保留保护阈值；没有残留进程与挂载才可以签收清理。

真实出口与各媒体地区/可达性结果必须与同任务记录一致；源端拒绝或无法确认时显示未知，后续失败保留以前成功并标明历史。本机无法提供的实机或许可证据继续标待验，不关闭相关 Issue 或宣布整体整改完成。
