# 2026-10-03 全仓缺陷扫描与修复

用户要求扫描仓库已有缺陷，补全已有功能的缺陷，并按严重程度给出清单。本记录在集成分支 `claude/sinan-scan-refactor-odrgr3` 上完成。起点是 main `58dce7799d9aa6757d9dcb1473e1e463268bcdcc`。修改集中完成，冻结后统一验证；统一验证中新发现的问题修复后，只补验受影响的范围；最后提交一次。远端 CI 继续暂停，未触发、重跑或恢复。没有正式签署、发布、部署，也没有访问真实设备、云资源、DNS 或通知渠道。

## 扫描方法

| 手段 | 范围 | 结果概要 |
| --- | --- | --- |
| 自动检查（修改前基线） | `cargo clippy --all-targets -D warnings`（Rust 1.97）、全工作区 `cargo test`（本机隔离 PostgreSQL 16）、Bun 1.4.2 单测与构建、`web/dist` 重建一致性、分层检查、`tests/` Python 回归、CI 中的工具脚本回归、全部浏览器回归 | 见下文“基线结果” |
| 静态工具 | 在临时目录安装 ESLint 和 `react-hooks` 规则扫描 `web/src`（不改仓库依赖）；检查 Markdown 相对链接 | Hooks 调用规则 0 错误；17 条依赖数组提示逐条核对后，均为有意使用稳定回调的写法；文档链接 0 失效 |
| 人工审查 | 面板鉴权、会话与限速；Agent WebSocket 与 HTTP 接口；服务器与接入；遥测入库；网卡流量周期；告警评估与投递；公开看板白名单；制品与安装命令；退役。sing-box 插件的订阅、外部授权、用量入账、套餐；DDNS；阿里云电源策略与云 API 签名；Agent 用量账本；前端入口、会话与资源钩子、服务器与节点页面 | 见缺陷清单 |
| 开放 issue 核对 | 14 个开放 issue | #147、#149、#152、#156 等的源码缺口均已在主线修复；其余开放项缺的是实机、权利或公网证据，不是新的代码缺陷，本轮不重复处理 |

## 缺陷清单（按严重程度）

状态说明：“已修复”指本轮已改源码并附回归；“待重构”指需要改数据模型或架构，列入后续重新架构，本轮不做半截修改；“记录”指影响有限，暂只登记。

| 编号 | 严重度 | 模块 | 缺陷 | 触发与影响 | 状态 |
| --- | --- | --- | --- | --- | --- |
| D1 | 高 | 面板 Agent 通道 / sing-box 用量 | 任一 `usage.batch` 被拒都会让面板断开该设备的 WebSocket | Agent 会把未确认的批次留在持久 outbox，每 15 秒重放一次。只要有一个批次永久无效，就会反复断线重连；同批之后的合法批次也来不及处理，该服务器的代理用量会一直停止入账，manifest 通知、checkpoint 等控制消息也会受影响。现实触发场景：设备离线时从面板删除，之后在同一台机器重装并保留了本地状态，outbox 中的旧节点身份从未向新服务器记录发布 | 已修复 |
| D2 | 中 | 面板后台任务 | 维护（告警、到期续期、诊断过期）、汇率、遥测历史，以及 sing-box 发布器、订阅工作器、DDNS、阿里云循环都只 `tokio::spawn` 一次，没有监督 | 任一循环 panic 后永久停止，而 HTTP 服务照常运行，表面看不出异常。插件循环用 `join!` 绑在一起，一个插件 panic 会连带停掉另外两个 | 已修复 |
| D3 | 中 | 发布/安装测试 | `tests/test_release.py` 直接执行未渲染的 `deploy/install.sh.tmpl` | 2026-10-01 新增 `@@LEGACY_CHECKPOINT_PREFLIGHT@@` 后，8 项以 root 运行的真实安装器前缀测试全部报 Python 语法错误。CI 以非 root 运行会直接跳过这些测试，所以一直没被发现，签名安装器真实执行路径的回归保护实际处于失效状态 | 已修复 |
| D4 | 中 | sing-box 用量入账 | 每条用量记录都用 jsonb 包含查询，按旧到新扫描该服务器全部历史部署 | `deployments` 保存每次发布的完整配置且从不清理，也没有索引。新加入用户的身份只出现在最新修订中，校验要先解码全部旧快照；入账耗时随发布次数线性增长 | 已修复（改为从最新修订开始检索） |
| D5 | 中 | sing-box 用量汇总 / 前端 | `/api/plugins/sing-box/usage` 每次请求都对全部 `usage_records` 做无时间范围的三次聚合，代理用户页默认每 5 秒轮询一次 | 明细约每 30 秒按“用户×节点”追加一行，且没有归并，页面打开时数据库负载随历史线性增长 | 待重构：增加按日或按周期的汇总表，在入账时增量维护 |
| D6 | 中 | sing-box 套餐 | 发布器每秒调用 `singbox_entitlements`，对所有用户的当前周期明细求和，每次调用两遍 | 有额度的用户在周期末需要累加接近一个月的明细，每秒执行一次，CPU 消耗随用户数和活跃度上升 | 待重构：与 D5 共用周期汇总 |
| D7 | 中 | 数据保留 | `deployments`（完整配置文本和 jsonb）、`usage_records`、`usage_batches`、`remote_commands`（单条输出最多 512 KiB）、`enrollment_tokens` 没有保留或清理策略 | 数据库体积和备份大小持续增长，同时放大 D4–D6 | 待重构：保留策略必须保留 Agent 当前已应用版本、订阅快照和账本可追溯性，需要专门设计 |
| D8 | 中 | 浏览器回归夹具 | 35 个浏览器测试的静态文件服务器先写 200 响应头再读文件。页面关闭时，Chromium 会把仍挂起的拦截请求放行到真实网络，这些请求打到静态服务器后读文件失败，又写 404 响应头，进程以 `ERR_HTTP_HEADERS_SENT` 崩溃。`node-ip-provider` 在 `goto` 之前就开始等待响应，可能等到即将被 reload 丢弃的旧响应，读取正文时报错 | 本机 Chromium 1194 下有 5 套测试稳定失败，与产品逻辑无关；另有 11 个文件此前已是正确写法，说明这个问题曾被零散修过 | 已修复 |
| D9 | 低 | 面板会话 | 过期会话只在管理员登录时清理 | Agent 每次重连都会新建会话（至少每小时一次）；管理员长期不登录时 `sessions` 表无限增长 | 已修复 |
| D10 | 低 | 发布测试卫生 | `tests/test_release.py` 在宿主机创建 `/run/systemd/system` 且不清理 | 改变测试机的 init 检测结果，影响之后在同一台机器上运行的其他测试和工具 | 已修复 |
| D11 | 低 | 测试对环境的依赖 | Agent 的 `selected_ipv6_records_the_actual_family_and_rejects_wrong_family` 与 `tcp-probe` 的 `real_ipv4_and_ipv6_connections_close_without_application_data` 在没有 IPv6 的主机或容器中直接失败；`tools/test-nodequality-node-query.py` 会继承开发机已有的代理变量（如 `YARN_HTTPS_PROXY`），在已配置代理的机器上必然失败 | 环境差异被误报为产品失败，掩盖真实回归。产品端已通过 curl 配置 `proxy=""`、`noproxy="*"` 禁用代理，不是产品缺陷 | 已修复 |
| D12 | 低 | 前端节点页 | `SubscriptionSources` 把订阅来源的首次加载当成“来源已变化”，回调父页面 `refresh()`，整页的节点、资源、服务器、用量和目录刚加载完就再请求一轮；`NodeCatalog` 挂载时也会重复请求目录。重复刷新期间点击“创建节点”“创建链路”会被静默忽略：按钮看起来可用，点了却没有反应 | 每次打开节点页多发约 7 个请求；浏览器回归 `mixed-chains`、`singbox-resource-snapshots` 因点击被忽略而稳定失败 | 已修复重复刷新。后台定时轮询期间点击仍会被静默忽略，这是原有设计，列入界面重排时统一处理 |
| D13 | 低 | 前端数据一致性 / 测试稳定性 | 节点页的有序资源、资源列表和节点目录各自独立刷新。删除有序链路后，排除列表先更新、目录数据还没刷新，已删除的链路会在“节点库”里短暂闪现；清除筛选后，目录也可能短暂显示旧数据 | `proxy-resources`、`singbox-business` 两套浏览器回归在本机时好时坏（原版代码分别 0/6 和 1/4 通过），`admin-refresh` 也偶发计时失败 | 记录：需要统一节点页的数据快照，留到界面重排时处理 |
| D14 | 低 | 离线告警 | 连接正常关闭时，`last_seen` 被写成“当前时间 − 61 秒”，告警评估却把它当作真实的最后心跳时间 | Agent 正常重启或升级断开后，离线告警比配置的阈值约早 61 秒触发，与“已超过 N 分钟”的文案不符；异常掉线不受影响 | 记录：需要单独保存断开时间，留到重构 |
| D15 | 低 | 前端构建 | 主包 `index-*.js` 约 730 KB（gzip 后 219 KB），超过 Vite 500 KB 警告线 | 首屏加载慢，管理页面没有按路由拆分 | 待重构（界面重排时按路由拆分） |
| D16 | 低 | 可维护性 | 627 行 Rust 超过 200 字符；543 行 TSX 超过 300 字符，最长一行 6094 字符（`ProxyUsers.tsx`）；35 条内联 SQL 超过 500 字符 | 审查、合并与定位困难，是缺陷难以被发现的主要原因之一 | 待重构 |
| D17 | 低 | 架构 | 订阅来源有新旧两套实现（`sources`、`subscription_sources` 加 `subscription_parser`）；链路有 legacy、mixed、ordered 三套模型；插件通过 `#[path]` 直接编入面板 crate，没有编译期边界 | 同一业务的修复需要同时改多处；插件可以随意引用面板内部 | 待重构 |
| D18 | 低 | 制品下载 | 每次下载都重新验证全部已收录发布（最多 128 份签名证明），并把整个制品读入内存 | 多台 Agent 同时下载运行时会造成 CPU 与内存尖峰；仅已认证设备可触发 | 记录 |
| D19 | 低 | 可观测性 | 有序链路生命周期 `tick` 失败时日志丢弃了错误详情 | 生产排障只能看到“transition failed”；需要先引入不含凭据的错误分类，再记录详情 | 记录 |
| D20 | 低 | 测试卫生 | `tools/test-nodequality-native-watcher.py` 在测试成功时也把证据目录留在 `/tmp`（`materials_retained: true`）；原生 fixture 进程测试的失败路径用例同样留下目录 | 与 2026-10-03 “验证完成就删除”的清理要求冲突，多次运行后 `/tmp` 不断累积 | 记录：仍需确认证据采集流程（`SINAN_WATCHER_TEST_EVIDENCE`）的去留，本轮只清理了本次运行产生的目录 |

## 已修复项

- **D1**：面板 WebSocket 循环单独处理 `usage.batch`。入账失败时整批回滚、不回 ACK，并以 `server_id` 记录告警，连接保持。其他消息的错误处理不变。`usage::ingest` 对无效批次仍返回错误，原有回归不变。新增 `crates/panel/tests/accounting.rs::rejected_batch_keeps_the_device_channel_and_acknowledges_later_batches`：先发一个身份从未发布的批次，再发一个合法批次，断言连接未断、只确认合法批次、被拒批次没有残留。协议说明已同步到 [协议文档](../protocol.md)。
- **D2**：新增 `maintenance::supervise`。每次尝试在独立任务中运行，panic 或意外返回时记录错误，5 秒后重启。外层被取消时通过 `AbortOnDrop` 一并终止正在运行的尝试，避免关停后遗留任务。面板入口的维护、汇率、遥测历史，以及兼容入口 `publisher::run`、`plugins::run` 中的 sing-box、DDNS、阿里云插件循环都分别受监督。各循环的状态均保存在 PostgreSQL 中，重启后继续执行。新增单元测试覆盖 panic 后重启、意外返回后重启，以及取消监督时终止正在运行的任务。
- **D3/D10**：测试改用与正式发布相同的 `release.installer_source` 渲染模板，展开全部标记后再截取前缀；改用测试私有目录模拟 systemd，不再写宿主机的 `/run/systemd/system`。强制优化模式改为让所有内嵌 Python 校验器（包括旧状态预检）都以 `-O` 运行，并断言至少有两处被替换，防止替换意外失效。
- **D4**：身份校验改为标量子查询 `ORDER BY rev DESC LIMIT 1`，从最新修订向旧修订检索；`EXISTS` 会丢弃子查询中的排序，所以不用它。语义不变：已撤销身份在历史修订中仍然有效，可用于终态样本与离线重放。
- **D8**：35 个浏览器测试的静态服务器改为先读文件、成功后再写 200，读取失败时返回 404，不再崩溃。`node-ip-provider` 改为只接受正文可读且等于本次夹具数据的响应，断言内容不变。
- **D9**：维护循环每 30 秒删除所有已过期的管理员和设备会话，新增 PostgreSQL 单元测试，验证过期会话被删除、未过期会话保留。
- **D11**：无法绑定 `[::1]` 时，Agent 与 `tcp-probe` 的对应用例打印原因并跳过 IPv6 部分，IPv4 部分照常断言；有 IPv6 的 CI 与开发机仍完整执行。node-query 测试只把宿主机自带的代理变量排除在受测环境之外，注入的 `HTTP_PROXY`、`https_proxy` 仍必须被产品清除。
- **D12**：`SubscriptionSources` 把首次加载的来源修订作为基线，之后真有变化（包括来源从无到有、从有到无）才通知父页面；`NodeCatalog` 只在父页面刷新序号确实变化时才重新读取目录。重新构建并提交了 `web/dist`。

## 基线结果（修改前）

源码 `58dce77`，本机 Rust 1.97.0、PostgreSQL 16.14（回环 55432 端口，专用临时实例）、Bun 1.4.2、Python 3.11、Playwright 1.56.1、Chromium 1194。

- Clippy：全工作区全 targets、warnings 视为错误，通过。
- Rust 与 PostgreSQL：`cargo test --locked --workspace --no-fail-fast`，114 组结果，1044 通过、2 失败、24 条件忽略。两项失败都是 D11 的无 IPv6 主机问题。开头两轮因本机测试数据库未建库、临时数据目录权限被会话环境重置而大量报错，属于本次测试环境问题，不计入；改用独立数据目录重跑后得到上述结果。
- 前端：Bun 1.4.2 下 30 个文件、166 项通过，2248 次断言；`bun run build` 重建的 `web/dist` 与仓库中已提交的逐字一致。用环境自带的 Bun 1.3.14 会因锁文件格式不同出现 8 项误报，不计入。
- 分层检查 `tools/check-core-boundary.py` 通过。
- `tests/` Python 回归（安装 minisign 后）：181 项中 12 项失败、15 项跳过。其中 8 项是 D3；另外 4 项 StandaloneBootstrapTests 需要运行中的 systemd/OpenRC，本容器不具备。临时创建 systemd 标记后单独运行这 6 项全部通过，随即删除标记，确认是环境原因。
- CI 中的工具脚本：48 个脚本、698 个方法，162 个按条件跳过；只有 `tools/test-nodequality-node-query.py` 的 1 个方法失败（D11），其余全部通过。
- 浏览器回归（用 Node 运行，全部使用私有回环 API 替身）：50 套中 43 套通过。`passkeys.mjs` 需要 Bun 运行时，并由 Rust ignored 用例拉起面板驱动，不能单独运行；另外 6 套失败分别是 D8 的 `node-options`、`singbox-chain-snapshot-writes`、`singbox-snapshot-writes`、`node-ip-provider`，D12 的 `mixed-chains`，以及同时受两者影响的 `singbox-resource-snapshots`。

## 修复后统一验证

- `cargo fmt --check`、全工作区全 targets Clippy（warnings 视为错误）、分层检查、`git diff --check` 全部通过。
- 受影响范围的 Rust 与 PostgreSQL 测试：`sinan-panel` 全部 targets 68 组，545 通过、0 失败、7 条件忽略，包含新增的用量通道、监督任务和会话清理用例；`sinan-agent-core --lib` 253 通过、0 失败、8 条件忽略；`sinan-tcp-probe --lib` 25 通过、0 失败。本机没有 IPv6，两个 IPv6 用例按 D11 的修改打印原因后跳过了 IPv6 部分。其他 crate 没有改动，沿用基线结果，没有重复运行全工作区。
- `tests/` Python：181 项中 D3 的 8 项全部通过，宿主机不再出现 `/run/systemd/system`；仍失败的 4 项是上面说明的 systemd 环境项，不计为通过。
- `tools/test-nodequality-node-query.py` 修复后 15 项全部通过。
- D4 检索顺序实测：在隔离库中构造 3000 个历史修订（每个 200 个用户、20 KB 配置），新旧查询结果完全一致。只出现在最新修订中的身份，单条校验从 219 ms 降到 0.2 ms；老身份两者都约 0.2 ms；不存在的身份两者都需要全量扫描（约 230–320 ms，是被拒批次的已知代价）。
- 前端：Bun 1.4.2 重新构建（TypeScript 检查与 Vite 构建通过），30 个文件 166 项单测通过；新 `web/dist` 一并提交，面板嵌入前端的测试（`--test frontend`）通过。
- 浏览器回归按文档改用 Bun 运行：49 套中 46 套通过（`passkeys.mjs` 同上跳过），基线中 D8、D12 涉及的 6 套全部转为通过。仍失败的 3 套属于 D13 的已有时序问题：用原版 `dist` 和原版测试在隔离目录重跑，`proxy-resources` 0/6、`singbox-business` 1/4 通过；`admin-refresh` 单独重跑 2/2 通过，原版也能通过，属偶发失败。这三套都不计为通过。

## 未验证范围

- 远端 CI 继续暂停；本地结果不代表 main 全绿。
- D1、D2 只用隔离 PostgreSQL 与回环 WebSocket 夹具验证，没有在真实设备上演示 outbox 重放与长时间重连；D4 只在构造的数据集上测过耗时，没有生产数据。
- 待重构和记录项（D5–D7、D13–D20）本轮只登记，没有实现；后续重新架构时与数据模型一并设计和验收。
- 需要 root 权限、systemd、ICMP、正式 sing-box 或 ACME 的条件测试仍按原状忽略；StandaloneBootstrapTests 需要运行中的 systemd/OpenRC，本容器无法执行，不计为通过；`passkeys.mjs` 的虚拟认证器浏览器往返未执行。
