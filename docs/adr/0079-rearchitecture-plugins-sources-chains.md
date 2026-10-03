# ADR 0079：重新架构：插件边界、订阅来源与链路模型

- 状态：已接受。阶段一已实施；阶段二随后实施；阶段三另写详细迁移方案，单独授权后实施。
- 日期：2026-10-03。
- 关联：[全仓缺陷扫描](../acceptance/defect-scan-20261003.md) D17；[ADR 0040](0040-mixed-chains-and-subscriptions.md)、[ADR 0072](0072-subscription-source-lifecycle.md)、[ADR 0076](0076-node-catalog-and-external-access.md)、[ADR 0078](0078-admin-layout-and-node-sections.md)。

## 背景

用户要求重新架构仓库和各个功能。缺陷扫描的 D17 指出三处结构问题。本 ADR 先记录核实后的现状，再提出分阶段方案。

### 插件边界

- 7 个面板插件共约 3.5 万行 Rust：sing-box、DDNS、阿里云、云 API 公共库、IP 质量、NodeQuality、TCP 质量。它们通过 `#[path]` 直接编进 `sinan-panel`，没有独立 crate。
- 插件直接使用面板内部的 `AppState`、`auth::require_admin`、错误类型、诊断服务、IP 质量、运行控制、通行密钥、通知等模块。
- 面板核心也反向直接调用插件内部，例如 Agent 通道调用用量入账和配置包，诊断与 IP 质量模块读取诊断插件的内部结构。
- 插件之间也有直接引用：阿里云、DDNS 引用云 API 库；NodeQuality 引用 sing-box 的运行活动。
- 迁移是一条线性序列，插件表混在其中。50 个集成测试中有 24 个直接引用插件路径。
- 分层检查只覆盖 `agent-core`，面板和插件之间的依赖没有任何约束。

### 订阅来源

| | A：数字编号来源 | B：UUID 有序来源 |
| --- | --- | --- |
| 接口 | `/subscription-sources` | `/ordered-subscription-sources` |
| 表 | 0026、0047（`singbox_subscription_sources` 等） | 0043（`singbox_ordered_*`） |
| 使用方 | 节点库、外部节点授权、mixed 链路 | 只有 ordered 链路 |
| 后台任务 | 由发布循环每秒驱动 | 独立 worker |
| 特有能力 | 预览后再采用、流量信息、自动更新设置 | 修订代、身份状态（唯一/歧义/未确认）、请求幂等记录、类型化出站 |

- 两套之间没有外键，ID 类型也不同。
- 抓取、私网地址检查、重定向、解压、四种格式（分享链接、Base64、sing-box JSON、Clash/Mihomo YAML）的解析、身份计算和任务队列各写了一份，重复约 4–5 千行。
- 两边的安全规则略有差异：A 拦截 `.internal` 主机名并支持 deflate，B 允许三种认证头。
- 现有文档要求两者分开保存，例如 ADR 0076：“两者不能因页面合并而互相替换”。

### 链路模型

- `singbox_chains.path_kind` 有三种取值：
  - `legacy`：0016 的两跳链路；
  - `mixed`：0027 的有序混合路径，订阅段引用来源 A；
  - `ordered`：0044 的有序路径，带候选、探测、屏障和恢复生命周期，订阅段引用来源 B。
- 编译分三层依次叠加：`relays` → `paths`（mixed）→ `paths/render`（ordered），后两层要检查入口和 `clash_api` 不能冲突。
- 创建入口：
  - 页头“创建链路”调用 `/chains/batch`，新建 mixed 链路；
  - “创建两跳链路”和“创建有序链路”都调用 `/chains/ordered-batch`，新建 ordered 链路，其中“两跳”就是只有一跳的 ordered 路径；
  - legacy 已没有创建入口，只剩历史数据。
- 把 legacy 转成 ordered 的代码（`ordered_paths/lifecycle.rs` 的 `start_candidate`）已经存在，但没有任何入口调用它。ADR 0040 原本计划把旧链路接管为单个受管段，并保留 ID、relay UUID、标签、订阅和编译字节。
- 文档与代码有出入：`docs/api.md` 中 `/chains/batch` 和 `/subscription-sources` 的描述已过时。

## 目标

1. 面板核心与插件之间有编译期边界：核心不认识具体插件，插件只通过公开接口使用面板能力，只有面板二进制把两者组装起来。这与 Agent 的 core/adapter 规则一致。
2. 订阅抓取与解析只有一份实现，安全规则只在一处维护。
3. 链路只有一种模型（ordered）、一条编译流水线。旧链路保留 ID、凭据、订阅、授权和历史计量。

## 方案：分三阶段

### 阶段一：插件编译边界（不改数据库，不改 HTTP 接口）

1. 新增面板宿主库 crate，放面板通用能力：`AppState`、配置、鉴权、错误类型、诊断服务、IP 质量、运行控制、通知、通行密钥等。同时定义插件接口，覆盖路由、后台任务、Agent 消息钩子（用量入账、manifest、配置包）、运行活动查询和诊断插件登记。
2. 各插件改为独立 crate，只依赖宿主库和明确声明的共享库：云 API 公共库成为普通库 crate；NodeQuality 改为通过宿主接口查询运行活动，不再直接引用 sing-box。
3. `sinan-panel` 只负责组装：二进制登记插件；库继续再导出 `sinan_panel::plugins::singbox` 等原有路径，集成测试不用改路径。
4. 迁移仍是一条线性序列，留在面板中；`sqlx` 要求单一序列，不拆分。
5. 分层检查扩展到宿主库：与 `agent-core` 一样，不得出现 sing-box 名称和代理业务词汇，例外表达式由检查器逐条列出。

这一阶段只改代码组织，行为不变。改动以调整模块路径为主，但规模很大，用全部 Rust 与浏览器测试验证。

### 阶段二：订阅抓取与解析合一（不改表，不改接口）

1. 抽出一个共享抓取器，安全规则取两边的并集：拦截 `.internal`、支持 gzip/deflate、认证头白名单、重定向与大小限制。
2. 抽出一个共享解析器：四种格式统一输出类型化出站。
3. A、B 各自保留存储、身份和版本规则，由适配层转换成各自原来的配置文本和摘要。用现有夹具加对照语料做逐字节比对，保证已存外部节点不会因为升级而生成新版本。
4. 删除重复的解析和抓取代码。

唯一的行为变化是安全规则取并集，例如 B 也会拦截 `.internal`。

### 阶段三：统一为一种来源和一种链路模型（需要数据迁移，单独授权）

1. 来源合并为一套模型，另一套的数据及其引用（链路订阅段、外部节点授权、节点库元数据）迁移过来。
2. legacy 链路迁为单个受管段的 ordered 路径，接入已有的转换代码；mixed 链路逐段映射为 ordered 路径。
3. 页头“创建链路”改用 ordered 流程，停止新建 mixed 链路。
4. 在真实数据快照上演练迁移，设备完成升级、重新发布，并通过实机验收之后，才删除 mixed 和 legacy 编译层。

按仓库规则，生产迁移、发布和实机验收需要单独授权。实施前另写详细迁移方案，包括字段映射、身份与凭据保留规则、回滚方式和演练步骤。

## 已确认的问题

- 实施范围：先做阶段一、二；阶段三另出详细迁移方案，再单独授权。
- 阶段三中来源统一的方向，在写阶段三详细方案时比较后再定：
  - 以 B 为准：ordered 链路依赖 B 的修订代和身份状态，类型化程度更高，但要把节点库、外部授权和预览采用迁到 B，并把外部节点编号从数字改为 UUID。
  - 以 A 为准：节点库和外部授权不动，但要给 A 补上修订代、身份状态和幂等记录，并改写 ordered 链路的订阅段引用。
- D16：暂不为前端引入格式化工具，只拆分本轮改动文件中的超长行。

## 阶段一实施说明

- **crate 划分：**
  - 宿主 `crates/panel-host`（`sinan-panel-host`）：原 `crates/panel/src` 中除入口与插件桥之外的全部模块，含共用诊断服务。
  - 业务插件：`plugins/singbox/panel`（`sinan-plugin-singbox`）、`plugins/ddns/panel`（`sinan-plugin-ddns`）、`plugins/alicloud/panel`（`sinan-plugin-alicloud`）。
  - 云 API 公共库：`plugins/cloud_api/panel`（`sinan-cloud-api`）。它的本地模拟服务只在测试或 `test-support` 特性下编译，供两个云插件的测试使用。
  - 组装：`crates/panel`（`sinan-panel`）。
  - 各插件目录保持原位置。`[lib] path = "mod.rs"` 让原有模块树不变；关闭自动发现目标，避免把作为子模块的 `tests/` 目录当成集成测试。
- **插件接口：**
  - 宿主的 `plugin_api::PanelPlugins` 覆盖用量入账、模块清单、配置包和运行活动查询。NodeQuality 也改为通过这个接口查询运行活动，不再直接引用 sing-box。
  - 插件路由由组装层作为参数传给宿主的 `router`；后台任务由组装层分别守护。
- **登记方式：**
  - 插件集合登记在宿主的进程级只登记一次的槽位中，由组装层在构造路由和启动后台任务时登记。
  - 没有放进 `AppState`，是因为测试和嵌入方直接调用 `AppState::new(pool, config)`。为保持这个公共签名，不给它增加参数。
  - 未登记时，宿主采用保守默认：用量入账报错并保持未确认、模块清单为空、配置包不存在、运行活动为“未配置”。
- **迁移：** 迁移仍是一条序列，留在 `crates/panel/migrations`。宿主用相对路径嵌入它；插件 crate 内的数据库单元测试也显式指向它。
- **公共路径：** 组装 crate 再导出宿主模块和插件，原有 `sinan_panel::*` 路径（含 `sinan_panel::plugins::singbox`、`sinan_panel::usage` 等）保持可用，集成测试不改路径。
- **分层检查：** `tools/check-core-boundary.py` 现在同时检查：
  - `agent-core` 与 `panel-host` 两个目录的禁用词；宿主的例外表达式逐条列出，如 HTTP `User-Agent` 和 URL 用户信息测试夹具。
  - Agent 核心、适配器、面板宿主和业务插件 `Cargo.toml` 中的工作区依赖方向。
- **未拆分的部分：**
  - 三个诊断插件（IP 质量、NodeQuality、TCP 质量）仍由宿主的 `diagnostic_plugins.rs` 通过 path 编入。它们与宿主的 IP 质量、诊断类型互相引用，拆分需要先把共用类型提升为宿主接口，留到后续独立步骤。
  - 这三个插件的源码物理位于 `plugins/` 下，不在宿主目录的禁用词检查范围内。

## 替代方案

- **保持现状，只补文档：** 重复的安全与解析代码仍然要修两遍；三层编译叠加的冲突检查会继续增长。
- **直接合并数据模型，不分阶段：** 风险集中，无法在不改数据的前提下先验证代码边界和解析一致性。
- **插件改成动态加载：** Rust 没有稳定的动态库 ABI，且会削弱现有类型检查；不采用。
