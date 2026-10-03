# 重新架构阶段三：来源与链路统一迁移方案

- 状态：方案，未实施。实施前需要用户确认第 9 节的决定，并按第 6 节分别授权代码合入、生产迁移、发布和实机验收。
- 日期：2026-10-03。
- 关联：
  - [ADR 0079](adr/0079-rearchitecture-plugins-sources-chains.md)：阶段一、二已实施，阶段二把解析器合并移到本阶段。
  - [ADR 0040](adr/0040-mixed-chains-and-subscriptions.md)、[ADR 0073](adr/0073-ordered-path-publication-and-native-probe.md)、[ADR 0035](adr/0035-singbox-policy-package-groups.md)、[混合链路设计](node-chain-design.md)。

本方案基于对当前源码和迁移文件的逐表核对，引用的文件位置以提交 `ed72fc2` 为准。文中“A”指数字编号来源（`/subscription-sources`，`sources/`），“B”指有序来源（`/ordered-subscription-sources`，`subscription_sources/`）。

## 1. 目标与必须保持的承诺

**目标：**

1. 订阅来源只保留一套模型和一套解析器。
2. 链路只保留有序（ordered）一种模型和一条编译流水线。
3. 删除旧两跳（legacy）和混合（mixed）编译层、另一套来源及其解析器。删除放在最后，且要等迁移、设备升级和实机验收都完成。

**迁移过程中必须保持不变：**

- 代理用户和凭据：`accesses` 的 `uuid`、`credential`、`stat_name`。
- 订阅令牌与订阅地址。
- 历史计量：`usage_records`、`singbox_usage_daily`，都按入口节点记账。
- 链路 ID、入口节点、链路授权（策略组）、链路名称。
- 外部节点授权，包括固定版本和跟随两种模式。
- 节点库元数据：改名、标签、备注、排序、启停。
- 迁移步骤本身不让任何已存节点生成新版本，也不改变任何设备配置包或用户订阅输出的字节。之后的正常刷新和编辑可以产生新版本。

**不在本方案内：** 自动出口池、任意拓扑、新协议、平台全局用户。

## 2. 核实后的现状

### 2.1 两套来源

| | A：数字编号来源 | B：有序来源 |
| --- | --- | --- |
| 来源编号 | `BIGSERIAL` | `BIGSERIAL`，与 A 各用一个序列，编号会重叠 |
| 修订、节点、版本编号 | 都是 `BIGSERIAL` | 都是 UUID；修订另有全局 `generation` |
| 主要表 | `singbox_subscription_sources`、`singbox_source_revisions`、`singbox_external_nodes`、`singbox_external_node_versions`、`singbox_source_jobs`、`singbox_source_previews`（0026、0047） | `singbox_ordered_subscription_sources`、`singbox_subscription_source_revisions`、`singbox_ordered_external_nodes`、`singbox_ordered_external_node_versions`、`singbox_subscription_revision_nodes`、`singbox_subscription_source_jobs`、`singbox_subscription_source_requests`（0043） |
| 节点身份 | 有提供方编号时为 `provider:`+摘要；否则为 `endpoint:`+端点摘要。重复的节点直接拒收 | 有提供方编号时为 `provider:`+摘要（但解析器目前从不提取提供方编号）；否则为 `fingerprint:`+指纹。状态分唯一、歧义、无法识别三种 |
| 出站 | 校验后的 sing-box JSON（`ExternalOutbound`） | 类型化模型（`NormalizedOutbound`） |
| 使用方 | 节点库元数据（0046）、外部节点授权（0048）、用户订阅渲染、mixed 链路的订阅跳 | 只有 ordered 链路的订阅跳，以及有序资源视图 |
| 特有能力 | 预览后采用、`adopted` 标记、上游流量信息、请求标识（User-Agent）、自动刷新开关、变更摘要、提取提供方编号 | 请求幂等记录、修订历史接口、每次修订的成员表、身份三态、任务租约与取消中状态、结构化失败、最多三个认证头 |
| 刷新周期 | 300–2592000 秒 | 3600–604800 秒 |

另外两点：

- 用户订阅里的外部节点标签是 `external-node-{A 的节点编号} {名称}`（`crates/compiler/src/client.rs:59`）。A 的节点编号会出现在用户的客户端配置里。
- 两套表之间没有任何外键。

### 2.2 三种链路

| | legacy | mixed | ordered |
| --- | --- | --- | --- |
| 数据 | `singbox_chains` 的 `exit_node_id`、`relay_uuid` | `singbox_chain_versions`、`singbox_chain_hops`（订阅跳指向 A） | `singbox_ordered_chain_versions`、`singbox_ordered_chain_hops`（订阅跳指向 B） |
| 设备侧标签 | `chain-{id}`、`relay_{id}` | `path-{c}-g{g}-h{0..}`、`relay_{c}_g{g}_h{p}` | `chain-{c}-g{g}-h{1..}`、`relay_{c}_g{g}_h{p}` |
| 创建入口 | 界面已无入口，但 `POST /chains` 路由仍在 | 页头“创建链路” → `/chains/batch` | “创建两跳链路”“创建有序链路” → `/chains/ordered-batch` |

关键事实：

- **0044 已经为每条旧两跳回填了有序模型的第 1 代。** 版本标记为 `legacy=TRUE`，跳的 `relay_uuid` 与原链路相同。回填没有排除已软删除的链路。
- **现有的 `start_candidate` 不能用来接管旧两跳。** 它会为每个受管跳生成新的 relay UUID，产生新一代，设备配置的字节会变；目前也没有任何入口对旧两跳调用它。
- **有序入口会排除另外两类授权。** `singbox_desired_accesses` 对有序链路的入口不计入直接授权和策略节点授权（0044:176-181），策略同步随后会删除对应的 `accesses` 行，用户凭据随之改变。旧两跳没有这条排除。
- **旧两跳在两条发布路径上的入选条件不一致：**
  - 旧路径（`chains.rs:224-253`）要求两端启用、两端都是 VLESS + Reality，且入口至少有一个有效授权。
  - 有序路径对 legacy 版本不做这些检查（`ordered_paths/publication.rs:214-256`），因此没有授权的链路，其出口会多出中继用户。
- **订阅资格也不一致。** 旧两跳一旦记为有序，`qualified` 会要求部署依赖、运行时检查点等记录（`lifecycle.rs:858-892`），比 ADR 0040 要求保留的原规则更严。
- **mixed 转 ordered 做不到字节一致。** 两者的标签方案、位置编号起点、`clash_api` 字段和 DNS 都不同。
- **设备会保存 mixed 作用域 `path-{id}` 的已提交下限，低于下限的配置会被拒绝。** 目前只有 `path_kind='mixed'` 的行会生成这份约束文件。

## 3. 保留哪套来源

| 比较项 | 以 A 为准 | 以 B 为准 |
| --- | --- | --- |
| 与最终保留的链路模型 | ordered 的订阅跳、冻结快照和编译模型都用 B 的 UUID 和类型化出站，要整体改写；而跳和快照是不可变行 | 已经一致，链路历史不用改写 |
| 需要改指向的使用方 | ordered 链路跳、有序资源视图 | 节点库元数据、外部授权、用户订阅渲染；mixed 跳本来就要随 mixed 链路一起退役 |
| 需要补的能力 | 幂等记录、修订成员、身份三态、任务租约。这些是核心表的结构保证，补进去要改核心表 | 预览后采用、流量信息、请求标识、自动刷新开关、变更摘要、提取提供方编号。这些是产品功能，补进去是加列、加接口 |
| 对外编号 | 不变 | 给 B 的节点和版本加数字别名，沿用 A 的编号，对外编号和用户订阅标签都不变 |
| 解析器 | 只留 A 的；ordered 链路引用的 B 来源在首次刷新时改用 A 的解析器 | 只留 B 的；A 的来源在首次刷新时改用 B 的解析器 |

**建议以 B 为准，同时保留 A 的数字编号作为对外别名。** 理由：

1. 保留的链路模型和保留的来源模型天然一致，不需要改写不可变的链路历史。
2. B 缺的都是产品功能，补起来风险低；A 缺的是结构保证，补起来要动核心表。
3. A 的使用方都能改指向：节点库元数据和外部授权是可更新的表；mixed 跳会随 mixed 链路退役。数字别名保证 API 编号和用户订阅标签不变。

**代价：** A 的来源在迁移后的首次刷新会改用 B 的解析器。部分节点可能出现新版本，少数节点可能被识别为新身份（第 4.5 节）。具体数量只能在演练中测量。

## 4. 来源迁移（以 B 为准）

### 4.1 迁移前要先在 B 上补的能力

这些都是代码改动，要先合入并验证；数据迁移开始前不启用。

- **采用标记与预览：**
  - 节点增加 `adopted BOOLEAN NOT NULL DEFAULT TRUE`。B 现有节点保持可用；从 A 导入的节点沿用原值。
  - 预览暂存与“预览后采用”流程改为挂在 B 上。暂存表结构沿用 0047 的 `singbox_source_previews`。
- **来源字段：**
  - 增加 `user_agent`、`auto_refresh`、`traffic`、`changes` 四列。
  - B 的抓取改为传入请求标识；阶段二的共享抓取器已经支持。
- **刷新周期：** 默认把 B 的检查范围放宽到 300–2592000 秒，保留 A 来源的原设置（决定项 2）。
- **提供方编号：** B 的解析器补上 A 的提取规则，即 sing-box JSON 与 Mihomo 的 `provider_id`。键格式与 A 相同，为 `provider:`+sha256。
- **数字别名：**
  - `singbox_ordered_external_nodes` 和 `singbox_ordered_external_node_versions` 各增加 `public_id BIGINT NOT NULL UNIQUE`。
  - 导入行沿用 A 的编号。新行取自一个起点高于 A 现有最大编号的新序列，避免重叠。
  - 用户订阅标签、节点库和外部授权接口都使用 `public_id`。
- **导入版本保留原配置：**
  - 版本增加 `legacy_config JSONB`，只有导入行有值，内容是 A 原来的 `config_json`。
  - 用户订阅渲染优先使用它，以保证迁移本身不改变用户订阅输出。
  - 正常刷新产生的新版本不写这一列。
- **来源数量上限：** 合并后的未删除来源如果超过 B 的 128 个上限，按演练结果决定是否提高（决定项 7）。

### 4.2 数据映射

迁移在维护窗口内完成：先停止两套来源的后台任务，取消排队中和运行中的任务，等待所有预览过期。迁移只新增行和列；A 的表保留为只读历史，到第 6 节第 S7 步才删除。

| A | B | 规则 |
| --- | --- | --- |
| `singbox_subscription_sources.id` | 新的 B 来源编号 | 由 B 的序列分配，对照关系写入新表 `singbox_source_id_map(a_source_id PK, b_source_id UNIQUE)` |
| `name`、`kind`、`archived`、`deleted_at`、`settings_revision`、`identity_epoch`、`created_at`、`last_attempt_at`、`last_success_at`、`next_refresh_at` | 同名或对应列 | 原值复制 |
| `refresh_interval_seconds` | `refresh_interval_secs` | 网址来源原值复制；粘贴来源记为 0 |
| `secret_url` + `secret_authorization` | `input_config` | 写为 `{"kind":"url","url":…,"auth_headers":{"authorization":…}}`；没有认证时 `auth_headers` 为空 |
| `secret_content` | `input_config` | 写为 `{"kind":"inline","content":…}` |
| `source_host` | `host` | 原值 |
| `last_error`（固定代码文本） | `last_error`（结构化） | 写为 `{stage, kind, message, http_status:null}`：`kind` 保留原代码，`message` 按代码取固定中文说明 |
| `etag`、`last_modified`、`cache_*` | `conditional_*` | 不超过 2 KiB 才复制，否则置空，下次完整下载 |
| `user_agent`、`auto_refresh`、`traffic`、`changes` | 第 4.1 节新增的列 | 原值 |
| 当前修订，以及被授权或 mixed 跳引用到的修订 | `singbox_subscription_source_revisions` | 规则如下 |
| `singbox_external_nodes` | `singbox_ordered_external_nodes` | 规则如下 |
| 当前版本，以及被授权或 mixed 跳引用的版本 | `singbox_ordered_external_node_versions` | 规则如下 |
| 导入修订中的节点 | `singbox_subscription_revision_nodes` | 序号按 A 节点编号排序；公开预览与身份状态取自导入节点 |
| `singbox_source_jobs` 的其余历史 | 不迁移 | 留在 A 表里 |
| `singbox_source_previews` | 不迁移 | 迁移前清空 |

**修订：**
- 分配新 UUID；`generation` 取 B 的序列。
- `format` 映射：`uri` → `uri_list`，`base64_uri` → `base64_uri_list`，另外两种同名。
- `raw_digest` 取 `body_sha256`，`parsed_at` 取 `fetched_at`。
- `parser_version` 保留 A 的 `sinan-subscriptions-2`。B 的任务会因解析器版本不同，不使用条件缓存，下次刷新整篇重新解析。
- B 要求每个修订对应一个任务。每个导入修订配一行合成任务：状态为成功，阶段为完成，时间取 `fetched_at`。

**节点：**
- 分配新 UUID；`public_id` 取 A 的编号；`identity_epoch` 原值；`adopted` 原值。
- 身份键：
  - `provider:` 开头的键原样保留。
  - `endpoint:` 开头的键改为 `fingerprint:`+B 指纹。指纹由 A 的 `config_json` 经 B 规范化后计算，因为两边的端点摘要算法不同。
- 身份状态：A 中 `present` 且 `identity_unique` 的记为 `unique`；`identity_unique=FALSE` 的记为 `ambiguous`，身份键置空。
- `latest_version` 指向导入的当前版本；`last_seen_revision` 指向导入的对应修订。

**版本：**
- 分配新 UUID；`public_id` 取 A 的编号。
- `normalized_config` 由 B 规范化 A 的 `config_json` 得到；`content_digest` 是对类型化模型序列化后取 sha256。
- `legacy_config` 存 A 的原 `config_json`。
- `capabilities` 取自 A 的 `capabilities_json`；`supported` 取决于规范化是否成功。

### 4.3 使用方改指向

- **节点库元数据 `singbox_node_metadata`：**
  - 主键 `(kind, id)` 不变；外部节点行的 `id` 就是 `public_id`。
  - 生成列的外键从 A 节点改指 B 节点的 `public_id`。
  - 节点库查询改读 B。
- **外部授权 `singbox_external_accesses`：**
  - `source_id` 按映射表更新为 B 编号。
  - `external_node_id`、`node_version_id` 的数值不变（等于 `public_id`）。
  - 复合外键改指 B。为此 B 节点要增加 `UNIQUE(public_id, source_id)`，B 版本要增加 `UNIQUE(public_id, node_id)` 一类的约束。
- **用户订阅：** 标签仍为 `external-node-{public_id} {名称}`；导入版本用 `legacy_config` 渲染，迁移后输出不变。
- **mixed 链路的订阅跳：** 这些行不可变，保持原样作为历史。mixed 链路按第 5.2 节逐条转换；转换时按 `public_id` 找到对应的 B 节点和版本。
- **ordered 链路：** 已经使用 B，不需要改。
- **接口：**
  - B 的路由成为唯一的来源接口，补齐预览、采用、流量、请求标识和自动刷新。
  - A 的路由保留一个版本的只读兼容（决定项 3）：列表、详情和节点查询返回映射后的数据，并带上 `migrated_to`；写操作返回 409 和“来源已迁移”的说明。
  - 前端的 A 来源界面合并到 B 的界面。

### 4.4 身份与凭据

- URL、认证和粘贴内容逐字节复制，不重新编码。迁移校验比较 A 与 B 每个秘密的 sha256，日志不输出秘密本身。
- 身份代次保持不变，节点仍属于原来的代次。
- 授权按原模式保持：
  - 固定版本授权仍指向同一个版本（同一 `public_id`）。
  - 跟随授权仍然跟随；迁移后跟随 B 的 `latest_version`。
- 外部节点本来就不计量，迁移不改变这一点。

### 4.5 首次刷新的影响

迁移后，原 A 来源的第一次刷新会用 B 的解析器整篇重新解析：

- B 每次成功修订都会为全部节点写新版本，这是 B 的既有行为。
- 如果重新解析得到的类型化模型与导入时规范化 A 配置的结果不同，内容摘要就会不同。
  - 跟随授权会渲染新配置。
  - 跟随模式的 ordered 跳会因此开启新一代。
- 身份变化的情况：
  - 如果重新解析出的指纹与导入时由 A 配置算出的指纹不同，节点会被识别为新身份，原节点记为缺失。
  - 固定授权不受影响，因为它仍指向导入的旧版本。
  - 跟随授权可能因节点缺失，从用户订阅中消失，具体取决于迁移后外部授权的资格规则；演练时要确认。
- 阶段二记录的解析差异（YAML 标量、合并键、格式识别、URI 参数、名称规则）都可能触发上述情况。

只有真实地重新抓取一次，才能测出受影响的节点数量。这需要访问外部订阅服务，是否在演练中做由决定项 5 确定。不做的话，首次刷新的影响只能在生产环境中观察。

## 5. 链路迁移

### 5.1 旧两跳接管：沿用第 1 代，不重编译

做法：利用 0044 已经回填的有序第 1 代，只修改 `singbox_chains` 的标记，不生成新代，设备配置的字节不变。这符合 ADR 0040 与 ADR 0073 的原意：保留 ID、入口、relay UUID、订阅和原有字节。

**先合入的代码修正（各自带字节对照测试）：**

1. 有序发布对 legacy 版本使用与旧路径相同的入选条件：两端启用、两端都是 VLESS + Reality、入口至少有一个有效授权。
2. legacy 版本的订阅资格沿用旧规则：两端服务器健康、配置已应用、没有待发布的改动。不要求探测和检查点记录（ADR 0040 第 37 行）。
3. 0044 的 SQL 回填与 Rust 计算语义摘要的方式不同；生命周期比较版本时，不能把这种算法差异当成内容变化。

**迁移步骤：** 每条链路一个事务，失败的链路保持 legacy 并写入报告。

1. 预检，任一项不通过就跳过该链路：
   - 链路未软删除。
   - 第 1 代 legacy 版本和跳都存在，跳的 relay UUID 与 `singbox_chains.relay_uuid` 相同。
   - 冻结快照中入口和出口的端口、主机、SNI、密钥、short_id 和设置都与当前节点行一致。节点被有序版本引用时，这些参数在编辑时会被锁定，因此漂移应该很少，但仍要逐条查。
   - 入口节点没有直接授权或策略节点授权，否则接管后这些授权会被排除，对应凭据会被重建。
2. 把原 `exit_node_id`、`relay_uuid` 存入新表 `singbox_legacy_takeovers(chain_id PK, exit_node_id, relay_uuid, taken_over_at)`。
3. `UPDATE singbox_chains SET path_kind='ordered', phase='applied', desired_generation=1, applied_generation=1, route_enabled=TRUE, exit_node_id=NULL, relay_uuid=NULL`。
4. 对每台服务器做一次不下发的编译，配置包摘要必须与接管前相同；每个用户的订阅输出也必须逐字节相同。

接管之后，编辑出口等操作会按有序生命周期产生新一代，使用新的 relay UUID 和标签。这也符合 ADR 0040：只有接管时的那一代保持原字节，之后的新代按新规则生成。

### 5.2 mixed 链路转换：逐条真实切换

mixed 转 ordered 做不到字节一致，每条链路都要在设备上完成一次切换。参与的设备需要支持运行时检查点、屏障和路径探测（`runtime:checkpoint-v1`、`barrier-v1`、`path-probe-v1`）。

**方式：** 管理员在链路详情里逐条执行“转为有序链路”（决定项 4），不在迁移 SQL 中批量处理。

**需要新增的代码：**

1. **交接：**
   - 转换期间，mixed 的活动代继续作为入口路由。
   - 有序候选通过探测后，才切换入口。
   - 切换前失败就退回 mixed，链路不中断。
   - 编译层现有的“同一链路、有序候选未启用”例外，要扩展到 mixed 链路。
2. **墓碑：**
   - 新增墓碑表，保存每台服务器上已退役 mixed 作用域的下限。
   - 发布器始终为这些作用域下发 `runtime-constraints.json`，不再依赖 `path_kind='mixed'` 的行。
   - 墓碑要长期保留，至少到所有设备都升级为能识别已退役作用域的版本。
3. **跳映射：**
   - 受管跳生成受管端点版本。
   - 订阅跳按 `public_id` 找到导入的 B 节点和版本，保留原 `update_mode`。

**对用户和设备的影响：**
- 用户看到的链路 ID、入口、授权、订阅条目和计量都不变。
- 设备侧的中继标签和 UUID 会改变，因为这已经是新的一代。

mixed 的版本和跳保留为历史。全部 mixed 链路转换或删除、并通过实机验收之后，才删除 mixed 编译层。

### 5.3 统一创建入口

- 页头“创建链路”改为有序创建流程：`ChainEditor` 改调 `/chains/ordered-batch`，来源选择改用合并后的来源。
- 停止新建 mixed 链路：`/chains/batch` 返回 409，并说明应使用的新入口。
- 停用仍然存在的 `POST /chains`（旧两跳创建）。
- 修正 `docs/api.md` 中 `/chains/batch` 和 `/subscription-sources` 的过时描述。

## 6. 执行顺序与授权门槛

| 步骤 | 内容 | 验证 | 需要的授权 |
| --- | --- | --- | --- |
| S1 代码准备 | 第 4.1 节的 B 补齐、数字别名、迁移脚本、只读兼容路由；第 5.1 节的三项修正；第 5.2 节的交接、墓碑和跳映射；第 5.3 节的入口统一。迁移和转换先保持关闭 | 源码审查、本地隔离测试、浏览器回归、字节对照测试 | 代码合入（本方案确认后开始） |
| S2 演练 | 在生产数据快照的隔离副本上做完整演练（第 7 节） | 第 7 节的全部比对 | 读取生产数据快照 |
| S3 来源迁移 | 维护窗口内执行第 4 节 | 迁移前后的摘要比对 | 生产迁移 |
| S4 旧两跳接管 | 执行第 5.1 节 | 配置包与订阅逐字节比对 | 生产迁移（可与 S3 同一窗口） |
| S5 发布 | 发布包含 S1 代码的版本，设备升级 | 设备能力矩阵 | 正式发布、部署 |
| S6 mixed 转换 | 先在专用测试机上实机验收转换和回退，再在生产环境逐条执行 | 每条链路的探测、订阅资格和计量 | 实机验收；生产转换 |
| S7 收尾 | 删除 A 的表、mixed 与 legacy 编译层、只读兼容路由、A 的解析器；保留墓碑 | 全量回归、观察期 | 单独授权 |

每一步失败都停在当前步骤，不自动进入下一步。CI 恢复以仓库的 CI 暂停规则为准。

## 7. 演练

在隔离环境中进行：不连接任何设备，不发送通知；除非决定项 5 允许，否则也不访问订阅服务。

1. 把生产快照恢复到隔离的 PostgreSQL，停止所有后台任务。
2. 运行预检查询，保存只含计数、不含秘密的摘要：
   - 未删除来源总数与上限。
   - 刷新周期超出 B 范围的 A 来源数量（若决定项 2 选择不放宽）。
   - A 中被引用的版本（当前版本、授权引用、mixed 跳引用）里 B 无法规范化的数量。**必须为 0**，否则这些引用会失效。
   - 同一来源、同一代次中，换算成 B 身份键后重复的节点对数。**必须为 0**，否则唯一节点会变成歧义节点，引用随之失效。
   - 超过 2 KiB 的缓存标记数量（迁移时丢弃）。
   - 旧两跳的预检（第 5.1 节）未通过的数量和原因。
   - mixed 链路数、订阅跳数、每台服务器的设备能力，以及设备已提交的下限。
   - 运行中或排队的任务、未过期的预览（迁移前应清空）。
3. 记录迁移前状态：
   - 每台服务器配置包的摘要（发布器编译，不下发）。
   - 每个订阅令牌的输出摘要。
   - 节点库、外部授权、来源列表接口的输出摘要。
4. 执行迁移脚本：来源迁移，然后旧两跳接管。
5. 记录迁移后的同样摘要并比对：
   - 配置包和订阅输出必须全部一致。
   - 接口输出只允许来源编号按映射表变化。
6. 完整性检查：
   - 秘密逐字节一致（比较摘要）。
   - 各类数量一致。
   - 外键和不可变触发器都存在。
   - 再执行一次迁移脚本应当什么都不改。
7. 回滚演练：执行第 8 节的回滚步骤，摘要应回到迁移前。
8. 记录每一步耗时，确定维护窗口。
9. 若决定项 5 允许：对每个来源各刷新一次，统计新身份、缺失、内容摘要变化的节点数，以及会因此开启新一代的 ordered 跳数。

## 8. 回滚

- **来源迁移：**
  - 迁移只新增行和列，A 的表保持只读。
  - 回滚时先停服务，然后执行回滚脚本：删除导入的行，恢复外部授权和节点库的指向。删除不可变表中的行需要临时停用触发器，只有回滚脚本可以这样做。
  - 迁移后如果已经有新写入，快照恢复会丢失这些写入，所以窗口内优先用回滚脚本。
  - 迁移本身不改变配置包，设备侧不需要回滚。
- **旧两跳接管：**
  - 按 `singbox_legacy_takeovers` 恢复 `path_kind`、出口和 relay UUID。
  - 接管后一旦产生过新一代，就不能这样回滚，只能走有序链路自己的恢复流程。
- **mixed 转换：**
  - 切换前失败会自动退回 mixed。
  - 切换后的回退只能走有序恢复流程，不支持退回 mixed，因此要先在测试机上验收。
- **发布：** 保留上一个版本的二进制和签名制品。

## 9. 需要确认的决定

1. **来源以哪套为准：** 以 B 为准，并用数字别名保持对外编号（推荐）；或者以 A 为准，见第 3 节。
2. **刷新周期：** 把 B 的范围放宽到 300–2592000 秒，保留原设置（推荐）；或者把超出范围的 A 来源调整进 B 的范围。
3. **A 的旧接口：** 保留一个版本的只读兼容（推荐）；或者直接移除。
4. **mixed 链路：** 管理员逐条转换（推荐）；或者在维护窗口内自动批量转换。批量转换会同时切换多条链路，失败的影响面更大。
5. **演练中是否对真实订阅服务做一次刷新：** 做的话能测出首次刷新的实际影响，但要访问外部服务。
6. **授权：** S1 代码准备是否现在开始。代码合入不会自动执行任何数据迁移。
7. **来源数量上限：** 合并后若超过 128 个，是否提高上限。
