# 面板与 Agent 协议 v1

## 传输与兼容

生产环境必须通过 HTTPS/WSS 暴露面板；本地测试可使用回环 HTTP。Agent 原生传输只访问已配置面板的同源地址，拒绝外站制品、重定向及路径穿越。NodeQuality 既有完整任务的上游执行链见 ADR 0016；新完整任务已按 ADR0031 暂停，日常探测只访问已配置目标。WebSocket 入口为 `GET /api/agent/v1/ws`。全部业务消息为 UTF-8 JSON 文本；单条消息应小于 1 MiB。

Agent 与面板的产品版本独立；面板当前声明支持协议范围 `1..=1`，按协议版本和能力判断兼容，不要求产品版本相等。hello 和静态遥测报告 Agent 二进制自己的版本。

信封：`{"v":1,"type":"heartbeat","id":"UUID","ts":1790000000,"payload":{}}`。

`v` 为协议主版本，`id` 为消息 UUID，`ts` 为 UTC Unix 秒，`payload` 为对应类型对象。字段只能增加，接收方忽略未知字段；未知 `type` 记录后忽略，不断开已认证连接。无法解析的已知消息拒绝处理。消息 ID 不承担流量去重；流量使用自己的 epoch 和 seq。

## 注册与身份

管理员为一个服务器产生一次性随机 token，24 小时过期。数据库只保存 token 摘要；服务器标识使用正整数。`POST /api/agent/v1/enroll` 请求 `{token,device_public_key,static_info}`，成功返回 `{server_id}`。设备公钥为 Ed25519 的 32 字节无填充 Base64 URL-safe 文本。

令牌校验、绑定设备与消费必须在同一数据库事务中完成，重复或过期 token 不可注册。Agent 私钥只保存在本地权限 0600 的身份目录中，永不上传。

## WebSocket 认证时序

1. 面板生成随机、连接专用、一次性的 nonce，发送 `auth.challenge`，内容 `{nonce,server_time}`。nonce 是无填充 Base64 URL-safe 文本。
2. Agent 用 Ed25519 签名 **nonce 字符串的 UTF-8 字节**，发送 `auth.response`：`{server_id,signature}`，signature 同样使用无填充 Base64 URL-safe。
3. 面板验证设备公钥和当前挑战，通过后发送 `hello.ack`：`{server_time,session_token,session_expires_at}`。`server_time` 是本次会话签发时的时间快照，过期时间由同一次取时加 3600 秒得到，并与数据库存储值一致。HTTP Bearer token 重新连接重新签发，绑定服务器身份。认证前不可获取清单或发送计量。
4. Agent 发送 `hello`：`{agent_version,protocol_version,capabilities:[],applied:{"module":rev}}`，再发送静态遥测。

一次挑战不能用于另一条连接。认证阶段有超时；超过 60 秒未收到任何消息判定离线。Agent 每 20 秒心跳，断线指数退避（上限 60 秒，另加 0–30% 抖动）重新认证。在会话过期前主动重连，避免 HTTP 凭证过期导致对账持续失败。

## 消息目录

| 方向 | type | payload |
|---|---|---|
| 面板 → Agent | `auth.challenge` | `{nonce,server_time}` |
| Agent → 面板 | `auth.response` | `{server_id,signature}` |
| 面板 → Agent | `hello.ack` | `{server_time,session_token,session_expires_at}` |
| Agent → 面板 | `hello` | `{agent_version,protocol_version,capabilities,applied}` |
| Agent → 面板 | `heartbeat` | `{applied,uptime_secs}` |
| Agent → 面板 | `telemetry.static` | 系统、内核、架构、Agent 编译 ABI `libc`、Linux 宿主运行时 ABI `runtime_libc`、CPU 型号与核数、内存与磁盘总量、虚拟化、主机名、Agent 与模块版本、`ip_addresses`（IPv4/IPv6 字符串数组） |
| Agent → 面板 | `telemetry.metrics` | CPU 百分比、内存使用、load 1/5/15、磁盘使用、网卡累计和速率、TCP/UDP 连接数、运行时间 |
| 面板 → Agent | `manifest.changed` | `{rev}`，提示重新读取全量清单 |
| Agent → 面板 | `apply.result` | `{module,rev,op_id,status,healthy,error?}`，status 为 `applied` 或 `failed` |
| Agent → 面板 | `usage.batch` | `{epoch,seq,period_start,period_end,records:[{stat_name,uplink,downlink}]}` |
| 面板 → Agent | `usage.ack` | `{epoch,seq}` |
| 面板 → Agent | `retirement.request` | `{request_id}`，持久退役请求 UUID |
| Agent → 面板 | `retirement.result` | `{request_id,success,error?,receipt?}`，成功须携带匹配的签名回执 |
| 面板 → Agent | `runtime.path_probe.request` | `{request_id,expected,probe_id,expires_at}`，指定已签、已应用计划中的验证 UUID |
| Agent → 面板 | `runtime.path_probe.result` | `{request_id,request_digest,observed,probe_id,elapsed_ms,success,error}`，绑定实际 activation 与运行实例 |
| 面板 → Agent | `runtime.path_probe.ack` | `{request_id,request_digest}`，精确不可变结果已持久化 |

指标每 10 秒发送，采集失败字段省略，不用 0 代表未知。流量每 30 秒采集；上下载单位是字节，负数无效。epoch 为 UUID；seq 在本地持久递增。所有时间戳使用 UTC Unix 秒。

面板拒绝某个 `usage.batch`（字段无效、身份从未向该设备发布或同一 epoch/seq 内容改变）时整批回滚、不回 `usage.ack`，并记录告警日志，但不断开已认证连接；Agent 继续在本地 outbox 保留并重放该批次，后续合法批次照常入账和确认。

Linux 静态信息区分两种 ABI：`libc` 保留 Agent 自身的编译 ABI，`runtime_libc` 是独立探测的宿主运行时 ABI。静态 musl Agent 在 glibc 主机上报告 `libc:"musl",runtime_libc:"gnu"`。Agent 自动更新只依据 `os`、`arch` 与 `libc`，运行时清单结合宿主 ABI 选择兼容候选；两个字段互不覆盖。

`runtime_libc` 为 Linux 可选新增字段，识别成功取 `gnu` 或 `musl`；新 Agent 无法可靠识别宿主时兼容沿用自身编译 ABI。面板接受 `glibc` 作为 `gnu` 别名，非 Linux 设备不发送此字段。旧设备缺少字段时保留原 `libc` 选择路径；显式 null 或非字符串在消息解析时拒绝，显式 `unknown`、空字符串或未支持值的运行时清单返回 400，不将这些值当作字段缺失。

Linux 宿主 ABI 与 Agent 编译 ABI 不同时，运行时先保留旧的编译 ABI 完整标识、旧 `{arch}` 选择顺序，再尝试宿主 ABI。GNU 宿主上的 musl Agent 因此依次选择 `linux-musl-{arch}`、旧 `{arch}`、`linux-gnu-{arch}`；已通过兼容层运行在 musl 宿主的 GNU Agent 依次选择 `linux-gnu-{arch}`、旧 `{arch}`、`linux-musl-{arch}`，保证此前签名缓存仍按原摘要复验。两种 ABI 相同时，GNU 路径兼容旧目录，musl Agent 在 musl 宿主不使用 GNU 完整标识或 GNU 兼容目录。只有制品不存在时才尝试下一候选，校验失败不能降级。Agent 自身升级继续只用编译 ABI，不随 `runtime_libc` 改变。

## 已签运行计划中的具体出站验证

路径验证需设备声明 `runtime:path-probe-v1`，并具有精确 checkpoint 能力。请求不携带目标 URL、代理凭据或命令，只选择已签 `runtime-probes.json` 中的 UUID；`expected` 是完整健康 checkpoint。正常请求 60 秒，剩余期限不得超过 120 秒；Agent 与 apply/recovery 共用 gate，前后确认实例、配置和无未完成 intent，SDK 请求上限 5 秒。成功须包含同一 checkpoint 与 1 至 5000 毫秒结果；失败不含测量值，错误固定脱敏。结果先持久再发送，重复消息不换内容、不续期，ACK 后保留去重身份。该消息不推进恢复 floor，不允许把迟到或不同 activation 的结果用于新路径切换；具体原生方法及证明范围见 [ADR 0073](adr/0073-ordered-path-publication-and-native-probe.md)。

## HTTP 期望状态

下列接口使用 `Authorization: Bearer <session_token>`，凭证只能访问绑定服务器的资源。

- `GET /api/agent/v1/manifest` → `{rev,modules:{module:{kernel_version,artifact:{url,sha256,proof},config_rev,bundle_url,bundle_sha256,stats_listen}}}`。
- 配置包 URL → `{files:{"config.json":"配置文件文本"}}`。sha256 是 HTTP 响应原始 UTF-8 字节的 SHA-256 小写十六进制，不是重新序列化的摘要。
- `GET /api/agent/v1/artifacts/{name}/{version}/{arch}` → 制品原始字节。路径段限定安全字符；`arch` 是完整平台标识（例如 `linux-gnu-amd64`、`linux-musl-arm64`），或旧发布的 `amd64` / `arm64` 兼容键。所有下载均校验已签清单中的 SHA-256。

`proof` 为 `{metadata_json,checksums,signature}`；`signature` 保留完整四行 `SHA256SUMS.minisig`，正文是 `checksums` 原始 UTF-8 字节。已签清单绑定 metadata 原始摘要、制品路径与压缩包摘要，metadata 进一步绑定仓库、发布 tag、协议范围、版本、架构、格式、安装后二进制摘要和大小。新 Agent 在应用、缓存命中、恢复、回滚及诊断执行前都以构建时固定的多个公钥验证证明与实际内容，不能把本地 marker 中的未签摘要当作可信值。格式与信任根轮换见 [ADR 0017](adr/0017-signed-release-artifacts.md)。

字段缺省时旧消息仍可解析，但新 Agent 拒绝执行无 proof 的制品。签名能力为 `artifact:minisign-v1`；面板拒绝向未声明该能力的旧设备提供新 manifest、制品或新诊断任务，继续接受旧设备的状态、流量和确认，保留已运行配置。缺根或缺能力都不降级到仅 SHA256 校验。

清单 rev 单调增加，模块 config_rev 表示配置包版本。无部署时清单可以是 rev 0、空 modules。Agent 每 60 秒拉取全量清单，并响应变更通知；心跳版本不一致时面板补发通知。多个通知可合并，以最终读取的全量状态为准。

## 应用与计量语义

监控上报另有兼容的 HTTP 扩展：旧 `AgentSettings` 的字段保持不变，新 Agent 声明 `telemetry:live:v1` 能力，独立读取 `GET /api/agent/v1/telemetry-settings` 获得 `persist_interval_secs`（默认 60，范围 15–3600）。接口不存在或不可用时继续原持久化上传节奏。采样默认 1 秒，`upload_interval_secs` 默认 3 秒并用于新版实时上报；新旧面板与设备无需同时升级。配置提前保存不等于旧设备已经支持，后台按设备声明提示升级。

`POST /api/agent/v1/telemetry/live` 接受单个 `TelemetrySample`，返回仅表示实时缓存收到请求，不是历史 ACK；Agent 不能据此删除 SQLite outbox。原 `POST /api/agent/v1/telemetry` 仍提交最多 64 条的 `TelemetryBatch`，面板将去重收据、历史汇总、最新持久化样本和服务器网卡增量事务提交后才返回 `TelemetryAck`。时间戳始终为真实采样的毫秒值，实时重试或心跳不得将旧指标改为新采样。

实时缓存丢失不影响已有历史和账本；历史压缩不删除七天重放窗口内的去重身份，不将聚合速率反推为流量。每个设备只访问自身的配置与上报端点。详见 [ADR 0047](adr/0047-monitoring-refresh-history-and-channels.md)。

`apply.result` 中 op_id 对应本地意图。只有校验、原子切换、服务动作、健康检查都成功后才能报告 applied；失败应回滚并提供错误。面板只接受已经为该服务器发布的版本，不接受未来版本，旧回报不能覆盖较新已应用状态。

累计计数读取必须 reset=false。Agent 在同一 SQLite 事务内写基线和待发送差值。确认前持续重发；面板事务去重键为 `(server_id,epoch,seq,stat_name)`，持久化成功后回复 ack，重复批次仍回复 ack。Agent 收到相同 ack 多次是幂等操作。

运行时重载前采集终值，再换 epoch。无法读取终值时应阻止主动破坏旧计数；外部重启导致计数下降则开启新 epoch，并记录可能丢失窗口。Agent 自身重启不换 epoch，保留已写入本地数据库的基线和未确认批次。

统计用户名格式为 `u{user_id}_n{node_id}`，用于唯一定位用户与节点，不应从入站标签猜测归属。

## 一次性诊断外插

新增内容保持协议主版本 1。旧 Agent 不发送 `ip_addresses` 时按空数组处理，不声明诊断能力时面板不下发新任务。新 Agent 在 hello 的 capabilities 中声明 `diagnostic:nodequality`，仍独立声明已有运行时模块。

设备接口继续使用绑定服务器身份的 Bearer session：

- `GET /api/agent/v1/diagnostics` 返回该设备尚未终止的任务数组，每个为 `{id,plugin,version,artifact:{url,sha256,proof},timeout_secs,expires_at?,options}`。
- `POST /api/agent/v1/diagnostics/{id}` 提交 `{id,status,report?,error?}`。设备可提交的 status 是 `running`、`succeeded`、`failed`，最终报告为 `{text,report_url?}`。数据库持久化后返回 204；其他设备不能更新该任务，过期会话不能取回任务。

确认式取消是独立扩展，能力为 `diagnostic:confirmed-cancel`。管理员取消接口先持久保存 `cancel_requested` 再发送 `diagnostic.cancel.request={server_id,job}`，其中 job 是该服务器已有任务；协议不接受任意单元名。设备先保存取消意图、停止绑定单元并核实进程与挂载都已清理，再发送 `diagnostic.cancel.result={server_id,id,plugin,confirmed,report?,error?}`。只有经设备身份认证的 `confirmed=true` 使任务进入 `cancelled`；普通 `DiagnosticUpdate` 不能提交取消状态。

`GET /api/agent/v1/diagnostics/cancellations` 返回当前设备的待取消请求（最多 64 条），`POST /api/agent/v1/diagnostics/{id}/cancel-confirmation` 持久保存取消结果并返回 204。HTTP pending 与 Agent SQLite outbox 恢复断连和重启。确认前界面显示“等待设备确认取消”；负确认、过期或末尾自然报告不结束该状态，已有报告保留。重复请求和确认幂等，已自然完成任务拒绝新取消。缺少能力的旧 Agent / 服务后端明确不支持。具体清理证据与并发边界见 [ADR 0026](adr/0026-confirmed-diagnostic-cancellation.md)。

NodeQuality 的 plugin 标识为 `nodequality`，version 为固定上游提交加包装器版本（当前为 `a92fca6c0067df29ddd03fdc2fee6f3000f64545-r5`），制品同源、校验后安装。新任务 options 允许 `mode=daily|full`、`ip_version=both|ipv4|ipv6`、`network_mode=low|normal`、`upload_report=true|false`、固定 `environment_section=true`，日常另带来自该服务器已启用 TCP 拨测的白名单 `daily_targets`（最多4个、8KiB）。日常只接受 low/false，不执行硬件或上游脚本。`upload_report` 在管理员创建任务的 HTTP 请求中为布尔值，缺省 `false`；在公共任务中为固定字符串，缺少时新 Agent 按关闭处理。旧 Agent 拒绝新版本和未知选项，不通过忽略隐私选项继续运行旧包。升级必须先准备 r5 包；新面板只向已识别 Linux、声明 `diagnostic:report-sections` 和 `diagnostic:nodequality-modes` 的 Agent 创建 r5 任务。新 Agent 保留 r2/r3/r4/r5 已有 Started checkpoint 的收集与取消，旧报告内容保留。任务不携带任意命令、程序地址或自由 shell 参数。


临时安全门禁不修改上述任务序列化格式：新完整任务在两种创建入口都返回 409。NodeQuality 视图另返回 `full_ready=false` 与 `full_reason`；`plugin_ready` 只表示日常插件就绪。旧排队完整任务保存失败原因且保留 `agent_completed=false`，可接收迟到章节/报告及取消；旧运行任务仅向声明 `diagnostic:nodequality-full-start-gate` 的 Agent 重发，升级后的适配器拒绝 Preparing 完整任务的新执行，已有 Started 不重跑。门禁前已领取任务的旧 Agent 须升级或确认取消，面板不能撤回已返回的 HTTP。历史 `upload_report=false` 只关闭顶层公开上传，不能证明内层没有外发；见 [ADR0031](adr/0031-nodequality-full-start-gate.md)。


任务 ID 同时用于设备持久 checkpoint、独立服务及面板去重。先记录启动意图再创建 systemd 服务；Agent 重启检查已有服务并继续观察，不自动重复运行。启动边界状态不明或服务消失时回报失败，管理员可另发新任务。结果确认前保存并重传；终态不能被晚到的 running 覆盖。每台设备最多一个活跃任务。代理配置版本与用户流量周期不会因诊断任务变化。

IP 地址来自网卡和可选的 Agent `public_ips` 配置。面板仅向固定的 IPQuality 查询域名请求公网地址，私网、回环、链路本地等地址可展示但不参与外部查询。每个数据库分别保存结果或错误；未知风险不能填成零风险。

## 在线退役

设备在 hello 声明 `server:retire-v1`。面板删除在线服务器时先保存并发送请求，收到成功回执后才完成软删除；没有能力的在线旧设备返回升级提示。离线软删除不证明设备清理成功。面板认证注册、删除与回执提交共同串行，在签发会话前再次检查服务器和公钥。

Agent 收到请求后持久阻止新的受管操作，停止运行时与诊断，提交所有已持久用量，再清除本机身份、会话与受管运行配置；保留历史账本。相同请求可重试，不同请求不能覆盖未结束的退役。清理完成后进入终态，不再自动注册或恢复代理。

回执为 `{server_id,request_id,signature}`；签名对象按顺序拼接 UTF-8 `sinan-retirement-v1`、一个零字节、8 字节大端有符号 server ID、16 字节请求 UUID。使用原设备 Ed25519 密钥，签名为 URL-safe base64，无填充。Agent 在删除私钥前持久保存回执，但只在清理完成后发送。面板使用保留的公钥和已存在请求验签。

完成后的 Agent 也可向原绑定面板的 `POST /api/agent/v1/retirement/receipt` 发送该回执。此接口不需要 Bearer session；签名本身只授权对应退役确认，不能恢复设备会话。重复合法回执返回 204，错误回执拒绝。确认响应丢失时仍可恢复；未清理完成就被离线软删除的设备不具备此保证，需人工处理。详细崩溃与离线边界见 [ADR 0019](adr/0019-server-retirement.md)。


诊断章节回报与执行状态独立。`POST /api/agent/v1/diagnostics/{id}/sections` 发送 `{id,name,text,complete,revision,collected_at}`，章节名须已登记在任务的 `expected_sections` 中，UTF-8 文本不超过 64 KiB、单任务不超过 512 KiB。`revision` 是此任务此章节的递增版本，采集时间使用秒；相同版本同内容可重复提交，同版本不同内容拒绝，迟到版本或已完成章节的未完成版本不会覆盖已保存内容。HTTP 204 只确认所提交版本持久化，Agent 用 SQLite 保存未确认章节和已确认版本，断连或重启后继续上传，不重新执行测试。

任务历史在原 `report` 文本之外返回 `expected_sections`、`sections` 和 `report_completeness=empty|partial|complete|legacy`。执行 `status` 不用于推导完整度；失败、取消或截止后仍可接收已执行任务的迟到章节，独立显示已完成部分。旧文本保持原样，完整度标记为 `legacy`（未知），不补造章节结果。已删除设备不能上传章节。NodeQuality r3 包装器在每个阶段运行时保存私有目录内原子章节快照；同一固定上游的下一阶段日志或最终压缩包证明上一章节完成，缺失或无效 JSON 只能产生未完成预览。


## 共用诊断任务服务

管理员用 `GET /api/servers/{id}/diagnostics` 查看登记插件就绪状态及最近任务，`POST /api/servers/{id}/diagnostics/{plugin}` 提交插件参数。只允许已登记插件，所有创建入口共享服务器锁；旧 NodeQuality 路由保留。Agent 结果、章节、待取消及确认接口维持原设备范围认证。

`DiagnosticJob` 增量字段 `resource_budget` 为对象，包含 `memory_max`（字节）、`tasks_max`、`cpu_weight`、`io_weight`、`oom_score_adjust`。新任务需 `diagnostic:job-service`；旧字段缺失代表适配器原预算。Agent 在预检前验证并应用，只可收紧适配器准备的限制。任务 JSON 与历史表不迁移，旧设备回报的历史任务及章节仍可接收。
