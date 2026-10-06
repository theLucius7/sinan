# 仓库目录与维护约定

本页说明现有代码与文档的位置。使用方法从[文档导航](README.md)进入，架构和范围以 [AGENTS.md](../AGENTS.md) 与[各项 ADR](adr/README.md) 为准。

## 顶层目录

| 路径 | 职责 |
| --- | --- |
| `crates/` | Rust 工作区：公共协议、配置编译、面板、Agent、适配器及原生 TCP 工具 |
| `plugins/` | 插件面板业务、外部工具包装及固定来源材料；插件业务不回迁到核心 |
| `web/src/` | React 界面（简体中文/English）；前端依赖与构建由 Bun 管理 |
| `web/dist/` | 提交到仓库、由面板嵌入的构建产物；修改源码后生成，不手工编辑 |
| `deploy/` | Compose、服务定义、安装模板、生成后的独立 bootstrap 入口和发布公钥 |
| `scripts/` | [面板运维、接入与验收入口](../scripts/README.md)；包含已有 CI 包装脚本 |
| `tools/` | [构建、签名、发布、规则检查与隔离测试工具](../tools/README.md) |
| `tests/` | 仓库工具的 Python 回归；Rust 和前端测试各自随所属代码放置 |
| `docs/` | 使用说明、接口契约、ADR、验收记录与证据 |
| `.github/workflows/` | 远端构建和验证定义；当前暂停，不因本轮整理恢复 |
| `PROGRESS.md` | 历史完成项、证据和未验证范围；保留既有记录与链接 |

`target/`、`web/node_modules/` 和本机临时目录属于忽略的本地状态，不作为源码整理对象。已有迁移编号、公开安装脚本路径、签名制品结构和 ADR 文件名属于兼容边界。

## Rust 工作区与分层

| 模块 | 职责与依赖方向 |
| --- | --- |
| `protocol` | 面板与 Agent 的共享消息、能力、签名制品契约 |
| `compiler` | 从业务模型确定性地生成完整运行时配置包 |
| `panel-host` | 面板宿主：HTTP 服务、管理员会话、服务器、遥测、通知、任务、共用诊断服务和插件接口；工作区依赖仅 `protocol`，不认识具体业务插件 |
| `plugins/*/panel` | 业务插件 crate（sing-box、DDNS、阿里云）及云 API 公共库；工作区依赖仅宿主、`protocol`、`compiler` 和云 API 公共库，插件之间不互相依赖 |
| `panel` | 组装：登记业务插件并启动服务；保存唯一的迁移序列，保留原有 `sinan_panel::*` Rust 路径 |
| `agent-core` | 设备身份、传输、对账、持久状态、遥测、计量与制品；工作区依赖仅 `protocol`、`adapter-sdk` |
| `adapter-sdk` | 无状态适配器接口与共享模型 |
| `adapter-singbox`、`adapter-nodequality`、`adapter-tcpquality` | 运行时或工具翻译；工作区依赖仅 `adapter-sdk` |
| `agent` | 注册具体适配器、启动 core 的二进制入口 |
| `tcp-probe` | 原生 TCP 检测工具 |

服务器网卡总流量属于核心；代理用户、授权、订阅、套餐与代理流量属于 sing-box 插件。`agent-core` 和 `panel-host` 都不引入具体插件名称或代理业务类型。分层检查入口为 `tools/check-core-boundary.py`，同时检查两个核心目录的禁用词和各层 `Cargo.toml` 的依赖方向。

## 面板入口与插件

面板分为宿主、插件和组装三层（[ADR 0085](adr/0085-rearchitecture-plugins-sources-chains.md)）。`crates/panel-host/src/lib.rs` 声明宿主模块；`state.rs` 创建共享状态；`plugin_api.rs` 定义插件接口。`crates/panel/src/` 只负责组装：`lib.rs` 再导出宿主模块并保留原有公共路径，`plugins.rs` 登记业务插件，`main.rs` 启动服务与后台任务。`passkeys/` 提供共用 WebAuthn 验证、挑战和凭据存储，管理员包装在 `auth/`，代理用户入口、邀请和独立会话在 `plugins/singbox/panel/portal/`。宿主的 HTTP 路由在 `crates/panel-host/src/routes/` 按职责组合：

| 文件 | 注册的接口 |
| --- | --- |
| `routes/mod.rs` | 健康检查、各组路由、组装时传入的插件路由、前端兜底及全局请求体限制 |
| `routes/system.rs` | 登录/TOTP/管理员 Passkey、统计、汇率、设置与通知 |
| `routes/servers.rs` | 服务器、接入令牌、遥测配置、命令、周期拨测和流量矫正 |
| `routes/diagnostics.rs` | IP 查询、共用诊断服务、旧诊断路径与 TCP 目标 |
| `routes/agent.rs` | Agent 认证接口、上报、待办、结果、配置包和运行时下载 |
| `routes/artifacts.rs` | 管理员制品目录、导入、版本查询及公开安装入口 |

路由文件只组合处理函数，鉴权和业务校验仍由原处理函数负责。`sinan_panel::router`、`AppState`、`AgentConnection` 及旧代理业务 Rust 导出继续可用。新增接口按职责归组，不再把所有接口堆入 crate 根文件。

插件接口：

- 宿主通过 `plugin_api::PanelPlugins` 把 Agent 通道上的用量入账、模块清单、配置包和运行活动查询交给插件。组装层在构造路由和启动后台任务时登记一次。
- 插件路由由组装层传入宿主的 `router`；插件后台任务由组装层分别守护，一个插件崩溃不会停掉其他插件。
- `plugins/singbox/panel/`、`plugins/ddns/panel/`、`plugins/alicloud/panel/` 各自是独立 crate，只经宿主公开接口使用面板能力。`plugins/cloud_api/panel/` 是云 API 公共库，不是独立产品插件。
- 诊断插件（IP 质量、NodeQuality、TCP 质量）暂时仍由宿主的 `diagnostic_plugins.rs` 通过 path 编入，共用诊断服务继续负责生命周期、预算、取消和历史。它们与宿主的 IP 质量和诊断类型互相引用，拆成独立 crate 前需要先把共用类型移入宿主接口。

数据库迁移保持在 `crates/panel/migrations/`，按既有序列追加；宿主通过 `sqlx::migrate!("../panel/migrations")` 嵌入这一条序列，插件 crate 的数据库测试也指向它。不能为整理文件而重命名、合并或修改已发布迁移。

## 前端入口

| 路径 | 职责 |
| --- | --- |
| `web/src/App.tsx` | 会话读取、失效处理、公开看板访问控制与顶层页面组合 |
| `web/src/app/routes.ts` | 解析 URL，复用看板/插件的严格路径解析及旧链接兼容 |
| `web/src/app/navigation.ts` | 后台侧栏分组、名称与当前页面归属 |
| `web/src/app/AdminPage.tsx` | 按解析结果选择页面，保留服务器筛选和组件重挂载边界 |
| `web/src/app/AdminShell.tsx`、`Login.tsx` | 后台布局与登录表单 |
| `web/src/pages/` | 服务器、系统设置、诊断、监控等核心管理页面 |
| `web/src/plugins/` | 插件目录及 sing-box、DDNS、阿里云业务界面 |
| `web/src/display/`、`statistics/` | 独立服务器看板与统计展示 |
| `web/src/api.ts`、`hooks.ts`、`components.tsx` | 共享请求、状态钩子和通用组件 |
| `web/src/i18n.tsx` | 语言上下文、浏览器语言选择、管理员偏好同步及静态界面词典 |

后台分区导航统一使用 `styles.css` 中的 `.ui-tab-list`，按钮通过 `aria-pressed`、页面链接通过 `aria-current="page"` 标记当前项；沿用“管理与安全”的浅底、细边框、6px 圆角与绿色选中态。`.button`、`.ui-button`、`.text-button`、`.icon-button` 和 `.back-link` 共用边框、圆角、悬停、禁用和键盘焦点规则，提供普通、紧凑与图标三种尺寸；主操作与危险操作保留颜色语义。文字操作也使用紧凑描边按钮，按钮组允许换行。页面样式只保留分区间距，不再单独定义导航按钮颜色、尺寸或选中轮廓。

Hash URL 是书签与兼容入口。新增页面要同时考虑路由、导航、管理员访问边界；公开访问只放行明确的看板路由，不据路径前缀推断权限。

## 验证与文件维护

- Rust 单元测试随模块放置；HTTP/PostgreSQL、协议与编译集成测试位于对应 crate 的 `tests/`。
- `web/tests/*.test.ts` 使用 `bun test`；`web/tests/*.mjs` 是构建页面的 Playwright 回归，API 使用隔离夹具。
- 仓库工具回归位于 `tests/test_*.py`、`tools/test-*.py` 和 `scripts/test-*.py`；具体入口见脚本导航，避免无差别执行实机验收驱动。
- 修改前端后先生成 `web/dist`，再编译/测试嵌入它的面板。完整本地检查命令见[开发指南](dev.md)。
- 使用文档放在 `docs/`，新的设计决策追加 `docs/adr/`，验证记录放在 `docs/acceptance/` 并标明源码和未验证范围；更新相应索引。
- 部署模板及生成入口有摘要、签名和旧版本依赖；通过既有生成工具更新，不按普通重复文件删除。生产数据、真实凭据和临时日志不进入仓库。

本轮只整理代码组合入口与文档导航；现有脚本、迁移、安装入口和历史验收记录继续使用原路径。
