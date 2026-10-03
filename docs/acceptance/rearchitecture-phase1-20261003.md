# 2026-10-03 重新架构阶段一：插件编译边界

这是用户确认“先做阶段一、二”后的第一个大步骤，在集成分支 `claude/sinan-scan-refactor-odrgr3` 上进行，起点是提交 `15fc71b`。设计和实施说明见 [ADR 0079](../adr/0079-rearchitecture-plugins-sources-chains.md)。

所有修改先集中完成并冻结，然后统一验证；验证中发现的问题修复后，只补验受影响的范围。远端 CI 继续暂停，未触发、重跑或恢复。没有签署、发布、部署，也没有访问真实设备或生产面板。

## 修改内容

- **面板宿主 `crates/panel-host`：**
  - 原 `crates/panel/src` 中除入口和插件桥以外的模块整体移入（git 记为重命名）。
  - 新增 `plugin_api.rs`：宿主经它调用用量入账、模块清单、配置包和运行活动查询。
  - `router` 改为接收组装层传入的插件路由。
  - 宿主不再引用任何业务插件。NodeQuality 改为经插件接口查询运行活动。
- **业务插件 crate：**
  - `sinan-plugin-singbox`、`sinan-plugin-ddns`、`sinan-plugin-alicloud`，以及云 API 公共库 `sinan-cloud-api`。
  - 源码位置不变，只把指向面板内部的路径改为指向宿主公开接口。
  - 插件实际用到的宿主函数、结构和模块由 `pub(crate)` 改为 `pub`，行为不变。
- **组装 crate `sinan-panel`：**
  - `lib.rs` 再导出宿主模块和插件，原有 `sinan_panel::*` 路径不变，集成测试没有改路径。
  - `plugins.rs` 实现插件接口并登记一次，分别守护各插件的后台任务。
- **迁移：** 仍是一条序列，留在 `crates/panel/migrations`；宿主和插件的数据库测试显式指向它。没有新增或修改迁移。
- **分层检查：**
  - `tools/check-core-boundary.py` 增加面板宿主目录的禁用词检查，宿主的例外表达式逐条列出。
  - 新增各层 `Cargo.toml` 依赖方向检查：Agent 核心、适配器、面板宿主、业务插件。
  - `tests/test_core_boundary.py` 增加对应用例，包括伪造反向依赖的反例。
- **其他：** 两处读取 Rust 源码的测试（PowerShell 引导、IP 质量字段）改用新路径。`AGENTS.md` 分层规则、`docs/repository.md`、`tools/README.md` 同步更新。

## 统一验证

环境：本机 Rust 1.97.0，PostgreSQL 16（专用临时实例，回环 55432 端口），Bun 1.4.2，Python 3.11。

- **格式与静态检查：**
  - `cargo fmt --check`、`git diff --check` 通过。
  - 全工作区全 targets Clippy（warnings 视为错误）：
    - 首轮编译失败。宿主中有 4 处只被插件使用的 `pub(crate)` 项，移出后被判为未使用。
    - 第二轮又暴露插件调用的宿主私有方法，以及 sing-box 插件只在测试中使用的 `config` 再导出。
    - 按编译器指出的位置放开可见性、把该再导出限定为测试后，第三轮通过。
  - `Cargo.lock` 只新增 5 个工作区路径 crate，没有新增或升级外部依赖。
- **分层检查：** `tools/check-core-boundary.py` 通过，覆盖两个核心目录和依赖方向；`test_core_boundary.py` 8 项通过。
- **Rust 与 PostgreSQL：** 新拆出的 crate 与组装 crate 一起运行，6 个 crate 共 79 组结果，553 通过、0 失败、7 条件忽略。
  - 单元测试 242 项：宿主 104、sing-box 71、阿里云 32、DDNS 29、云 API 6。
  - 组装 crate 的 66 个集成测试目标：311 通过、7 条件忽略，其中包括嵌入前端的 `frontend` 目标。
  - 合计与拆分前（合并主线后）`sinan-panel` 的 553 通过、7 条件忽略一致。
- **前端：**
  - 改了路径的 `quality.test.ts` 通过，共 5 项、931 次断言。
  - 前端源码没有改动，`web/dist` 不变，浏览器回归不受影响，本轮没有重跑。
- **仓库 Python 回归：**
  - `tests/test_*.py` 共 185 项，失败 4 项、跳过 15 项。
  - 失败的 4 项都在 `test_bootstrap.py`：独立引导脚本要求有运行中的 systemd 或 OpenRC，本容器没有。
  - 在未修改的 `15fc71b` 工作树上重跑 `test_bootstrap.py`，同样是这 4 项失败，与本轮改动无关。
  - `tools/test-build-scripts.py`、`tools/test-init-env.py` 通过。
  - 改了路径的 PowerShell 启动器用例在本机被跳过（需要 PowerShell）；只确认了新路径的文件存在。

## 未验证范围

- 远端 CI 继续暂停，本地结果不代表 main 全绿。
- 浏览器回归没有重跑；前端源码和 HTTP 接口没有改动。
- 三个诊断插件仍由宿主通过 path 编入，未拆成独立 crate，也不在宿主目录的禁用词检查范围内。
- 插件登记依赖组装层在构造路由和启动后台任务时调用。只构造 `AppState`、不经路由直接调用宿主 Agent 处理函数的嵌入方式，会得到宿主的保守默认结果。
- 没有在真实设备或生产数据上运行。
