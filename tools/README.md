# 构建与验证工具导航

本目录主要服务于维护者，命令在仓库根目录运行。面板日常安装和升级入口在 [scripts/](../scripts/README.md)，完整步骤见[开发指南](../docs/dev.md)和[签名发布](../docs/release.md)。

## 构建与制品

| 工具 | 用途 |
| --- | --- |
| `build-agent.py`、`build-agent.sh` | Agent 平台构建及打包入口 |
| `build-singbox.sh`、`build-runtime-native.py`、`singbox-builder.Dockerfile` | 固定运行时源码与平台构建 |
| `build-tcp-probe.py`、`tcp_probe_artifact.py`、`tcp_probe_notices.py` | 原生 TCP 工具制品、元数据与许可 |
| `build-nodequality.sh`、`build-nodequality-offline.py`、`build-nodequality-node-query.py` | NodeQuality 制品及独立节点查询工具 |
| `nodequality-rootfs-build.py`、`nodequality-rootfs-collect.py`、`nodequality_rootfs_artifact.py` | 离线依赖材料、rootfs 构建及制品检查 |
| `artifact_manifest.py`、`release.py`、`publish.py` | 清单、签名、Release 与发布操作 |
| `render-bootstrap.py`、`render-bootstrap-powershell.py` | 从模板和受控源码生成 `deploy/bootstrap.sh`、`deploy/bootstrap.ps1` |
| `bootstrap.py`、`legacy_agent_checkpoint.py` | 安装器与旧版本检查点支持 |

`tools/licenses/` 存放构建中使用的许可材料。制品元数据与固定来源须随对应构建更新，不手动改摘要绕过验证。NodeQuality 离线材料准备不等于完整执行能力已经通过实机签收。

## 本地规则与回归

- `check-core-boundary.py`：检查 `agent-core` 与面板宿主的禁用词，以及 Agent 核心、适配器、面板宿主和业务插件 `Cargo.toml` 的依赖方向。
- `verify-release-runtime.py`：核验 Release 中运行时与声明的一致性。
- `test-*.py`：同目录工具、策略、构建脚本和夹具的回归；根 `tests/test_*.py` 也覆盖部分工具。
- `test-*.cjs`：既有前端浏览器夹具；较新的前端回归位于 `web/tests/`。
- `ci-run.py`、`ci-release-fixture.py`：已有 CI 调用及公开 TEST_ONLY 夹具支持，不能用于生产签名。

## 隔离环境与实机驱动

`agent-smoke.py`、`native-service-smoke.py`、`openrc-smoke.py`、`openrc-job-smoke.py`、`acme-smoke.py` 涉及实际进程、服务或容器，按[设备平台说明](../docs/platforms.md)和对应 CI/验收文档准备环境。

`p0-joint-load.py`、`probe-lease-acceptance.py`、`carrier-monitoring-acceptance.py`、`prepare-native-tcp-acceptance.py`、`prepare-plugin-install-acceptance.py` 属于指定场景的验收与准备驱动；不要把它们当成无需条件的通用测试命令。执行范围、资源预算和证据见[验收索引](../docs/acceptance/README.md)。

## 文件放置原则

新工具按用途放在现有目录内，与对应回归及说明一并维护。生产插件执行逻辑位于 `plugins/`，面板/Agent 业务逻辑位于对应 Rust 模块，不因工具语言相同就移入本目录。已有脚本路径、生成入口和发布元数据保留兼容；当前整理不重写语言或改变安装依赖。
