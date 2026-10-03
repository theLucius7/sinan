# 离线 NodeQuality 工具链准备与当前验收边界

主线 PR #137 的原默认版本 r19 保持原字节；2026-10-03的新默认r22另见[当前分项记录](nodequality-r22-upload-and-history.md)。r20 是显式离线准备制品，由完整 canonical r19 严格派生，包含 `nodequality`、`rootfs.tar.gz`、`rootfs-manifest.json`。r21 是另一个显式选择的正式节点 API 查询制品，不使用 rootfs。旧 r2–r19 的版本、签名文件及历史结果不改写。

本轮窄整合了原未合入分支 `de54084` 中的离线准备代码；其旧 r18 身份与主线不同，因此使用新 r20，保持主线 r19 的完整执行准入、正式日常 IP helper 和来源策略。原分支的测试统计不视为当前主线通过；组合编辑期间没有运行测试，冻结后的当前输入检查与统一执行收据见 [集成验收](remaining-issues-20261002.md)。

设备侧按 signed job 的版本决定辅助文件集合，流式下载并逐一核验签名长度、SHA256、成员数和完整总量。rootfs 只接受有界 gzip/USTAR、完整目录清单、逐文件摘要与合法相对链接，拒绝设备、FIFO、扩展头、路径穿越及额外成员。验证、展开和发布均在本次私有目录内，失败或取消只回收自己创建的资源。

工厂准备工具要求真实 Debian 12 签名链、全部固定二进制包及对应源码、独立审阅的 keyring/builder 身份；不下载、不自动信任镜像、不执行在线脚本。原生构建只使用固定本地包镜像和隔离 namespace，保留包状态及许可库存。发现残留挂载时保留失败目录，禁止递归删除挂载内容。打包重新认证 prepared/export 绑定，并要求整个外层制品不超过原 256 MiB 边界。

签名表示维护者绑定了相应字节及准备记录，不能代替实际来源、许可、构建器身份或复建证据。小型 TEST_ONLY 夹具也不代表真实 Debian 签名或完整验机通过。当前没有收到适用的 Geekbench/Ookla 再分发、自动运行和禁上传授权证明，未执行这些工具；nexttrace/GPU 等剩余工具闭包仍须补齐。原完整功能记录保留，full 在面板、Agent 和 r19/r20/r21 wrapper 继续拒绝启动。

#28、#65、#66、#82 只有实际双架构合法工具链、完整故障矩阵及专用 Debian 服务器保护/取消/心跳/持续代理联合验收满足后才能关闭。本准备层不开放 full，不发布正式 Release，不部署生产。具体来源契约见 [ADR 0049](../adr/0049-nodequality-offline-rootfs.md)。

## PR #151 的独立 native 准备入口

本节原整合输入为默认 r19、显式 `sinan-native-r1`；r20 离线派生、r21 typedQuery 和 `offline-rootfs-r1` 不重命名。2026-10-03 后当前默认 `tools/build-nodequality.sh` 使用 r22，显式 `tools/build-nodequality-native.sh` 使用 native-r2；修改后的当前 wrapper/report 不重标为历史身份。两套必要历史 runner/report 及共享 rootfs 以精确字节保存，并按固定摘要读取；`tools/build-nodequality-native-offline.py` 仍只从原 native-r1 精确组合派生 `offline-rootfs-r1`，使用独立的 `nodequality_native_rootfs_artifact.py` 核验。两条离线身份均精确包含三个普通文件；r19/r21/r22/native-r1/native-r2 的 runner-only 身份不能携带离线辅助文件。

新增 IPQuality 最小闭包的公开 proof 必须逐字绑定 prepare、build、export、嵌入 rootfs 的 provenance/runtime manifest 以及最终制品；父材料复验和离线重放仍是独立工厂门禁。公开 proof 不包含私有重放位置，不审批 builder、许可、复建或 full。新增受控托管工具只接受专用 Linux 的私有 TEST_ONLY namespace、固定 panel HTTPS origin 和普通 enroll `--token=` 参数；工具契约不能冒称 Agent/代理实机验收。

2026-10-03集中修改冻结后，已使用逐份匹配原source-lock的17份固定本地材料实际验证历史组合：r20派生12项、native-offline派生12项、r21查询派生5项全部通过，包含真实minisign对TEST_ONLY材料的签名与拒绝检查。这29项已经包含在[当前111项固定源定点验证](nodequality-r22-upload-and-history.md)中，不重复累计。完整来源摘要及整体收据见[本轮统一验收](all-open-issues-20261003.md)。没有运行实际rootfs原生复建、native controller或完整验机。下面保留作者旧步骤的原始统计及输入边界，旧 r17/r18 身份属于该历史分支，不属于当前 main 的 r17/r18，不能用于认证新增组合。

## 作者旧离线步骤归档

### 原步骤统一验收结果

输入为 `e809395676ef1f4436d4448c3a72600eb6de990f` 加本步骤冻结修改，完整摘要和原始收据摘要见[机器记录](evidence/nodequality-offline-rootfs-r18.json)。最终 Rust 的 374 个输入前后相同；原 r17 的 23 份来源/策略/模板与默认构建脚本逐字保持基线。

| 范围 | 实际结果 | 认证边界 |
| --- | --- | --- |
| macOS Python、canonical 派生与 Release | 90 个不同方法，77 通过、13 条件跳过 | 9 个 Linux 专项在下行 Debian 12 执行；4 个既有 Release 条件仍未执行 |
| Debian 12 小型归档、来源/导出契约、签名 | rootfs 20、builder 26、artifact 12，58 通过、零跳过 | 原生 Linux 路径、TERM/HUP 子进程回收与展开取消实际执行；官方索引签名状态是自有 mock，未运行 mmdebstrap |
| Rust/PostgreSQL workspace/all-targets | 483 通过、0 失败、16 条件忽略 | 新流式缓存 4 个函数、版本清单 1 个函数的 4 个真实签名组合及 r18 日常/历史/full 门禁通过；忽略不计通过 |
| 静态及格式 | fmt、全 targets Clippy、core boundary、diff check 通过 | 本地冻结输入，不是 GitHub CI |

Debian 12 验收单元实际限制内存 256 MiB、swap 0、进程数 64，使用独立网络与挂载命名空间、无外部路由。峰值内存 51,023,872 B、峰值进程数 5，OOM 计数为零；真实 minisign 0.11 对公开 TEST_ONLY 夹具签名和验签。单元、子进程、挂载、cgroup 与临时目录均无残留，SSH 的 PID/重启数和系统启动标识不变。这些是小型夹具结果，未运行正式 Agent/代理的完整联合压测。独立 PostgreSQL 已停止，PID、监听端口和 socket 均无残留。

初次 macOS 夹具因 `/var` 别名被禁止跟随链接而失败，修正为真实临时路径；私有驱动的 Release 测试路径笔误、临时 PG socket 路径过长，以及一次 Clippy 嵌套条件失败均保留原记录。只补验失败或受修复影响的范围；产品 Python、节点场景没有因 Rust 条件格式修正重跑。工作区完整 Rust 测试只实际执行一轮。

四源码工作流仍为 `disabled_manually`，不恢复 CI。实际 snapshot/package/source 闭包、独立 builder 审批、合法完整工具链、双架构真实构建/复建、专用节点 Agent 心跳和持续代理流量联合负载仍未完成，完整验机门禁保持关闭。
