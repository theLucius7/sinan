# NodeQuality 报告采集器的运行所有权与异常收尾

主线整合说明：下文及机器收据是作者原分支的冻结证据，本聊天未重演其历史 PID 清理。2026-10-03 补修覆盖当前原 `report.py`/`runner.sh.tmpl` 和独立 `native-report.py`/`native-runner.sh.tmpl`，新身份分别为 r22/native-r2；必要的 r19/native-r1 历史源码素材严格固定，r20/r21/offline-rootfs-r1 的原身份及 full 门禁保持。新输入需要单独验证，不能把下文 74 项直接列为本聊天的通过数量。

本步骤修复 [Issue #152](https://github.com/theLucius7/sinan/issues/152)，承接 [集成交付索引](integrated-delivery.md)。基线 `6eaa1728d4249920be867ab9644726afadfccba0` 的只读本机盘点先发现 20 个具名旧 inert fixture 的 `report.py watch-sections`；最后全进程核对另外发现同一批历史进程组中的 6 个普通临时目录 fixture。共 26 个，全部 PPID=1，全部工作目录已删除，启动时间均早于本步骤。两次现场各在停止对应进程之前固定到私有证据；它们不代表仍在运行的完整验收。

## 实现

- `watch-sections` 必须显式绑定真实直接父进程的规范 PID；父进程退出／被 KILL 后退出。工作区与 `.runner` 各自的普通目录设备／inode 绑定本次运行，删除、替换或符号链接不会继续采集。
- watcher 显式处理 TERM／HUP／INT，不继承启动器的忽略策略；轮询使用非阻塞章节锁，忙锁不阻止检查所有权。capture／render 和同步章节 API 保持串行发布，锁等待最多两秒，超过期限保留已有章节并报错。
- wrapper 在启动／记录 watcher PID 的窗口暂存取消意图，先停止并回收 watcher，再保存最后可取得的快照；清理快照不等待其他章节锁。已经完成的章节、原始报告及上游退出状态保持。
- inert wrapper fixture 在独立自有会话中执行；正常、超时、异常及外层取消均安排确认收尾。自有子进程确认退出后才删除临时目录，失败和清理失败分别保留，不终止共享终端进程组或外部 sentinel。

## PR157 主线整合补修：读取与发布同一目录对象

本聊天审阅发现，只有章节发布固定目录 FD 仍不足以保护源读取：根目录在源文件打开前替换时，按路径枚举结果可读取新任务；普通文件在路径检查后改为 FIFO，也可能使采集器阻塞。

当前 r22/native-r2 两套 reporter 的单次 snapshot 与 live watcher 从持有的原根目录 FD 枚举并逐层打开 `.nodequality*`、`BenchOs`、`result`；每层禁止符号链接、核对所有者与不可被其他账户写入的权限，并比较打开前后的设备/inode。非目录组件整棵跳过，不能回到祖先采集日志。源文件通过该结果目录 FD 以 `NOFOLLOW|NONBLOCK` 打开，再以同一 FD 核验普通文件、所有者、权限及大小，不另开路径；活跃日志只读有界前缀，JSON 与压缩包保留完整大小门禁。

每个最多 64 KiB 的源读取块之前及源读取完成后检查单调两秒快照期限。live watcher 同时复核真实直接父 PID、停止信号、根目录和 `.runner` 当前身份；取消或目录替换后丢弃尚未发布的字节。最终原子替换即使与目录替换发生竞争，也只落到持有的原目录 FD。capture、响应记录、stream-log 与 render 也在输入读取前绑定输出目录 FD，之后读取、写入和移除上传缓存均使用该对象，不能写入同名新任务目录。stdin 的执行期限继续由已有外层 wrapper／传输监督承担；这里的逐块检查是协作式取消，不将它当作 Linux/systemd 强制停止或完整验机证明。

共用回归新增根目录在源目录／源文件打开前替换、嵌套结果目录打开前替换、普通文件转 FIFO、非目录祖先日志、逐块取消／期限、四类 collector 读取后根替换和串行锁有界等待。两套入口各自执行同一完整回归。实现、测试代码及本节先集中完成；下文历史 74 项及作者其他收据不认证本次输入。`historical-r19` 与 `historical-native-r1` 固定素材未修改。

本聊天集中验证中，两套 watcher 首轮各 23 个完整方法通过；同一个解释器 metadata 夹具在 macOS 的 `/var`→`/private/var` 规范路径上各失败两个子例。修复仅将夹具临时目录 `Path(name)` 改为 `Path(name).resolve()`，保留可信框架元数据、外部解释器拒绝、执行 mode 与所有权的全部断言。实现字节、历史 helper 与 bootstrap 未变；两套完整 watcher 范围各 24 个方法、60 个子例补验通过，0 失败／跳过。首轮四个失败子例单独保留，不能称首次全通过。

原功能冻结库存 `9509bc8e34cfc2e9f2c1f236578245ec388d54563e656db3183eef4db2fbab7c` 未覆盖或改写；另存夹具补修库存 `be7db2e5bcee80dd26b73aa12b6184c6ef9c49953d50fcbe16685ab094a8a4cd`，1138 份输入只有共享 watcher 夹具增加 10 字节。完整补验及选定 GNU 条件的收据 SHA256 为 `231c2b8cfe6a3f02200290fb0df0a7ec9afe1fc2ff6a649657c2b6e25d5629c6`。本次是本地自有进程与私有报告验证，不签收 Linux/systemd、完整 NodeQuality 或生产能力。

## 集中验收及证据边界

本整步的源码、回归代码和说明完成后才冻结并集中验收。新回归使用真实 Python／Bash 小进程及私有文件，不执行上游硬件、公共查询或上传；覆盖父退出、信号、忙锁、目录身份与 fixture 异常，历史 orphan 仅在逐个核对原始 PID／启动时间／命令身份后清理。

最终冻结 784 份功能输入，SHA256 `504880b192ff8ee705774fbe80e8d3c5e52a651c896c124771a214ffb582a623`；相对前一步只改 reporter、wrapper 和三套 fixture，新增共享 fixture helper 与 watcher 回归。验收后所有冻结输入逐字保持，未重跑无关 Rust／前端测试或构建。

| macOS ARM64 集中范围 | 结果 |
| --- | --- |
| 报告与 wrapper，以及新增 owned-process 回归 | 37 通过，含 3 个新增收尾方法 |
| 固定来源包装与实际 shim | 16 通过 |
| 报告策略与原始调用者输出 | 14 通过 |
| 真实 watcher 生命周期 | 7 通过，7 份独立清理收据确认直接子已回收，外部 sentinel 保持 |
| 合计 | 74 个不同方法通过，0 失败，0 跳过 |
| 历史残留收尾 | 20＋6＝26 个原 PID 均重新核对启动时间、完整命令及失去父进程／目录；TERM 后逐个 KILL，确认原执行进程已退出，最终报告 watcher 为 0；未发送进程组信号、未删文件 |

原有恶意重复 ZIP 名夹具的 `UserWarning` 保留，不声明零警告。私有完整日志、原现场和清理材料保留；公开摘要见 [机器收据](nodequality-watcher-lifecycle-local.json)。本步骤不认证当前 Linux 原生重建、真实注册 Agent 的取消／重启／断连／挂载清理矩阵或完整硬件联合负载。完整 NodeQuality 的工厂与许可门禁保持，CI 继续暂停，仍使用同一个集成 PR。
