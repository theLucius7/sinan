# NodeQuality 报告采集器的运行所有权与异常收尾

主线整合说明：下文及机器收据是作者原分支的冻结证据，本聊天未重演其历史 PID 清理。2026-10-03 补修覆盖当前原 `report.py`/`runner.sh.tmpl` 和独立 `native-report.py`/`native-runner.sh.tmpl`，新身份分别为 r22/native-r2；必要的 r19/native-r1 历史源码素材严格固定，r20/r21/offline-rootfs-r1 的原身份及 full 门禁保持。新输入需要单独验证，不能把下文 74 项直接列为本聊天的通过数量。

本步骤修复 [Issue #152](https://github.com/theLucius7/sinan/issues/152)，承接 [集成交付索引](integrated-delivery.md)。基线 `6eaa1728d4249920be867ab9644726afadfccba0` 的只读本机盘点先发现 20 个具名旧 inert fixture 的 `report.py watch-sections`；最后全进程核对另外发现同一批历史进程组中的 6 个普通临时目录 fixture。共 26 个，全部 PPID=1，全部工作目录已删除，启动时间均早于本步骤。两次现场各在停止对应进程之前固定到私有证据；它们不代表仍在运行的完整验收。

## 实现

- `watch-sections` 必须显式绑定真实直接父进程的规范 PID；父进程退出／被 KILL 后退出。工作区与 `.runner` 各自的普通目录设备／inode 绑定本次运行，删除、替换或符号链接不会继续采集。
- watcher 显式处理 TERM／HUP／INT，不继承启动器的忽略策略；轮询使用非阻塞章节锁，忙锁不阻止检查所有权。capture／render 和同步章节 API 的串行锁合同保持。
- wrapper 在启动／记录 watcher PID 的窗口暂存取消意图，先停止并回收 watcher，再保存最后可取得的快照；清理快照不等待其他章节锁。已经完成的章节、原始报告及上游退出状态保持。
- inert wrapper fixture 在独立自有会话中执行；正常、超时、异常及外层取消均安排确认收尾。自有子进程确认退出后才删除临时目录，失败和清理失败分别保留，不终止共享终端进程组或外部 sentinel。

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
