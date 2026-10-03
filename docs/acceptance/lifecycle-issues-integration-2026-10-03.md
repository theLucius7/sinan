# 诊断、拨测许可与 NodeQuality 采集器生命周期整合

本记录对应 [#143](https://github.com/theLucius7/sinan/issues/143)、[#144](https://github.com/theLucius7/sinan/issues/144) 与 [#152](https://github.com/theLucius7/sinan/issues/152)，纳入[全部开放 issues 集成交付](all-open-issues-20261003.md)。本轮先集中修改源码、回归用例与文档，修改期间没有运行测试、构建、实机验收或 CI。整个集成功能输入冻结后才统一验证，集中修复首轮错误后只补受影响范围。本记录使用本轮最终结果，旧记录的通过数量不认证新输入。

## 诊断清理所有权（#143）

现有实现已经先持久保存自然终态与报告，再取得停止和强清理证据，最后原子释放活动任务。取消结果、活动检查点与 done 账本使用同一状态锁；取消接管后丢弃旧观察协程。历史任务取消不阻塞当前任务保护，后端清理证明能力失效时仍尝试停止，证据未知则保留占用。原结果和未验范围见 [诊断完成专项记录](confirmed-diagnostic-completion.md)。

本轮静态审阅发现保存目标检查遗漏空 UUID：损坏检查点若将任务、单元名、目录及终态同时改成规范空 UUID，原检查仍接受。现在在任何状态、停止或挂载证明操作之前拒绝该身份。损坏目标矩阵增加这种全部字段一致的空身份，要求活动记录保留、外部服务调用和终态排队均为零。

## 同会话多许可收据（#144）

现有实现已移除一天离线权限，使用绑定设备、修订号与连接会话的最多 90 秒许可；冷启动、断连、GET 拒绝、换会话和在途取消回归保留，原结果见 [拨测许可专项记录](authorized-probe-leases.md)。

本轮静态审阅发现 `last_accepted` 仅保存最近一次收据。同会话收到 A、B、A，且 A、B 为同次配置同秒签发时，B 会使 Agent 忘记 A 的原字节和单调期限；面板时间偏移重校准后，最后的 A 可被重新计时。

现在保存同会话最多 64 个仍可合法重复领取的许可收据。相同身份保持原字节，期限只能缩短。新签发时间经持久高水位验证且超过旧许可绝对期限后，才回收旧收据。GET 错误保留收据，会话换代清空执行权限与收据；容量不足时拒绝新许可并撤销执行，不先写入高水位。

新增回归覆盖 A→B→A 与时间偏移重校准、非相邻身份期限改写、64 个同秒收据容量拒绝，以及签发前进后释放旧收据并拒绝旧许可。只使用本地状态与自有夹具，不探测第三方。

## 原 wrapper 采集路径（#152）

此前整合将生命周期修复放入 native reporter/runner，原 `report.py` / `runner.sh.tmpl` 仍存在无父退出条件的 watcher。本轮补齐默认新版本的原 wrapper 路径；旧制品精确源码只供历史身份复核，不作为新版本运行证据。

采集器绑定规范的真实直接父 PID，以及工作目录和 `.runner` 的设备/inode。父退出、目录消失或替换时退出，TERM/HUP/INT 使用自身处理。live watcher 和最终清理快照采用非阻塞章节锁。wrapper 在 spawn 与保存 PID 窗口暂存取消意图，先确认 watcher 停止并回收，再采集快照和删除本次目录；无法确认时保留目录和错误。已保存章节与失败日志保持。

原 wrapper、固定来源和报告策略三套 fixture 使用共用 `OwnedProcesses`，通过独立会话、有界输出和期限，在所有终态清理自有进程组。新增回归覆盖超时、外层异常、外部 sentinel，以及 Linux 下仅 KILL wrapper 父进程后，采集器在组清理前自行退出。`tools/test-nodequality-watcher.py` 复用生命周期套件并实际执行原 `report.py`，覆盖父 TERM/KILL、继承忽略信号、忙锁、目录删除/替换、已有章节和严格 readiness。

整合静态交叉审阅还发现，原 reporter 与 native reporter 都只在快照前比较路径 inode，快照读取后仍按路径创建锁与章节；此期间工作目录被替换时，旧采集器可能写入新任务目录。两种 reporter 现在都持有原工作目录和 `.runner` 的目录 FD。章节锁、已有章节的有界普通文件读取、私有临时文件、原子替换及目录同步均通过该原目录 FD 操作，不重新解析可被替换的根路径。目录身份变化仍使后续循环退出。

共用生命周期套件增加两个确定性 barrier：读取原快照后、以及写完临时文件但尚未原子替换前，将工作区重命名并创建同名新目录。live watcher 与最终单次 snapshot 都先绑定原目录 FD，各自覆盖两个 barrier。要求旧章节仅在持有的原目录发布，原章节修订号继续递增，新目录的章节、锁和文件集合逐字保持。原与 native 两个入口各自执行该用例；新 native 来源字节使用独立 `native-r2` 身份，`native-r1` 精确历史来源只供原制品核验。

PR157 主线补修将该合同继续覆盖到源读取。原根 FD 下逐层打开的结果目录核对设备/inode，日志、JSON 和上传包同 FD 禁止链接／阻塞特殊文件，核对所有者、权限与大小；每个有界读取块检查两秒单调期限，watcher 还复核父 PID、信号及根／运行目录身份。源路径替换为 FIFO 不进入阻塞读取，取消后的未发布内容丢弃。capture、response、stream-log、render 固定原输出目录，所有 sidecar 和缓存移除也不重新解析根；串行章节锁最多等待两秒。完整设计与新增回归见[采集器目录读取边界](nodequality-watcher-lifecycle.md)。这些新增输入在实现完成后另行冻结验证，本节下表仍是作者原冻结结果，不能移作本聊天补修的通过数量。

本聊天最终原 wrapper 40 个完整方法通过／1 个 Linux procfs 条件方法未验，native wrapper 42 个完整方法通过，两套固定来源分别 17／16、两套报告策略分别 6／14 个完整方法通过。原／native watcher 首轮各 23／24 个方法通过，唯一共同失败是夹具预期路径没有规范化 macOS `/var` 别名；只修这行夹具后，各完整 24 个方法、60 个子例补验通过，产品与历史来源字节保持。未重复运行已经通过的 wrapper、固定来源或报告策略；首轮四个失败子例保留。38 个 NodeQuality 工具的最终去重数量及其他未验条件见[本聊天新输入集中结果](nodequality-r22-upload-and-history.md)。

## 本轮集中验证结果

五套生命周期相关工具最终共有 94 个不同方法通过，0 项仍失败或跳过。通过后的原/native watcher 与报告策略未重复执行；受影响 wrapper 的补验取代首轮结果，不重复累计 41 个方法。

| 工具 | 最终结果 | 实际覆盖 |
| --- | --- | --- |
| `test-nodequality.py` | 41 通过 | 原 wrapper 报告、信号、超时/异常自有组清理、仅 KILL 父进程后的采集器自主退出及 sentinel |
| `test-nodequality-sources.py` | 17 通过 | 固定来源、包装/签名身份、修改拒绝与实际 shim；原 minisign 条件用例补验通过 |
| `test-nodequality-report-policy.py` | 6 通过 | 打包、服务与四个调用者的输出和参数合同 |
| `test-nodequality-watcher.py` | 15 通过 | 原 reporter 所有权、目录身份、信号、忙锁、readiness 和目录 FD 发布 barrier |
| `test-nodequality-native-watcher.py` | 15 通过 | native reporter 对同一生命周期合同的独立实际覆盖 |

原 wrapper 首轮的父 KILL 回归读取 `/proc/<PID>/task/<PID>/children` 时出现 `FileNotFoundError`。只读核实当前内核没有该可选接口后，集中将 fixture 改为有界 PID/PPID 元数据枚举，再核对已知候选的 start/cmdline 精确身份；没有跳过或削弱父 KILL 的断言。修复后的整套 wrapper 41 项通过。固定来源首轮因缺 minisign 跳过一个方法，补齐工具后仅补验该方法并通过。原失败、跳过及对应有界收据保持，不将首轮写成全绿；恶意重复 ZIP 名夹具的预期 `UserWarning` 也保持。

总集成另以按锁精确核验的只读上游源码运行原/native 的 canonical Wiring 选择方法，补充真实固定源码进入 wrapper/策略的证据。原报告策略中的两个方法已有成功记录，新的 canonical 输入不重复增加这五套的不同方法数量；native 与其他 canonical 范围由总交付统一记录。该场景仍使用明确的自有替身和回环 recorder，不执行真实硬件测试或公共报告上传。

每条命令保存退出码、方法/跳过数量、输出 SHA-256 及有界日志，公开说明使用 TEST_ONLY 夹具。18 个本轮保留 fixture 目录另保存精确路径、设备/inode 和清理摘要；其直接子回收、自有进程组无活动成员及 wrapper 清理均已确认。工作区 Rust、面板/协议、默认新制品身份和最终材料清理由[总集成交付记录](all-open-issues-20261003.md)统一记录。验证结束后只保留有界结果、源码身份和最新必要材料，兼容历史所需的已提交源码保持。

专用 Linux/systemd 当前 Agent 的重启、断连、标准 ICMP、取消、服务与挂载证明，以及完整 NodeQuality 和持续代理流量联合负载，仍需真实设备证据。自有 Python/Bash 进程、SQLite 状态和协议夹具不能签收这些条件，也不构成正式发布或生产部署。
