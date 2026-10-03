# NodeQuality r22 上传请求边界与历史源码身份

关联 #28、#65、#66、#82；本文件记录本轮实现及集中修改冻结后的实际验证。整体交付收据见[本轮统一验收](all-open-issues-20261003.md)。

旧 host curl shim 根据参数中是否出现顶层报告 URL 选择真实上传路径；显式允许上传时，附带第二个 URL、额外配置或其他 curl 选项也会随原参数执行，且 curl 自身默认配置没有被关闭。固定上游入口目前只使用 `-X POST --data-binary @- <固定 URL>`，上述额外参数不是其正常请求。

当前默认 r22 新增 `runtime-curl.sh`，在收集报告或调用外部工具前只接受这一个精确 POST 结构。陌生来源仍通过固定 source-helper 拒绝；rootfs 下载和在线 main 没有回退。允许上传时只向固定 HTTPS URL 发起一次请求，`--disable` 位于真实 curl 首参，协议限制、连接截止、总截止和响应大小限制继续有效。默认、false 及未知许可值保留本地报告且不执行真实 curl。上传失败保留传输退出码和本地章节，不把请求失败写成成功。

默认 build、runner、面板插件、adapter 和 release 常量采用 r22；旧 r19 仍作为明确历史版本保留日常、报告回收和取消支持。显式 native 构建采用 native-r2，并内嵌同一个新上传边界及章节目录保护；native-r1 继续作为历史身份支持。旧 `curl-shim.sh` 保留供原 r19/native-r1 字节身份，新防护不改写这些已签名身份。17 个原源码、参考文件和完整许可证不变，现有内层报告、评分上传与 swap 精确补丁保留。r22/native-r2 的 owner watcher 生命周期和持有目录FD的章节发布改动见同轮独立记录。

PR157 主线整合进一步将原目录 FD 贯穿章节源遍历、普通文件读取与发布，并覆盖 capture／response／stream-log／render 的 sidecar 和缓存操作；源 FIFO／链接／大小／身份替换拒绝，快照逐块检查单调期限及 watcher 当前所有权。详见[采集器运行与目录读取边界](nodequality-watcher-lifecycle.md)。当前两套构建器和 `render-bootstrap.py` 的嵌入内容须在整步实现完成后统一刷新及冻结验证；不能以作者下文旧输入的结果证明本次 reporter 或新生成 bootstrap 已验证。

r20/r21 的严格派生之前读取当前 runner/report；当前文件升级后继续用它们重建旧版本会破坏签名身份。`historical-r19` 只保存本轮前 runner/report/rootfs 的精确源码素材，`historical-native-r1` 保存原 native runner/report；两者由 `nodequality_history.py` 按固定摘要、普通文件及大小限制读取。r20/r21 重建使用历史 runner/report，既有 r20/native-offline-r1 使用历史 rootfs；offline-rootfs-r1 仍由原 native-r1 精确派生，新 IPQuality 元数据修复使用当前 rootfs。历史 helper 直接编译已经核验的字节，不重新打开可变化路径。这里保留的是兼容所必需的源码，不是过期测试环境或二进制制品。

静态 rootfs 库存同时补显式遗漏：root/home/etc 或私有配置路径里的执行 mode 文件只记录 tar 元数据；无执行 mode 的潜在私有 ELF/脚本和链接仍未盘点。因此，即使声明的公开路径身份完全匹配，输出也始终注明完整执行库存未完成。稀疏归档成员在读取内容前拒绝。这项改动不读取私有配置，也不将文件摘要或许可证文本推成再分发授权。

集中修改冻结后，NodeQuality 分项首轮29套均退出0；框架记录 `testsRun=286` 和166次跳过事件，后者包含子用例及整类初始化，不能相减得到通过方法数。新增上传边界4项、历史源码身份4项、执行库存10项均实际通过；原包装器、来源、报告与生命周期等并行分项结果由统一收据分别记录。本轮修改期间没有执行这些测试。

首次读取固定材料在 `LICENSE.net` 遇到HTTP503；随后通过GitHub connector补齐原固定提交的17份源码、参考文件及完整许可证，共687969字节。每份原始大小和SHA256均匹配提交的source-lock；真实 `source-helper.pack` 接受该完整集合，包摘要为 `e778772d44165b525de1c0216208519929fb759eb4930c8a1a42722e7a512874`。采集没有执行上游入口或取得许可工具。

使用该只读缓存，针对17套策略中此前缺固定源证据的方法、原/native报告接线、历史派生及native真实签名共111个不同方法定点验证：首批99项实际通过，余下12项因缺 `bc` 跳过；外部取得并核对官方Debian `bc` 后，仅这12项补验全部通过。因此这111个方法均有实际通过证据，没有重复计算已通过方法，也不与首轮 `testsRun` 相加作为不同方法总数。其中r20/native-offline/r21真实历史派生29项、原/native报告接线4项、native真实minisign签名1项已经包含在111项中；原包装器的1项真实签名由生命周期批次单独记录。

验证使用 `python3 tools/test-nodequality-upload-boundary.py`、`python3 tools/test-nodequality-history.py`、`python3 tools/test-nodequality-execution-inventory.py` 及相应精确方法选择；固定源策略传入 `--readonly-upstream-dir`，历史派生传入 `SINAN_NODEQUALITY_CANONICAL_SOURCES`。夹具使用私有报告、惰性命令及本地受控传输；真实minisign只签署TEST_ONLY材料，不运行benchmark、swap、许可接受或真实公共上传。

## PR157 本聊天新输入集中结果

上文分项数量来自作者原冻结，不作为本聊天新输入结果。原始私有历史材料已被清理，本轮重新检查路径与工具，使用 source-lock 精确匹配的 17 份只读来源（687969 字节），完成当前冻结的全部 38 个 `tools/test-nodequality*.py` 入口。记录器先因手工估计 39 个入口而拒绝启动，零测试执行；纠正为与冻结 manifest 的精确 38 个路径一致后才执行，记录器错误与产品验证分开。

首轮 574 个启动方法中，484 个完整方法通过、86 个方法跳过、2 个父方法只有部分子例完成，2 个 watcher 方法共 4 个子例失败；940 个子例通过、36 个子例跳过，0 个整类跳过。失败仅是同一解释器 metadata 夹具的 macOS 规范路径预期，修复后只完整补验原／native 两个 watcher 入口。另在事先固定的四套支持 `SINAN_NODEQUALITY_TEST_BASH` 的工具中，使用实际 GNU Bash 5.3.20 完整执行此前未认证的 34 个方法、105 个子例；没有重复已认证方法，没有改写硬编码 `/bin/bash` 的条件。

最终仍是 38 个实际入口、574 个不同启动方法：520 个完整方法通过、53 个方法跳过、1 个父方法含 10 个跳过子例而不计完整通过，0 失败／整类跳过；1049 个有效子例通过、10 个未验。物理启动 656 个方法，不能把完整补验或条件补验重复累加为不同方法。剩余条件包括 macOS `/bin/bash` 3.2、Linux 进程／挂载／原子抽取以及未启用的自有 loop 文件系统，不将它们记为通过。

原始功能库存及首轮收据保持，补修后的 1138 份功能输入只有共享 watcher 夹具增加 10 字节；两轮执行前后实际输入逐字核对。首轮 proof SHA256 `368bf668252c29f9d9e4ab1435172eba88b39f43a23d191e4083c5fd7b34df32`，补验 proof `231c2b8cfe6a3f02200290fb0df0a7ec9afe1fc2ff6a649657c2b6e25d5629c6`，最终去重 coverage `b8d115266090931e46bd80d364147314cbc32e814e9d638bc475be2c4ce09235`。这些是本聊天当前本地执行收据，不是重建已删除的旧材料；详细方法、子例、参数、工作目录、工具和来源身份由总交付摘要固定。没有运行原生完整验机、真实第三方上传、SSH、生产操作或 CI。

仍缺适用于 Ookla 1.2.0.84 与 Geekbench 5.5.1 的实际来源、再分发及无人值守许可、工具自身上传证明、完整工具和动态库闭包、双架构原生复建与完整故障矩阵实机证据。保留原完整能力源码和暂停门禁；本轮补修不签收完整验机，也不凭准备层或惰性夹具关闭上述四项外部条件。
