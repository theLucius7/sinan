# 安装版本策略与 Reality 预算补充

2026-10-03，本轮集中处理 [Issue #3](https://github.com/theLucius7/sinan/issues/3) 与 [Issue #6](https://github.com/theLucius7/sinan/issues/6) 的源码缺口。源码集中修改冻结后，统一执行受影响验收；结果及真实剩余条件记录如下。最终源码身份和机器收据以[本轮统一交付记录](all-open-issues-20261003.md)为准，不能使用历史通过结果代替。

## 安装接口的版本选择

`/install.sh?token=<接入令牌>&agent_version=<版本>&agent_target=<平台架构>&platform=unix` 返回标准安装描述；Windows 可用 `platform=windows` 或 `/install.ps1`。令牌先经过有效性检查，安装命令使用固定官方 GitHub bootstrap 及其摘要，Agent 二进制由独立安装器从 GitHub 获取并验签。

未传 `agent_version` 或传 `latest` 时，安装描述的 `version` 为 `latest`、`tag` 为 `null`。安装器识别实际主机的操作系统、CPU 与 libc，再从已签目录中选择数值最高的兼容稳定版；不取面板包版本，不将预发布版本默认提供给设备。显式版本保持固定身份，不能回退成其他版本。管理员版本目录和接入版本目录新增以下声明，与原 `versions` 数组同时返回：

```json
{
  "policy": {
    "default_version": "latest",
    "selection": "highest_stable_signed_protocol_compatible_for_target",
    "minimum_version": "0.3.0"
  }
}
```

目录声明解释面板的选择策略，不代替独立的发布签名、完整 metadata、实际主机 ABI 或安装后状态检查。版本目录中的未缓存平台仍可从 GitHub 安装；不能把面板没有缓存某个 Agent 二进制误记为没有签名发布。

接入版本目录 `/api/bootstrap/versions` 使用 `target`，安装描述入口使用 `agent_target`。此次补齐接入目录空结果的明确 HTTP 409，避免独立 bootstrap 对所有显式拒绝都报“未导入”：

| 条件 | 标准拒绝原因 |
| --- | --- |
| 没有已校验的对应签名发布 | 所选版本尚未导入 |
| 已签发布协议范围与面板不相交 | 协议不兼容 |
| 已签原字节早于 0.3.0，缺少现代安装/验签/监督执行合同 | 历史安装合同不支持；补签不能添加原二进制没有的命令 |
| 已签版本没有所选平台的合格制品 | 平台、架构或稳定版本条件不满足 |
| 接入令牌无效或过期 | HTTP 401；重新签发接入令牌 |

独立 bootstrap 对 HTTP 409 的错误正文最多读取 8 KiB，读取仍共享原目录请求的 30 秒绝对截止。只把已知原因映射为固定提示；未知错误、超大正文及无效 JSON 使用固定通用提示，不反射面板 URL、令牌或任意错误正文。不增加请求、重试或执行未校验内容。

## 历史 0.1.0 → 0.2.0 的关闭条件

现有[历史准备记录](remaining-native-validation-preparation.md)保存真实 0.1.0/0.2.0 字节摘要，以及原地升级保持设备身份、配置、账本与独立运行时的历史证据；0.1.0 首装仍使用人工脚本 workaround，0.2.0 精确源码来源尚缺。此次目录策略与错误分类不能补齐这些事实，Issue #3 的全部验收条件仍未完成。

剩余工作要求取得历史原字节的真实来源和执行合同，在隔离环境用正式标准接口完成 0.1.0 首装及 0.2.0 同设备升级，保留版本选择、发布来源、脚本摘要、server ID、公钥/身份文件摘要、账本、已应用配置及运行时 PID 的前后对应。不能将现代二进制重标为旧版本，不能伪造历史签名，也不能通过弱化验签或忽略缺失命令满足版本号字面要求。现代兼容版本的标准安装通过，只证明其自身合同。

## Reality 单次请求预算与失败证据

`scripts/e2e-traffic-evidence.py` 的传输固定为自有回环 HTTP 目标、回环 SOCKS 入口与本机 Reality 监听；伪装 TLS 目标是本轮独立 Docker 夹具，由严格白名单的私有地址元数据定位，不请求公网业务目标。首次与恢复后各下载 2 MiB、上传 1 MiB，总共最多四条传输记录；原载荷校验与账本验收继续由驱动执行。

此轮没有延长请求预算。新增公开白名单 `policy` 将实际配方写入结果，避免在阅读新证据时猜测采用了 15 秒还是 90 秒：

| 范围 | 固定预算与判定 |
| --- | --- |
| 每条代理请求 | curl `--max-time 90`，从请求开始至响应体结束共享 90 秒，无自动重试 |
| curl 进程守护 | 92 秒；仅终止未自行退出的本次 curl，返回原超时类别/退出 28，不增加正常请求的 90 秒预算 |
| 失败后的直接网络探测 | 三个 TCP 各 1 秒、HTTP 总 2 秒、TLS 总 2 秒；网络预算最多 7 秒，进程启动/回收和写盘开销另计 |
| 通过条件 | curl 退出 0、HTTP 成功、双向完整载荷及身份/配置/账本断言均满足；服务 active 不能替代流量通过 |

新超时记录的 `timeout_source=curl_deadline` 表示 curl 自行报告请求超时；`process_guard` 表示外层终止了未退出的进程。`reached_stage` 只说明最后可观察到的客户端进度：本地 SOCKS 连接前、代理/传输、等待请求/响应、收到响应或未知，不能把本地 SOCKS 的连接时间当成远端 Reality TLS 握手时间。记录收发字节、HTTP 状态、连接/预传输/首字节/总耗时并保留原失败码；写盘或诊断失败不能将传输失败变成成功。

历史 JSON 没有声明的预算或超时来源继续保持未知。清洗器仅允许本轮固定 `policy` 值，拒绝 15 秒或其他值冒充这套 90 秒配方，过滤任意地址、配置、stderr 和路径。加入错误字段或旧文件读取不会触发网络探测。

## 可复用的分层定位

1. 固定源码、运行时和客户端版本，先记录同一次请求的预算、方向、期望字节及退出码。单次失败直接判为失败，保留有限摘要，再运行失败后的直接夹具探测，不通过反复重跑抹掉失败。
2. 核对客户端仍存在、本地 SOCKS TCP 是否可连及客户端观察阶段。SOCKS 可连只证明监听存在；HTTP 状态 0 或已发送全部上传字节都不能证明服务端已经收到并完成请求。
3. 核对 HTTP 目标的直接下载以及伪装目标的直接 TLS 握手。慢滴响应头和正文共享绝对截止；失败记具体类别。独立 TLS 成功只说明该次夹具握手成功，不能代替失败时的 Reality 内层握手。
4. 对齐运行时监听、固定服务白名单状态、资源观察和恢复前后配置摘要。active、PID 保持或健康快照都不能证明字节流畅通；失败后快照也不能证明失败瞬间没有资源争抢。
5. 公网复现需在已授权专用环境对齐同一次失败的双端时间窗，取得脱敏 TCP retrans/zero-window/RST、服务端读写进度及伪装目标证据，再区分客户端、链路、伪装目标和服务端。保留有限所需字段，生产凭据与原始私密配置不进入公开摘要。

原公网两次 15 秒失败与后来 CI 自有回环 90 秒失败属于不同环境；后者包含只收到 1,103,168/2,097,152 字节及首次下载 0 字节的历史观察，详见[原失败证据](reality-failure-evidence.md)。后续成功与同源码重跑成功不能证实原失败由预算偏小造成。实际配方没有启用 multiplex，其他项目的 smux 结论不能直接用于归因。缺少对应失败瞬间证据，Issue #6 的根因仍未解决。

## 整体冻结后的验证命令

以下命令列出本项纳入最终统一验收的范围；实际已执行范围及结果见后文：

```sh
python3 -m unittest discover -s tests -p 'test_bootstrap.py'
python3 scripts/test-e2e-traffic-evidence.py
python3 scripts/test-e2e-driver.py
python3 tools/render-bootstrap.py --check
python3 tools/test-bootstrap-artifact-contracts.py
python3 tools/test-build-scripts.py
cargo test --locked -p sinan-panel --test releases
cargo test --locked -p sinan-panel --test foundation signed_agent_versions_require_admin_or_live_enrollment_and_match_platforms
```

`foundation` 需要隔离 PostgreSQL；完整真实安装/Reality 场景需要专用 amd64、Docker、systemd 和匹配制品。本轮源码回归可验证目录策略、拒绝分类、错误隐私、预算和守护来源；不能替代历史标准首装、失败时双端现场证据或公网压力范围。CI 暂停要求与既有实机/发布门禁保持。

## 集中验收发现的独立 bootstrap 闭包修复

首次集中验收发现，新增历史读取器未进入 bootstrap 打包清单；即使仅增加模块，原平铺布局仍不能满足读取器及制品校验器通过 `__file__` 定位源码的合同。此次集中修复保留私有 stage 中 `tools/` 与 `plugins/` 的仓库相对布局，包括 r19/native-r1 的固定历史原字节、r20/r21/native-offline 校验器全部 helper，以及 IPQuality 实际 intake 的 profile、inputs、capacity、共享 factory、source-policy、许可证与当前源码证明闭包。

生成入口将固定源码映射通过 Python 标准库 LZMA 压缩嵌入；解码器内存上限为 8 MiB，展开文本限 2 MiB，入口仍受原 256 KiB 下载上限约束。解包之前严格核对路径白名单、逐文件长度和 SHA-256，全部内容通过后，从原 stage 目录描述符逐层创建及打开子目录，使用 `dir_fd`、`O_DIRECTORY` 与 `O_NOFOLLOW` 拒绝替换的链接；叶文件同样从持有的目录描述符独占创建，不接受环境变量或任意替代路径。历史原字节在生成时和实际读取时分别按固定摘要检查。公钥继续使用顶层保护文件，可信安装器位于 `tools/`，与实际 bootstrap 模块相邻；生产验签和安装器合同没有放宽。

新增 `tools/test-bootstrap-artifact-contracts.py` 回归从实际生成的物料程序建立孤立 stage，在 Python isolated mode 中验证历史 reader/编译入口、所有衍生 helper 的定位、IPQuality factory 输入与政策摘要，以及篡改/缺失/额外文件在任何 stage 写入前拒绝。这些惰性导入和严格拒绝合同不会执行上游 benchmark、构建 rootfs、下载或安装服务；完整合法制品的实际验收仍按各自配方记录。

## 本项集中验收结果

| 范围 | 当前结果与边界 |
| --- | --- |
| 独立 bootstrap 打包合同 | 8 个不同方法通过；其中 IPQuality 内嵌 verifier 回归在修正夹具断言后单独通过，未重复累加此前通过的方法 |
| 构建脚本合同 | 8 个方法通过 |
| 传输证据与端到端驱动合同 | 20＋26＝46 个方法通过；属于配方及证据处理回归，没有发起公网 Reality 复现 |
| bootstrap 单元与 root 方法 | 25 个无特权方法及隔离 Linux root 容器中 8 个方法，共 33 个不同方法通过；容器使用 TEST_ONLY 签名与惰性安装器，未安装生产 Agent 或激活生产服务 |
| 生成物一致性 | `tools/render-bootstrap.py --check` 通过，固定入口保持原 256 KiB 上限 |
| Release 真实安装前缀 | 7 个 root 方法最终通过；集中修复夹具为完整渲染的生产安装器，并将强制优化定点用于实际签名证明校验 Python，验签、拒绝及零 HTTP 请求断言均保留；仅补验这 7 项，先前通过的 8 个 root bootstrap 方法未重复 |

原始集中验收发现的缺失历史模块、夹具断言和 root 环境条件保留在[统一交付记录](all-open-issues-20261003.md)的有界收据中；修复后的通过只覆盖对应冻结源码与方法。#3 历史标准首装及精确源码来源、#6 原失败双端证据与根因条件继续待完成，CI 暂停与生产发布门禁保持。
