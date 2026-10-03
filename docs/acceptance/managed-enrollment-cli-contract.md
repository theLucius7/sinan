# 真实 Agent 注册命令合同

关联 [Issue #149](https://github.com/theLucius7/sinan/issues/149)。普通产品 CLI 的 `Enroll` 同时要求 `panel` 和 `token`；配置文件的 `panel_url` 不能满足 Clap 必需的 `--panel` 参数。

控制器在既定隔离命名空间内执行普通 `sinan-agent --config /etc/sinan/agent.toml enroll --panel=<已绑定的 HTTPS origin> --token=<私有令牌>`，完成后启动标准 Agent 服务。面板 origin、二进制和配置来自已经校验的控制器清单。令牌始终作为带等号的一个 argv，即使首字符为 `-` 也不会被解释成新的选项。描述文件中额外的 URL、panel、binary、argv 或嵌套 enrollment 字段不能选择注册目标。

注册描述文件必须位于本次 owned root、仅当前用户可读，且是 schema 1 的对象；run、角色和有限 ASCII 令牌均需匹配。错误 schema（含布尔类型）、非对象描述文件、错误 run／角色、空值／数值／数组／对象令牌、超长或含控制字符的令牌，以及调用参数中新增 panel 字段，在运行产品 CLI 或启动服务前拒绝。

回归源码位于 `tools/test-managed-paths-preparation.py` 的 `ControllerContracts`。合同核对完整 argv 与固定目标，并确认失败输入没有调用注册进程或服务。这是控制器边界合同，不能证明实际 Agent 已完成 HTTPS 注册或生成身份。

2026-10-03 本轮修改期间没有运行测试或构建；全部集成修改冻结后，集中执行准备／控制器合同 17 项、托管 API 驱动合同 31 项、托管夹具合同 21 项和有序原生路径工具合同 17 项。四套各执行一次，合计 86 项通过、0 失败、0 跳过；本注册 argv 与描述文件边界由其中的准备／控制器合同覆盖。最终命令、输入及证据统一见[全部开放 issues 集成交付](all-open-issues-20261003.md)，不将其它三套合同计作新增注册设备证据。

真实 native CLI 参数读回、冻结签名 Agent、CA、A／M／B 三设备注册与身份互异仍单独待验。CI 继续暂停，实际注册合同与整链、账本、清理证据分别记录。
