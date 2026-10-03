# 订阅来源实现与参考记录

日期：2026-10-01。对应 ADR 0040。本文记录来源服务、格式转换及外部出站边界；混合路径发布和真实网络验收另行记录。

## 参考项目与实现边界

本次先核对成熟项目的格式、参数和网络承载语义，再按 Sinan 的受限模型实现。没有复制上游转换器代码，没有调用第三方转换服务，也没有修改 sing-box 上游。

| 一手来源 | 核对内容 | 本仓库实现 |
| --- | --- | --- |
| [sing-box v1.14.2 出站选项](https://github.com/SagerNet/sing-box/blob/v1.14.2/option/outbound.go)及 [VLESS](https://github.com/SagerNet/sing-box/blob/v1.14.2/option/vless.go)、[VMess](https://github.com/SagerNet/sing-box/blob/v1.14.2/option/vmess.go)、[TLS](https://github.com/SagerNet/sing-box/blob/v1.14.2/option/tls.go)结构 | 出站类型、认证、TLS、传输参数、`detour` 与显式解析器归属 | `crates/compiler/src/external.rs` 使用严格白名单；原配置的 tag、路由、解析器、绑定接口和文件路径不能进入编译输入。名称只作公开展示。 |
| [sing-box HTTP/SOCKS 参数](https://github.com/SagerNet/sing-box/blob/v1.14.2/option/simple.go)、[SS 出站](https://github.com/SagerNet/sing-box/blob/v1.14.2/protocol/shadowsocks/outbound.go)、[AnyTLS 出站](https://github.com/SagerNet/sing-box/blob/v1.14.2/protocol/anytls/outbound.go)、[Naive 出站](https://github.com/SagerNet/sing-box/blob/v1.14.2/protocol/naive/outbound.go) | 代理向用户提供的 TCP/UDP，与连接代理所需的 TCP/UDP 是不同能力；SS 原生 UDP 与 UoT/mux 的下层不同；Naive 有独立构建条件 | `ExternalCapabilities` 分开记录 TCP 所需下层和 UDP 所需下层；所需构建特性随出站返回给路径编译与设备检查。 |
| [Mihomo 官方 provider 说明](https://wiki.metacubex.one/config/proxy-providers/) | 节点集合与 provider 地址、覆写、健康检查、策略组的区别 | 只读取 `proxies` 或顶层 `payload` 中的具体节点；provider URL 不递归抓取，脚本和全局设置不执行。参数转换由插件 `sources/mihomo.rs` 原创实现。 |
| [Sub-Store 官方解析入口](https://github.com/sub-store-org/Sub-Store/blob/master/backend/src/core/proxy-utils/parsers/index.js) | URI、VMess JSON、订阅编码以及不同客户端参数之间需要显式转换，不能把名称当身份 | 本仓库用独立 Rust 模块解析四种格式，转换后再统一校验；没有移植 JavaScript、远端脚本执行或在线转换。 |
| [Shadowsocks SIP002](https://shadowsocks.org/doc/sip002.html) | AEAD 与 AEAD-2022 userinfo 编码、IPv6、百分号编码和插件参数 | 统一 URI 解析保留认证内容；2022 密钥按算法校验长度，未知插件明确列为不可选。 |
| [saphyr-parser 0.1.0](https://docs.rs/saphyr-parser/0.1.0/saphyr_parser/)和[官方源码](https://github.com/saphyr-rs/saphyr/tree/master/parser) | YAML 事件流、锚点和别名、重复键及展开预算 | `sources/structured.rs` 在事件消费过程中限制深度、标量、值数量和累计字符串大小，复制别名前先计预算。递归引用、多文档、未知标签、重复显式键直接拒绝。支持有界非递归别名和映射合并。 |

sing-box 的配置结构与行为用于互操作核对；Mihomo 和 Sub-Store 仅作为格式行为参考。本仓库新增代码遵循现有 AGPL-3.0-only。Sub-Store 的[上游许可证](https://github.com/sub-store-org/Sub-Store/blob/master/LICENSE)为 AGPL 系列，本次不纳入其源码。直接依赖的 saphyr-parser 保留其 MIT OR Apache-2.0 许可证及 Cargo 元数据，不能将“参考过”写成复制实现或声称上游为本项目背书。

## 依赖与预算

仅面板新增 `saphyr-parser = "=0.1.0"`，`default-features = false`，不启用 `debug_prints`。已实际核对下载的 Cargo 包：edition 2024、MSRV 1.85，直接依赖 `arraydeque 0.5.1` 与 `thiserror 2.0.20`；后者复用工作区依赖。Cargo.lock 固定实际解析结果。此选择的必要性与替代方案沿用 ADR 0040，不向 Agent、core 或 compiler 引入 YAML。

来源下载总期限 20 秒。压缩正文和解压后正文分别限 2 MiB；只处理 identity、gzip、deflate，其他编码明确失败。gzip 连续 member 逐个解压并累计计限，不能忽略首段之后的内容。解析限 5000 个代理、结构深度 64、单标量 64 KiB、100000 个结构值及累计 2 MiB 字符串（包括别名复制）。额外结构值限额防止大量短值耗尽内存，受保护原文也不能绕过正文限额。

2026-10-03 起，两套来源共用 `subscription_fetch.rs` 一个抓取器，规则取两边并集，详见 [ADR 0079 阶段二](adr/0079-rearchitecture-plugins-sources-chains.md)。下文仍描述该抓取器。

HTTPS 目标逐跳校验来源同源关系和全部解析地址，再将连接固定到已检查的地址；关闭环境代理、自动重定向和 Referer。最多三次同源跳转；IPv4 特殊用途段、IPv6 本地/映射/过渡/文档段均拒绝。在附加 Authorization 的请求构建边界再次校验同源，307 也不能将凭据带到其他主机或端口；原始 Location 中的控制字符、反斜线和 userinfo 明确拒绝。来源 URL 和 Authorization 只在获取服务读取；解析错误和下载错误只保存固定分类，不保存上游诊断原文。请求结构错误也转为统一错误，避免框架回显秘密字段值。

## 版本、任务与引用

迁移 `0026_subscription_sources.sql` 保存来源设置修订、身份代次、成功批次、不可变节点版本和持久刷新任务。两个版本表均由数据库触发器拒绝 UPDATE/DELETE。来源删除使用软删除；任意未删除链路代数仍引用来源时返回冲突，历史版本不级联删除。

提供方独立 `provider_id` 优先标识节点；不存在时使用协议、端点、SNI、传输身份的摘要。凭据、名称和顺序不参与匹配。重复身份不可自动选用；缺失节点保留旧版本。URL/认证更换或管理员明确更换内容来源建立新身份代次，旧节点不会自动迁入新来源。普通管理 API 不返回 URL、认证、原文或出站秘密。

每个来源最多一个有效排队/运行任务；数据库调度锁限制全局四个运行任务，进程内也限四个工作槽。下载和解析在业务事务外完成；提交时再次锁定并比较任务状态、设置修订、身份代次及解析器版本。归档、取消或更新设置后旧结果不能提交，运行中的下载也会观察持久取消状态。写入设置与排队在同一个事务中进行，避免保存来源后任务未入库。

条件请求仅使用绑定当前设置修订、身份代次和解析器版本的成功批次。304 不新增内容版本并保留有效缓存标记；200 返回新正文但未携带 ETag/Last-Modified 时清除旧标记。名称变化和节点重排不会改变连接参数摘要；来源仍追加不可变成功批次，链路跟随逻辑比较语义摘要，避免纯名称变化触发切代。

链路读取通过 `load_version_on` / `latest_follow_version_on` 获取冻结参数。新引用必须满足来源未归档、当前身份代次、节点仍存在且身份唯一；显式固定版本允许同一当前身份的历史快照。恢复旧代使用原不可变版本，不能重新读取最新参数。

## 已执行验证与限制

来源解析、下载边界和服务定向测试 15 项通过，覆盖四种格式等价转换、凭据轮换、名称变化/重排、同端点多账号歧义、重复字段、结构深度、递归/膨胀别名、标量和值预算、压缩膨胀、保留地址与特殊 IPv6、307 跨源请求构建拒绝、畸形私网重定向、刷新并发、过期结果及条件请求缓存。有效节点旁的原始 route/DNS/providers/scripts/control 配置被回归确认不会进入规范化出站。重定向测试验证生产校验和请求构建路径，没有连接公网测试来源，也没有为测试放宽下载器的 SSRF 限制。

隔离 PostgreSQL 与回环面板接口测试覆盖旧版本不可变、跟随/固定读取、缺失/歧义/更换来源、公共响应脱敏、归档、全代引用删除保护及历史保留。浏览器选择引用及状态转换测试验证草稿不携带来源秘密，取消、失败和保留旧版本的状态有明确区分。

这些测试不证明某个第三方机场可用，不替代专用代理夹具中的路径、TCP/UDP、实际出口、入口单次计量和恢复验收。未获取真实机场订阅，未执行生产迁移、签署或部署。GitHub Actions 继续暂停，远端 CI 未验证。
