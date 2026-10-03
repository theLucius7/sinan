# native-r1 历史签名身份的源码

这里保存本轮前 `native-runner.sh.tmpl`、`native-report.py` 的精确原字节，只用于 native-r1 和 offline-rootfs-r1 的严格历史派生。`tools/nodequality_history.py` 固定二者摘要；当前显式 native 构建使用外层 native-r2 源码，新增章节目录保护和上传边界不得改标为 native-r1。

原离线工具使用历史 r19 保存的同一份 rootfs.py，无重复副本。历史源码仍受原完整执行门禁和许可条件约束，不属于待运行工具、测试缓存或旧二进制制品。
